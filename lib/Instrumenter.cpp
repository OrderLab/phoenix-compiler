#include "llvm/ADT/iterator_range.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/raw_ostream.h"

#include <cstddef>
#include <cstdlib>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <ranges>

#include "Instrumenter.h"
#include "Utils.h"
#include "FunctionAnalysis.h"
#include "phx_instrument_compiler_abi.h"

using namespace llvm;
// C++20:
// using std::ranges::reverse_view;

namespace phoenix {

namespace instrument {

/* Algorithm to calculate the safe end cut. See `run` for a overall step.
 *
 * TODO: replace this with llvm/ADT/SCCIterator.h
 * https://eli.thegreenplace.net/2013/09/16/analyzing-function-cfgs-with-llvm
 */
struct SafeCut {
    Function &f;
    std::unordered_set<const Instruction *> taints;
    bool debug = false;

private:
    size_t sccCnt = 0;

    struct ks_t {
        bool visited;
        size_t color;
    };
    // kosaraju state: <bb, <visit, color>>
    std::unordered_map<const BasicBlock *, ks_t> ks;
    // kosaraju visit order
    std::vector<BasicBlock *> visit_order;

    // superblock state
    struct sbs_t {
        std::unordered_set<BasicBlock *> bbs;
        size_t nsucc;   // number of successors
        bool has_taint;
    };
    // superblock <color, bb[]>
    std::vector<sbs_t> superblock;

public:
    SafeCut(Function &f, std::unordered_set<const Instruction *> taints, bool debug = false)
        : f(f), taints(taints), debug(debug) {}

    /* Main entry function
     * This function has two steps:
     * 1. first use SCC to create supernode and eliminate loops
     * 2. second use BFS in topology order on the reversed supernode graph and
     *    find what nodes cannot be reached. Then, the `br` from unvisited
     *    node to visited node is in the safe cut.
     */
    std::vector<Instruction *> run() {
        kosaraju();
        return extract_cut();
    }

private:
    void dfs1(BasicBlock *bb) {
        ks[bb].visited = true;
        for (auto bnext : successors(bb)) {
            if (!ks[bnext].visited)
                dfs1(bnext);
        }
        visit_order.push_back(bb);
    }

    void dfs2(BasicBlock *bb) {
        ks[bb].color = sccCnt;
        superblock[sccCnt].bbs.insert(bb);
        for (auto bprev : predecessors(bb)) {
            if (!ks[bprev].color)
                dfs2(bprev);
        }
    }

    // SCC algorithm
    // https://oi-wiki.org/graph/scc/
    void kosaraju() {
        sccCnt = 0;
        superblock.push_back({});
        for (auto &bb : f)
            if (!ks[&bb].visited)
                dfs1(&bb);
        // C++20:
        // for (auto &bb : reverse_view(visit_order))
        for (auto &bb : iterator_range(visit_order.rbegin(), visit_order.rend())) {
            if (!ks[bb].color) {
                ++sccCnt;
                superblock.push_back({});
                dfs2(bb);
            }
        }
    }

    // returns instrument list
    std::vector<Instruction *> extract_cut() {
        std::queue<size_t> q;

        // determine superblock taints
        for (auto inst : taints)
            superblock[ks[inst->getParent()].color].has_taint = true;

        /* count number of successors of each superblock
         * the count is the sum of successors of all bbs in the superblock,
         * excluding successors in the same superblock */
        for (size_t color = 1; color <= sccCnt; ++color)  {
            auto &sbs = superblock[color];

            for (auto &bb : sbs.bbs) {
                for (auto succ : successors(bb)) {
                    if (ks[succ].color != color)
                        ++sbs.nsucc;
                }
            }
            // also add leafs to the queue
            if (sbs.nsucc == 0 && !sbs.has_taint)
                q.push(color);
        }

        // debugSuperblocks();

        /* From the leaf node, access successors, but do not visit tainted
         * ones. paths that contain tainted ones will also not be visited */
        while (!q.empty()) {
            auto color = q.front();
            q.pop();

            for (auto &bb : superblock[color].bbs) {
                for (auto pred : predecessors(bb)) {
                    auto pred_color = ks[pred].color;
                    if (pred_color != color) {
                        auto &pred_sb = superblock[pred_color];
                        // check taint before decrement nsucc
                        if (!pred_sb.has_taint && --pred_sb.nsucc == 0)
                            q.push(pred_color);
                    }
                }
            }
        }

        // debugCut();

        std::vector<Instruction *> instrument_list;

        /* Look for cuts: the `br` from unvisited supernode to visited
         * supernode is in the safe cut. */
        for (size_t color = 1; color <= sccCnt; ++color) {
            auto &sbs = superblock[color];
            // non-zero nsucc superblock must be above safe cut
            if (sbs.nsucc != 0 || sbs.has_taint) continue;

            // determine which bb to instrument in the superblock (because
            // there is no need to instrument internal nodes)
            for (auto &bb : sbs.bbs) {
                // check if any of the node's predecessor is unsafe, then this
                // node is the cut point.
                for (auto pred : predecessors(bb)) {
                    auto pred_color = ks[pred].color;
                    // predecessor is unsafe if nsucc is non-zero
                    if (pred_color != color && superblock[pred_color].nsucc != 0) {
                        assert(bb->getFirstNonPHI() != nullptr);
                        instrument_list.push_back(bb->getFirstNonPHI());
                        // don't break early, because one superblock may have
                        // multiple links to the same predecessor superblock
                    }
                }
            }
        }

        return instrument_list;
    }

    locked_ostream dbg() const {
        return debug ? lerrs() : lnulls();
    }

    void debugSuperblocks() const {
        for (size_t color = 1; color <= sccCnt; ++color) {
            auto &sbs = superblock[color];
            dbg() << "=== Superblock " << color << ": "
                "tainted (" << sbs.has_taint << ") "
                "nsucc (" << sbs.nsucc << ") ===\n";
            for (auto &bb : sbs.bbs)
                dbg() << *bb;
            dbg() << "=== Superblock end ===\n";
        }
    }

    void debugCut() {
        for (size_t color = 1; color <= sccCnt; ++color) {
            auto &sbs = superblock[color];
            dbg() << "current color " << color << '\n';
            if (sbs.nsucc != 0 || sbs.has_taint) continue;
            dbg() << "current color alive " << color << '\n';
            for (auto &bb : sbs.bbs) {
                auto os = dbg();
                os << "  bb "; bb->printAsOperand(os.os, false); os << '\n';
                for (auto pred : predecessors(bb)) {
                    os << "      pred "; pred->printAsOperand(os.os, false);
                    auto pred_color = ks[pred].color;
                    os << " color " << pred_color
                        << " nsucc " << superblock[pred_color].nsucc << '\n';
                }
            }
        }
    }
};

/* Is not the last instruction in the basic block (though typically it is
 * `br`), and is not the last instruction before the `br` or `ret`. */
static inline bool is_not_last_br(const Instruction *last) {
    if (!last) return false;
    auto bb_end = &last->getParent()->back();
    return last != bb_end &&
        !(last->getNextNode() == bb_end && (isa<BranchInst>(bb_end) || isa<ReturnInst>(bb_end)));
}

bool FunctionInstrumenter::instrumentArgumentEffect(
        const analysis::ArgumentEffect &effect, uint8_t argno,
        std::vector<__phx_taint_pair> *relations)
{
    // FIXME: should be inserting a safe mark, TBD?
    if (effect.writes.empty())
        return false;

    assert(argno < state_count);

    /* === Calculate unsafe_begin === */

    /* Instrument the first modification in each basic block */
    std::vector<std::pair<Instruction *, bool>> unsafe_starts;

    /* This is used for unsafe_end: split tainted basic blocks into
     * two, so that the unsafe region could end early.
     *
     * TODO: Alternatively, we can construct a virtual graph based on
     * instruction range pair, instead of based on BB. */
    std::vector<Instruction *> breakoff_points;

    for (auto &bb : f) {
        Instruction *last_taint = nullptr;

        for (auto &inst : bb) {
            // C++20:
            // if (effect.writes.contains(&inst)) {
            if (effect.writes.find(&inst) != effect.writes.end()) {
                if (last_taint == nullptr) {
                    // lerrs() << "Function: " << f.getName() << " checking first_call at " << inst << '\n';
                    // lerrs() << f << '\n';

                    // bool first_call = inst.getNextNode() && isa<CallBase>(inst.getNextNode());
                    // FIXME: this is wrong...
                    // for (1..10)
                    //     call()
                    // will set state to FCALL before each call() ...
                    // If there ever is loop in CFG (superblock), it cannot have
                    // FCALL or LCALL, but have to set B before it, and E after it.

                    bool first_call = false;
                    if (auto *call = dyn_cast<CallBase>(&inst)) {
                        auto called_func = call->getCalledFunction();
                        // treat instrinsic and external function as INSTRUCTION
                        // and not function call, because they cannot write to
                        // flcallee_done.
                        first_call = !isa<IntrinsicInst>(inst) &&
                            !(called_func && analysis::isKnownExternalFunctions(*called_func, phx_preset));
                    }

                    unsafe_starts.push_back({&inst, first_call});
                    if (first_call) {
                        // auto callee_arg_no = effect.taint_call_arg.find(&inst)->second;
                    }
                }
                last_taint = &inst;
            }
        }
        // optimization for IR clarity: do not breakoff the last instruction
        if (is_not_last_br(last_taint))
            breakoff_points.push_back(last_taint->getNextNode());
    }
    dumpDebugInstrumentPoint(breakoff_points, "split_point");

    for (auto inst : breakoff_points) {
        auto bb = inst->getParent();
        bb->splitBasicBlock(inst);
    }

    /* Start inserting instrumentation
     * NOTE: This must be called after the analysis above. Otherwise the
     * "first_call" calculation will be wrong (but it shouldn't be..) */
    // prepareFunctionHook();

    // TODO: use GUI for debugging
    // https://llvm.org/docs/ProgrammersManual.html -> Viewing graphs while debugging code
    if (debugSplittedFunction)
        lerrs() << "=== splitted function is ===\n" << f << "=== end splitted function ===\n";

    // equivalent to:
    //     state[argno] = STATE;

    Value *slot_arg = nullptr;
    {
        auto b = IRBuilder(unified_states_initcall);
        if (slot_flcallee_done == nullptr)
            slot_flcallee_done = b.CreateGEP(b.getInt8Ty(), unified_states_ptr, b.getInt64(0), "flcallee_done");
        slot_arg = b.CreateGEP(b.getInt8Ty(), unified_states_ptr,
            b.getInt64(argno+1),    // +1 for flcallee_done
            "argstate" + std::to_string(argno));
    }

    // size_t instru_cnt = 0;
    for (auto [inst, first_call] : unsafe_starts) {
        auto b = IRBuilder(inst);
        if (first_call) {
            // auto suffix = std::to_string(instru_cnt++);
            b.CreateStore(b.getInt8(0), slot_flcallee_done, true);
            b.CreateStore(b.getInt8(FCALL), slot_arg, true);
            b.SetInsertPoint(inst->getNextNode());
            b.CreateStore(b.getInt8(MODIFYING), slot_arg, true);

            auto callee_argtaint = effect.callee_relation.find(inst);
            if (callee_argtaint == effect.callee_relation.end()) {
                die() << "callee_argtaint not found for " << *inst << '\n';
            }

            if (relations) {
                relations->push_back({
                    .caller_arg = argno,
                    .callsite = FCALL,
                    .argtaint = callee_argtaint->second,
                });
            }
        } else {
            // TODO handle LCALL
            b.CreateStore(b.getInt8(MODIFYING), slot_arg, true);
        }
    }

    // TODO: instrument RCALL
    // FIXME: we should handle cases where LCALL=RCALL **on one of the path**
    // instead of checking only number of writes.

    // === instrument end of unsafe region ===
    auto unsafe_ends = SafeCut(f, effect.writes, debugSafeCut).run();
    // equivalent to:
    //     state[argno] = MODIFY_END;
    // FIXME: add another bit to tell that the function has modified already
    for (auto inst : unsafe_ends) {
        auto b = IRBuilder(inst);
        // lerrs() << "instrumenting unsafe_end at " << *inst << '\n';

        // FIXME: Handle function call
        b.CreateStore(b.getInt8(MODIFY_END), slot_arg, true);
    }

    if (debugInstrumentPoint) {
        // dumpDebugInstrumentPoint(unsafe_starts, "unsafe_start");
        dumpDebugInstrumentPoint(unsafe_ends, "safe_cut");
    }

    return true;
}

void FunctionInstrumenter::prepareFunctionHook() {
    /* Already created */
    if (storage)
        return;

    /* Create storage at the very beginning */
    auto b = IRBuilder(&f.front().front());

    auto guard = anyLock(&M);

    /* Create storage and also initialize.
     * Equivalent to:
     * struct __phx_func_state_local local = {
     *     .func_id = thisfuncid,
     *     .__unified_states = {0} // length nbytes
     * };
     */
    size_t nbytes = state_count + 1;    // +1 for flcallee_done
    auto unified_states_type = ArrayType::get(b.getInt8Ty(), nbytes);
    std::vector<Type*> state_fields = {
        b.getInt32Ty(),  // func_id
        unified_states_type // __unified_states[]
    };
    storage_type = StructType::get(b.getContext(), state_fields);
    storage = b.CreateAlloca(storage_type, nullptr, "__phx_func_state_local");

    // Initialize func_id
    auto func_id_ptr = b.CreateStructGEP(storage_type, storage, 0);
    static_assert(sizeof(thisfuncid) == 4, "func_id_t size mismatch");
    b.CreateStore(b.getInt32(thisfuncid), func_id_ptr);

    // Initialize unified_states array to 0
    unified_states_ptr = b.CreateStructGEP(storage_type, storage, 1);
    unified_states_initcall = b.CreateMemSet(unified_states_ptr, b.getInt8(0), nbytes, MaybeAlign());
    unified_states_initcall = unified_states_initcall->getNextNode();
    // lerrs() << "created storage " << *storage << '\n';
    // lerrs() << "created memset " << *memset << '\n';

    /* Register storage to global array.
     * Equivalent to:
     *    fstate** oldtop = __phx_func_state_top;
     *    fstate** nexttop = oldtop + 1;
     *    *nexttop = &local;
     *    __phx_func_state_top = nexttop;
     *
     * TODO use thread local storage to store global array.
     * CreateThreadLocalAddress */

    // Get or create (declaration only) variable (runtime contains this)
    auto phxtop = M.getOrInsertGlobal("__phx_func_state_top_tls", b.getPtrTy());
    assert(phxtop != nullptr && isa<GlobalVariable>(phxtop));
    dyn_cast<GlobalVariable>(phxtop)->setThreadLocal(true);
    // TODO use platform width: https://stackoverflow.com/a/56864871/7804578
    auto oldtop = b.CreateLoad(b.getPtrTy(), phxtop, "__phx_old_top");

    auto nexttop = b.CreateGEP(b.getPtrTy(), oldtop, b.getInt32(1));

    b.CreateStore(storage, nexttop, true);

    b.CreateStore(nexttop, phxtop, true);

    // === Reset stack layer before return ===
    // equivalent to:
    //     __phx_func_state_top = oldtop;
    for (auto &inst : instructions(f)) {
        if (isa<ReturnInst>(inst)) {
            b.SetInsertPoint(&inst);

            auto oldstack = b.CreateLoad(b.getPtrTy(), oldtop, "__phx_old_stack");
            auto oldstack_unified_states_ptr = b.CreateStructGEP(storage_type, oldstack, 1);
            auto oldstack_flcallee_done = b.CreateGEP(b.getInt8Ty(), oldstack_unified_states_ptr, b.getInt64(0));

            b.CreateStore(b.getInt8(1), oldstack_flcallee_done, true);

            b.CreateStore(oldtop, phxtop, true);
            break;
        }
    }

    // errs() << "=== begin new func ===\n" << f << "=== end new func ===\n";
}

// TODO: use GUI for debugging
// https://llvm.org/docs/ProgrammersManual.html -> Viewing graphs while debugging code
void FunctionInstrumenter::dumpDebugInstrumentPoint(std::vector<Instruction *> insts, std::string_view name) const {
    if (!debugSplitPoint) return;

    lerrs() << "=== " << name << " list begin ===\n";
    for (auto inst : insts) {
        auto os = lerrs();
        os << "  bb ";
        inst->getParent()->printAsOperand(os.os, false);
        os << ':' << *inst << '\n';
    }
    lerrs() << "=== " << name << " list end ===\n";
}

} // namespace instrument

} // namespace phoenix
