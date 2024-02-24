#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/raw_ostream.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <ranges>

#include "Instrumenter.h"
#include "Utils.h"

using namespace llvm;
using std::ranges::reverse_view;

namespace phoenix {

namespace instrument {

/* Algorithm to calculate the safe end cut. See `run` for a overall step.
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
        for (auto &bb : reverse_view(visit_order))
            if (!ks[bb].color) {
                ++sccCnt;
                superblock.push_back({});
                dfs2(bb);
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
                        break;
                    }
                }
            }
        }

        return instrument_list;
    }

    locked_ostream dbg() const {
        return debug ? lerrs() : locked_ostream(nulls());
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

static void dumpDebugInstrumentPoint(std::vector<Instruction *> insts, std::string_view s);

/* Is not the last instruction in the basic block (though typically it is
 * `br`), and is not the last instruction before the `br` or `ret`. */
static inline bool is_not_last_br(const Instruction *last) {
    if (!last) return false;
    auto bb_end = &last->getParent()->back();
    return last != bb_end &&
        !(last->getNextNode() == bb_end && (isa<BranchInst>(bb_end) || isa<ReturnInst>(bb_end)));
}

bool FunctionInstrumenter::instrumentArgumentEffect(
        const analysis::ArgumentEffect &effect, size_t argno)
{
    if (effect.taints.empty())
        return false;

    assert(argno < max_state_size);

    prepareFunctionHook();

    // === instrument start of the unsafe region ===

    // instrument the first modification in each basic block
    std::vector<Instruction *> unsafe_starts;
    // This is used for end of modification: split tainted basic blocks into
    // two, so that the unsafe region could end early.
    // TODO: Alternatively, we can construct a virtual graph based on
    // instruction range pair, instead of based on BB.
    std::vector<Instruction *> breakoff_points;

    for (auto &bb : f) {
        Instruction *last = nullptr;

        for (auto &inst : bb) {
            if (effect.taints.contains(&inst)) {
                if (last == nullptr)
                    unsafe_starts.push_back(&inst);
                last = &inst;
            }
        }
        // optimization for IR clarity: do not breakoff the last instruction
        if (is_not_last_br(last))
            breakoff_points.push_back(last->getNextNode());
    }
    if (debugSplitPoint)
        dumpDebugInstrumentPoint(breakoff_points, "split_point");

    for (auto inst : breakoff_points) {
        auto bb = inst->getParent();
        bb->splitBasicBlock(inst);
    }

    // TODO: use GUI for debugging
    // https://llvm.org/docs/ProgrammersManual.html -> Viewing graphs while debugging code
    if (debugSplittedFunction)
        lerrs() << "=== splitted function is ===\n" << f << "=== end splitted function ===\n";

    // equivalent to:
    //     state[argno] |= mask;
    size_t instru_cnt = 0;
    for (auto inst : unsafe_starts) {
        auto b = IRBuilder(inst);
        auto section = b.CreateInBoundsGEP(storage_type, storage, { b.getInt64(0), b.getInt64(argno / 8) });
        auto suffix = std::to_string(instru_cnt++);
        auto tmpmask = b.CreateLoad(b.getInt8Ty(), section, "__phx_tmp_mask_" + suffix);
        auto newmask = b.CreateOr(tmpmask, b.getInt8(1 << (argno % 8)), "__phx_new_mask_" + suffix);
        b.CreateStore(newmask, section, true);
    }

    // === instrument end of unsafe region ===
    auto unsafe_ends = SafeCut(f, effect.taints, debugSafeCut).run();
    // equivalent to:
    //     state[argno] &= ~mask;
    // FIXME: add another bit to tell that the function has modified already
    for (auto inst : unsafe_ends) {
        auto b = IRBuilder(inst);
        auto section = b.CreateInBoundsGEP(storage_type, storage, { b.getInt64(0), b.getInt64(argno / 8) });
        auto suffix = std::to_string(instru_cnt++);
        auto tmpmask = b.CreateLoad(b.getInt8Ty(), section, "__phx_tmp_mask_" + suffix);
        auto newmask = b.CreateAnd(tmpmask, b.getInt8(~(1 << (argno % 8))), "__phx_new_mask_" + suffix);
        b.CreateStore(newmask, section, true);
    }

    if (debugInstrumentPoint) {
        dumpDebugInstrumentPoint(unsafe_starts, "unsafe_start");
        dumpDebugInstrumentPoint(unsafe_ends, "safe_cut");
    }

    return true;
}

void FunctionInstrumenter::prepareFunctionHook() {
    if (storage)
        return;

    auto b = IRBuilder(&f.front().front());

    auto guard = anyLock(&M);

    // === Create storage ===
    // equivalent to `char __phxfuncstate[nbytes] = {0};`
    // don't forget to initialize
    size_t nbytes = (max_state_size + 7) / 8;

    storage_type = ArrayType::get(b.getInt8Ty(), nbytes);
    storage = b.CreateAlloca(storage_type, nullptr, "__phx_func_state");
    b.CreateMemSet(storage, b.getInt8(0), nbytes, MaybeAlign());
    // lerrs() << "created storage " << *storage << '\n';
    // lerrs() << "created memset " << *memset << '\n';

    // === Register storage to global array ===
    // equivalent to:
    //    size_t __phx_old_top = __phx_func_state_top;
    //    __phx_func_state_array[__phx_old_top] = __phx_func_state;
    //    __phx_func_state_top = __phx_old_top + 1;
    //
    // TODO use thread local storage to store global array
    // CreateThreadLocalAddress
    auto phxarray_ptr = M.getGlobalVariable("__phx_func_state_array_ptr");
    auto phxtop = M.getGlobalVariable("__phx_func_state_top");
    if (!phxarray_ptr || !phxtop) {
        lerrs() << "Variable __phx_func_state_array or __phx_func_state_top not found!\n";
        return;
    }
    // TODO use platform width: https://stackoverflow.com/a/56864871/7804578
    auto phxarray = b.CreateLoad(b.getPtrTy(), phxarray_ptr, "__phx_func_state_array");
    auto oldtop = b.CreateLoad(b.getInt64Ty(), phxtop, "__phx_old_top");

    auto myslot = b.CreateInBoundsGEP(b.getPtrTy(), phxarray, { oldtop, });
    b.CreateStore(storage, myslot, true);

    auto nexttop = b.CreateAdd(oldtop, b.getInt64(1));
    b.CreateStore(nexttop, phxtop, true);

    // === Reset stack layer before return ===
    // equivalent to:
    //     __phx_func_state_top = __phx_old_top;
    for (auto &inst : instructions(f)) {
        if (isa<ReturnInst>(inst)) {
            new StoreInst(oldtop, phxtop, true, &inst);
        }
    }

    // errs() << "=== begin new func ===\n" << f << "=== end new func ===\n";
}

// TODO: use GUI for debugging
// https://llvm.org/docs/ProgrammersManual.html -> Viewing graphs while debugging code
static void
dumpDebugInstrumentPoint(std::vector<Instruction *> insts, std::string_view name) {
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
