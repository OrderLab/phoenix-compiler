#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <queue>
#include <shared_mutex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <string_view>

#include "FieldChain.h"
#include "FunctionAnalysis.h"
#include "Injector.h"
#include "Instrumenter.h"
#include "ModuleAnalysis.h"
#include "ThreadPool.h"
#include "Utils.h"
#include "phx_instrument_compiler_abi.h"

#include "redis_72_root.hpp"

using namespace llvm;

namespace phoenix {

namespace analysis {

bool is_force_leaf_redis(const llvm::Function &f) {
    std::unordered_set<std::string> force_leaf_funcs = {
        "_serverPanic",
        "_serverAssert",
        "redis_check_rdb"
    };
    std::vector<std::string> force_leaf_prefixes = {
        "addReply",
        "replication",
        "module",
        "ldb",
        "lua",
    };
    for (auto &prefix : force_leaf_prefixes) {
        if (f.getName().startswith(prefix)) {
            return true;
        }
    }
    if (force_leaf_funcs.find(f.getName().str()) != force_leaf_funcs.end()) {
        return true;
    }

    return false;
}

TopologyFuncList topology_sort(Module &M, const std::string &preset) {
    // function type
    using ftype = Function *;
    // function state
    struct fstate {
        /* number of callees, decrementing to 0 means all callee summaries have
         * been calculated. There could be duplicate call pairs (i.e. one
         * function has multiple instructions that call the same function), but
         * since the sum(ncallee) matches sum(callers.size()), the function
         * will still be added to the queue once and only once. */
        size_t ncallees;
        /* When all callee summaries has been calculated, calculate the current
         * function, and notify all callers to decrement their ncallees.
         * Duplicate callers will work fine since ncallees also has duplicate
         * counts. */
        bool visited;
        std::vector<ftype> callers;
        // for debug use only
        std::unordered_multiset<ftype> debug_callees;
    };

    std::unordered_map<ftype, fstate> calls;

    /* First pass: build the call dependency graph */
    for (auto &caller : M) {
        // touch caller to make sure leaf funcions are also added
        calls[&caller];

        // Empty function are external functions
        if (caller.empty() && !isKnownExternalFunctions(caller, preset)) {
            lerrs() << "External unknown function: " << demangleName(caller.getName().str()) << '\n';
        }

        // Force leaf
        if (preset == "redis") {
            if (is_force_leaf_redis(caller)) {
                lerrs() << "Force leaf function: " << caller.getName() << '\n';
                continue;
            }
        }

        // Find all call instructions
        for (auto &inst : instructions(caller)) {
            // if (inst.isDebugOrPseudoInst()) continue;

            if (auto call = dyn_cast<CallBase>(&inst)) {

                auto callee = call->getCalledFunction();
                if (callee == nullptr) {
                    lerrs() << "Indirect call not processed in " << caller.getName()
                        << " value ID: " << call->getCalledOperand()->getValueID() << '\n';
                    continue;
                }

                if (callee == &caller) {
                    // handle direct recursion
                    lerrs() << "Direct recursion found: " << caller.getName() << "\n";
                    continue;
                }

                ++calls[&caller].ncallees;
                calls[callee].callers.push_back(&caller);

                calls[&caller].debug_callees.insert(callee);
            }
        }
    }

    /* Second pass: topological sort */
    // TODO: This does not handle mutual calls: a calls b, b calls a

    // queue, which is also the topology sort result
    TopologyFuncList q;
    // do not actually pop the queue, since we also need to return the queue
    size_t qfront = 0;

    // Start with all leaf functions
    for (auto &[f, fstate] : calls) {
        if (fstate.ncallees == 0) {
            q.push_back({f, 0});
            fstate.visited = true;
        }
    }

    /* Run the actual topological sort with BFS */
    while (qfront != q.size()) {
        auto [f, order] = q[qfront++];
        for (const auto &caller : calls[f].callers) {
            auto &fstate = calls[caller];

            if (fstate.ncallees == 0) {
                lerrs() << "Internal error: ncallees prematurely decrements to 0! "
                    << caller->getName() << "\n";
                continue;
            } else if (fstate.visited) {
                lerrs() << "Internal error: function has been visited in dependency graph! "
                    << caller->getName() << "\n";
                continue;
            }

            fstate.debug_callees.erase(f);
            // If all callees have been visited (calculated summaries), we
            // should be able to use their summaries to calculate the current.
            if (--fstate.ncallees == 0) {
                q.push_back({caller, order + 1});
                fstate.visited = true;
            }
        }
    }

    /* Check if there are loops. Currently we really cannot handle them... */
    if (q.size() != calls.size()) {
        auto fail_count = calls.size() - q.size();
        lerrs() << "Error: not all functions called are in the dependency graph! "
            "Possible loop found for " << fail_count << " functions \n";
        if (1 || fail_count <= 10) {
            for (auto &[f, ftype] : calls) {
                if (!ftype.visited) {
                    if (f->getName().startswith("lua")) {
                        continue;
                    }
                    if (auto MD = f->getMetadata("dbg")) {
                        if (auto *subProgram = dyn_cast<DISubprogram>(MD)) {
                            lerrs() << subProgram->getFile()->getDirectory()
                                << '/' << subProgram->getFile()->getFilename() << '\n';
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                    lerrs() << "Unvisited function: " << f->getName() <<
                        " degrees " << calls[f].ncallees << '\n';
                    for (auto &callee : calls[f].debug_callees) {
                        lerrs() << "\tcallee " << callee->getName() << '\n';
                    }
                }
            }
        }
    }

    return q;
}

class RealModuleAnalysis : public ModuleAnalysis {
    public:
    // Some option fields are defined in ModuleAnalysis
    RealModuleAnalysis(const ModuleAnalysis &m)
        : ModuleAnalysis(m),
        injector(m.M, m.phx_preset, m.inject_parallel_names)
    {}

private:
    /* ====================== Parsed Arguments ========================= */

    // <function, [argno1, argno2, ...]>
    std::vector<std::pair<Function *, std::vector<size_t>>> scope_root_funcs;

    /* ==================== Analysis Related Data ====================== */
    TopologyFuncList sorted_func;

    using FunctionSummaryMap = phoenix::analysis::FunctionSummaryMap;
    FunctionSummaryMap function_summaries;

    /* ================= Instrumentation Related Data ================== */

    struct FunctionRelation {
        Function *f;
        std::vector<uint8_t> modify_type;
        // TODO: turn this into two level array?
        std::vector<__phx_taint_pair> relations;
    };
    // index is allocated function_id
    using FunctionRelationsTable = std::vector<FunctionRelation>;
    FunctionRelationsTable function_relations_table;
    // std::unordered_map<Function*, func_id_t> func_id_map;

    StructType *taint_pair_type = nullptr;
    StructType *func_relation_type = nullptr;
    /* We will generate a lot of __phx_func_relation_X_t, where X is the
     * length of taints[]. Store them and reuse them as we can. */
    std::unordered_map<size_t, StructType*> scenario_count_to_type;

    /* ===================== Injector ===================== */
    injector::Injector injector;
    ClonedFunctionMap cloned_function_map;

    /* ===================== Debug counters ===================== */
    std::atomic<size_t> instrumented_origs = 0;
    std::atomic<size_t> modified_scenario = 0, modified_function = 0;
    std::atomic<size_t> single_arg_func_count = 0, two_arg_func_count = 0;
    std::atomic<size_t> three_arg_func_count = 0, max_arg = 0;

private:
    /* === Auxiliary functions === */

    void parseArguments() {
        // C++23: https://stackoverflow.com/a/68655819/7804578
        // std::string_view&& word : line | std::views::split(' ')

        std::stringstream ss(scope_root);
        std::string funcitem;

        // format is like: flow:1:2,caller:1 (1-based index)
        while (std::getline(ss, funcitem, ',')) {
            if (funcitem == "") {
                continue;
            }

            std::stringstream funcitem_ss(funcitem);
            std::string funcname;
            std::getline(funcitem_ss, funcname, ':');

            Function *func = getFunctionByName(funcname, M);
            if (!func) {
                die() << "Scope root \"" << funcitem << "\" cannot be found!\n";
            }

            std::string funcargno;
            std::vector<size_t> argnos;

            while (std::getline(funcitem_ss, funcargno, ':')) {
                if (funcargno == "") {
                    die() << "Scope root argno empty!\n";
                }

                argnos.push_back(std::stoul(funcargno));
            }

            lerrs() << "Found scope root \"" << funcitem << "\"\n";
            scope_root_funcs.push_back({func, argnos});
        }
    }

    void updateDebugCounters(size_t modified_cnt) {
        modified_function += bool(modified_cnt);
        modified_scenario += modified_cnt;
        single_arg_func_count += (modified_cnt == 1);
        two_arg_func_count += (modified_cnt == 2);
        three_arg_func_count += (modified_cnt == 3);
        max_arg = std::max((size_t)max_arg, modified_cnt);
    }

    void dumpDebugCounters() const {
        lerrs() << "Instrumented " << instrumented_origs << " original functions\n";
        lerrs() << "Instrumented " << modified_function << " functions with "
            << modified_scenario << " argument scenarios\n";
        lerrs() << "Unmodified function " << (function_summaries.size() - modified_function) << '\n';

        lerrs() << "two_arg_func_count " << two_arg_func_count << '\n';
        lerrs() << "three_arg_func_count " << three_arg_func_count << '\n';
        lerrs() << "max_arg " << max_arg << '\n';

        /* for (auto &f : M) {
            lerrs() << "=======\n" << f << "********\n\n";
        } */
    }

    void debugTopologySort() const {
        int i = 0;
        for (auto &[f, order] : sorted_func) {
            lerrs() << ++i << ": Function " << f->getName() << " at order " << order << "\n";
        }
    }

public:
    /* === Start analysis function === */
    bool run() {
        parseArguments();

        /* First get the topology sort */
        sorted_func = topology_sort(M, phx_preset);

        lerrs() << "Total functions: " << M.size() << '\n';
        lerrs() << "topology link length: " <<
            (sorted_func.size() ? sorted_func.back().second : 0) << '\n';
        debugTopologySort();

        analyzeAndInstrument();
        dumpDebugCounters();

        // Generate the function relations table for runtime
        generateFunctionRelationsTable();

        injector.fork_multiplexer_tail();

        // Success if we modified at least one function
        return bool(modified_function);
    }

private:
    void dumpFunction(const Function &f) {
        // return;
        lerrs() << "=== dump of function " << f.getName() << "\n";
        lerrs() << f << '\n';
        /* lerrs() << "=== dump of function " << f.getName() << "\n";
        for (auto &bb : f) {
            lerrs() << "Found basic block " << (void*)&bb << '\n';
            for (auto &inst : bb) {
                lerrs() << "\tFound inst " << inst << '\n';
            }
            lerrs() << "End basic block " << (void*)&bb << '\n';
        }
        lerrs() << "===\n"; */
    }

    void analyzeAndInstrument() {
        // parallel functionality is broken. LLVM probably does not support
        // parallelization (probably in errs() debug print part)
        parallel = false;

        if (parallel)
            analyzeAndInstrumentParallel();
        else
            analyzeAndInstrumentSequential();

        instrumentMainThreadInit();
        instrumentPthreadInit();
    }

    /*
     * Call __phx_instrument_init_thread in the beginning of main().
     */
    void instrumentMainThreadInit() {
        Function *main = M.getFunction("main");
        if (!main || main->isDeclaration()) return;

        auto &mctx = M.getContext();
        IRBuilder<> b(&*main->getEntryBlock().getFirstInsertionPt());

        auto init = M.getOrInsertFunction("__phx_instrument_init_thread", Type::getVoidTy(mctx));
        assert(init);

        b.CreateCall(init.getFunctionType(), init.getCallee(), {});
        lerrs() << "Phoenix instrumenter: Instrumented main thread init\n";
    }

    /*
     * Replace pthread_create calls with phx_pthread_create_wrapper.
     */
    void instrumentPthreadInit() {
        Function *pthread_create_f = M.getFunction("pthread_create");
        // Module has no call to pthread_create, good.
        if (!pthread_create_f) return;

        auto wrapper = M.getOrInsertFunction("phx_pthread_create_wrapper",
                pthread_create_f->getFunctionType());

        // It is problematic to replace called function while iterating over
        // users, so we collect them first...
        std::vector<User*> users(pthread_create_f->users().begin(), pthread_create_f->users().end());

        int count = 0;
        for (auto U : users) {
            auto inst = dyn_cast<Instruction>(U);

            // Skip if use is in the runtime wrapper function
            if (inst && inst->getFunction() == wrapper.getCallee()) {
                lerrs() << "Phoenix instrumenter: Skipping pthread_create user in wrapper "
                    << *U << "\n";
                continue;
            }

            if (auto call = dyn_cast<CallBase>(U)) {
                call->setCalledFunction(wrapper);
                ++count;
            } else {
                die() << "Warning: pthread_create has non-call use in function "
                    << (inst ? inst->getFunction()->getName() : "(non function)")
                    << ", usage: " << *U << "\n";
            }
        }
        lerrs() << "Phoenix instrumenter: Replaced " << count << " pthread_create calls\n";
    }

    /*
     * Main analysis step.  Analyze all functions, instrument them, and
     * optionally prepare for injection.
     *
     * TODO: Add instrument-only mode.
     *
     * Steps of how injector interact with instrumenter:
     * 1. instrument: effect analyze by topology order (leaf to root)
     * 2. injector:   random select instruction * count
     * 3. main pass:  dup * 4
     * 4. injector:   map * 2 * count
     * 5. instrument: all single func instrument (run twice only on injected
     *                functions, though wasting a little CPU time)
     * 6. injector:   finally do inject
     * 7. main pass:  create a shim function that calls the correct version and
     *                relink all calls
     */
    void analyzeAndInstrumentSequential() {
        using injector::OO, injector::OF, injector::IO, injector::IF;

        auto cloneAndAnalyze = [this](Function *f,
            const char *suffix, injector::InjectVersion suffix_id)
        {
            llvm::ValueToValueMapTy VMap;
            auto new_f = CloneFunction(f, VMap);
            new_f->setName(f->getName() + suffix);

            cloned_function_map[f][suffix_id] = new_f;

            // this wastes CPU cycle... fix this later
            if (suffix_id == IO || suffix_id == IF) {
                analyzeOneFunction(new_f, nullptr, false, false);
            }
        };

        injector.preprocessPrefixSum(sorted_func);

        /* 1. Analyze the modification effect of all functions in
         * topology order, save the function effect summaries into a map.
         * 3. At the same time, create duplicated functions for later
         * instrumentation and injection use. */
        for (auto &[f, order] : sorted_func) {
            if (!isInstrumentableFunction(*f))
                continue;

            analyzeOneFunction(f, nullptr, false, true);

            // Set noinline!
            // https://stackoverflow.com/a/54589116/7804578
            f->addAttributeAtIndex(AttributeList::FunctionIndex, Attribute::get(M.getContext(), Attribute::NoInline));

            cloneAndAnalyze(f, "_OO", OO);
            cloneAndAnalyze(f, "_IO", IO);
        }

        injector.fork_multiplexer_magic();

        /* 2. Random selection of injectable function with the instrucitons. */
        injector.select_injectable_instructions(sorted_func, inject_count,
                inject_offsets_override);

        /* 3. Dup*2 (remaining injections) */
        for (auto &[f, order] : sorted_func) {
            if (!isInstrumentableFunction(*f) || !injector.isToInject(*f))
                continue;
            cloneAndAnalyze(f, "_OF", OF);
            cloneAndAnalyze(f, "_IF", IF);
        }

        /* 4. Find the injectable instructions in the duplicated functions. */
        injector.collect_injectable_instructions(cloned_function_map);

        /* 5. Instrument the functions. */
        for (auto &[f, order] : sorted_func) {
            if (!isInstrumentableFunction(*f))
                continue;

            /* Assign only one function ID for each group of duplicated
             * functions.
             * TODO: assert whether both instrumentations agrees. */
            func_id_t func_id = function_relations_table.size();
            function_relations_table.push_back({f, {}, {}});

            FunctionRelation &func_relation = function_relations_table.back();
            assert_eq(&func_relation - &function_relations_table.front(), func_id);

            /* Collect modify types */
            assert_eq(function_summaries.at(f).argument_effects.size(), f->arg_size() + 1);
            for (auto &effect : function_summaries.at(f).argument_effects) {
                func_relation.modify_type.push_back((uint8_t)effect.modify_type);
            }

            /* Instrument IO, optionally IF. */
            auto &cloned_functions = cloned_function_map.at(f);
            // Update debug counter
            ++instrumented_origs;

            instrumentOneFunction(cloned_functions.at(IO), func_id, &func_relation);

            if (cloned_functions.find(IF) != cloned_functions.end()) {
                instrumentOneFunction(cloned_functions.at(IF), func_id, nullptr);
            }
        }

        // warnIfFieldFunctionRuleUnused();

        /* 6. Finally inject on the collected instructions. */
        injector.inject_all();

        /* 7. Relink all calls. */
        for (auto &[f, order] : sorted_func) {
            relinkCalls(f);
        }
    }

    Function *getClonedFunctionOrFallback(Function *f, injector::InjectVersion suffix) {
        auto &cloned_functions = cloned_function_map.at(f);

        if (cloned_functions.find(suffix) == cloned_functions.end()) {
            if (suffix == injector::IF) {
                return cloned_functions.at(injector::IO);
            } else if (suffix == injector::OF) {
                return cloned_functions.at(injector::OO);
            } else {
                die() << "Unexpected not found suffix: " << f->getName() << " " << suffix << "\n";
            }
        } else {
            return cloned_functions.at(suffix);
        }
    }

    /* Relink calls.
     * Replace the original function with a shim that calls the correct version
     * of function on-demand. */
    void relinkCalls(Function *f) {
        if (!isInstrumentableFunction(*f))
            return;

        /* Get the debug location of the original function
         * FIXME: why this is only getting the first instruction with debug
         * location? */
        DebugLoc loc;
        for (auto &inst : instructions(f)) {
            if (inst.getDebugLoc()) {
                loc = inst.getDebugLoc();
                break;
            }
        }

        /* Clear the function  */
        // for (auto &bb : iterator_range(f->begin(), f->end())) {
        for (auto &bb : *f) {
            // Finally fixed crash... Stealing this line from ~Function()...
            bb.dropAllReferences();
        }
        while (!f->empty()) {
            f->begin()->eraseFromParent();
        }

        /* === Create a function that jumps to the correct version of the
         * function based on the global run_mode variable. === */
        BasicBlock::Create(M.getContext(), "base", f);

        auto b = IRBuilder(&f->front());

        AllocaInst *alloc = nullptr;
        Instruction *retblock = nullptr;
        if (!f->getFunctionType()->getReturnType()->isVoidTy()) {
            alloc = b.CreateAlloca(f->getFunctionType()->getReturnType());
            retblock = b.CreateLoad(f->getFunctionType()->getReturnType(), alloc);
            b.CreateRet(retblock);
        } else {
            // FIXME: dummy instruction for breakoff
            b.CreateAdd(b.getInt32(0), b.getInt32(0));
            retblock = b.CreateRetVoid();
        }

        b.SetInsertPoint(retblock);

        // Get or create (declaration only) variable (runtime contains this)
        auto global_inject_run_mode = M.getOrInsertGlobal("__phx_inject_run_mode", b.getInt32Ty());
        assert(global_inject_run_mode != nullptr);
        auto run_mode_val = b.CreateLoad(b.getInt32Ty(), global_inject_run_mode, "run_mode");

#if 0
        /* This version generates a jump table implementation (on x86_64). */
        for (auto suffix : {injector::OO, injector::OF, injector::IO, injector::IF}) {
            b.SetInsertPoint(retblock);

            auto icmp = b.CreateICmpEQ(run_mode_val, b.getInt32(suffix));
            auto then = SplitBlockAndInsertIfThen(icmp, retblock, false);

            b.SetInsertPoint(then);

            std::vector<Value *> args;
            for (auto &arg : f->args())
                args.push_back(&arg);

            auto call = b.CreateCall(getClonedFunctionOrFallback(f, suffix), args);
            call->setDebugLoc(loc);
            // call_OO->setIsNoInline();
            if (!f->getFunctionType()->getReturnType()->isVoidTy()) {
                b.CreateStore(call, alloc);
            }
        }
#else
        /* This version generates branch-based (on x86_64). */
        auto icmp_OO = b.CreateICmpEQ(run_mode_val, b.getInt32(0));

        Instruction *branch_OO = nullptr;
        Instruction *branch_OO_else = nullptr;

        SplitBlockAndInsertIfThenElse(icmp_OO,
                retblock,
                &branch_OO,
                &branch_OO_else);

        b.SetInsertPoint(branch_OO);

        std::vector<Value *> args_OO;
        for (auto &arg : f->args())
            args_OO.push_back(&arg);
        auto call_OO = b.CreateCall(getClonedFunctionOrFallback(f, injector::OO), args_OO);
        call_OO->setDebugLoc(loc);
        // call_OO->setIsNoInline();
        if (!f->getFunctionType()->getReturnType()->isVoidTy()) {
            b.CreateStore(call_OO, alloc);
        }

        b.SetInsertPoint(branch_OO_else);

        auto icmp_OF = b.CreateICmpEQ(run_mode_val, b.getInt32(1));

        Instruction *branch_OF = nullptr;
        Instruction *branch_OF_else = nullptr;
        SplitBlockAndInsertIfThenElse(icmp_OF,
                branch_OO_else,
                &branch_OF,
                &branch_OF_else);

        b.SetInsertPoint(branch_OF);

        std::vector<Value *> args_OF;
        for (auto &arg : f->args())
            args_OF.push_back(&arg);
        auto call_OF = b.CreateCall(getClonedFunctionOrFallback(f, injector::OF), args_OF);
        // call_OF->setIsNoInline();
        call_OF->setDebugLoc(loc);
        if (!f->getFunctionType()->getReturnType()->isVoidTy()) {
            b.CreateStore(call_OF, alloc);
        }

        b.SetInsertPoint(branch_OF_else);

        auto icmp_IO = b.CreateICmpEQ(run_mode_val, b.getInt32(2));

        // dumpFunction(*f);
        // lerrs() << "branch_OF_else is " << *branch_OF_else << '\n';

        Instruction *branch_IO = nullptr;
        Instruction *branch_IO_else = nullptr;
        SplitBlockAndInsertIfThenElse(icmp_IO,
                branch_OF_else,
                &branch_IO,
                &branch_IO_else);

        b.SetInsertPoint(branch_IO);

        std::vector<Value *> args_IO;
        for (auto &arg : f->args())
            args_IO.push_back(&arg);
        auto call_IO = b.CreateCall(getClonedFunctionOrFallback(f, injector::IO), args_IO);
        // call_IO->setIsNoInline();
        call_IO->setDebugLoc(loc);
        if (!f->getFunctionType()->getReturnType()->isVoidTy()) {
            b.CreateStore(call_IO, alloc);
        }

        b.SetInsertPoint(branch_IO_else);

        // then remaining is OO
        std::vector<Value *> args_IF;
        for (auto &arg : f->args())
            args_IF.push_back(&arg);
        auto call_IF = b.CreateCall(getClonedFunctionOrFallback(f, injector::IF), args_IF);
        // call_IF->setIsNoInline();
        call_IF->setDebugLoc(loc);
        if (!f->getFunctionType()->getReturnType()->isVoidTy()) {
            b.CreateStore(call_IF, alloc);
        }

#endif
        // dumpFunction(*f);
    }

    void initTaintTableTypes() {
        if (taint_pair_type != nullptr)
            return;

        auto &mctx = M.getContext();
        auto b = IRBuilder(mctx);

        taint_pair_type = StructType::create(mctx, {
                b.getInt8Ty(),  // caller_arg
                b.getInt8Ty(),  // callsite
                b.getInt32Ty()  // argtaint
            }, "__phx_taint_pair");
        func_relation_type = StructType::create(mctx, {
                PointerType::get(b.getInt8Ty(), 0),  // func_name (char*)
                ArrayType::get(b.getInt8Ty(), 16),  // modify_type
                b.getInt32Ty(),  // nargs
                b.getInt32Ty(),  // nrelations
                ArrayType::get(taint_pair_type, 0)  // taints[] flexible array member
            }, "__phx_func_relation");
    }

    /* Get or create the struct type for this taint count */
    StructType *getOrCreateFuncRelationType(size_t scenario_count) {
        auto &mctx = M.getContext();
        auto b = IRBuilder(mctx);

        auto it = scenario_count_to_type.find(scenario_count);

        if (it != scenario_count_to_type.end()) {
            return it->second;
        }

        auto this_func_relation_type = StructType::create(mctx, {
                PointerType::get(b.getInt8Ty(), 0),  // func_name (char*)
                ArrayType::get(b.getInt8Ty(), 16),  // modify_type
                b.getInt32Ty(),  // nargs
                b.getInt32Ty(),  // nrelations
                ArrayType::get(taint_pair_type, scenario_count)  // taints[scenario_count]
            }, "__phx_func_relation_" + std::to_string(scenario_count) + "_t");
        scenario_count_to_type[scenario_count] = this_func_relation_type;

        return this_func_relation_type;
    }

    /* Backup function for possible future use. */
#if 0
    // Pad taint_elements to the required size if needed
    void padTaintElements(std::vector<Constant*> &taint_elements, size_t scenario_count) {
        auto &mctx = M.getContext();
        auto b = IRBuilder(mctx);
        std::vector<Constant*> zero_taint = { b.getInt8(0), b.getInt8(0), b.getInt32(0) };
        while (taint_elements.size() < scenario_count) {
            taint_elements.push_back(ConstantStruct::get(taint_pair_type, zero_taint));
        }
    }
#endif

    /* Create or modify a scalar global constant. */
    GlobalVariable *createOrModifyGlobalScalar(const char *name, Type *type, Constant *value) {
        auto gnew = M.getOrInsertGlobal(name, type);
        if (auto *g = dyn_cast<GlobalVariable>(gnew)) {
            g->setInitializer(value);
            g->setConstant(true);
            return g;
        } else {
            die() << "Global variable type mismatch: " << gnew->getType() << " != " << type << '\n';
        }
    }

    /* Create or modify a global array.
     *
     * Note that array type has a fixed length that needs to be updated.
     *
     * Because replaceInitializer is not supported in LLVM 15, we need to
     * create a new global variable and replace the old one's `Use`s.
     *
     * Note that replacing global variable's `Use`s will not change the access
     * type (e.g. the type on GEP), but this is fine for array.
     */
    GlobalVariable *createOrModifyGlobalArray(const char *name, Type *type, Constant *value) {
#if 0
        GlobalVariable *global = M.getGlobalVariable(name);
        if (global != nullptr) {
            // This is not available in LLVM 15.
            global->replaceInitializer(value);
        } else {
            return new GlobalVariable(M, type, true,
                GlobalValue::ExternalLinkage, value, name);
        }
#else
        GlobalVariable *old_global = M.getGlobalVariable(name);
        // Create the global variable for replacement
        GlobalVariable *new_global = new GlobalVariable(
            M, type, true, GlobalValue::ExternalLinkage, value, name);
        // Future: instead of linking, we could inject the runtime only if
        // compiled with the compiler.
        if (old_global != nullptr) {
            old_global->replaceAllUsesWith(new_global);
            old_global->eraseFromParent();
        }

        return new_global;
#endif
    }

    void generateFunctionRelationsTable() {
        initTaintTableTypes();

        auto &mctx = M.getContext();
        auto b = IRBuilder(mctx);

        /* Create individual constant structs for each function relation */
        std::vector<Constant*> func_relation_ptrs;
        PointerType *func_relation_ptr_type = PointerType::get(func_relation_type, 0);

        for (const auto &func_relation : function_relations_table) {

            /* Create relation array data first */
            std::vector<Constant*> taint_elements;
            for (const auto &relation : func_relation.relations) {
                taint_elements.push_back(ConstantStruct::get(taint_pair_type, {
                    b.getInt8(relation.caller_arg),
                    // FIXME: allocate callsite number for each function
                    b.getInt8(relation.callsite),
                    b.getInt32(relation.argtaint),
                }));
            }

            /* Create function relation struct constant */
            const size_t scenario_count = func_relation.relations.size();
            assert_eq(taint_elements.size(), scenario_count);

            StructType *this_func_relation_type = getOrCreateFuncRelationType(scenario_count);

            assert_eq(func_relation.modify_type.size(), func_relation.f->arg_size() + 1);
            std::vector<uint8_t> modify_type_copy = func_relation.modify_type;
            while (modify_type_copy.size() < 16)
                modify_type_copy.push_back(0);

            // Create function name string constant
            std::string func_name = func_relation.f->getName().str();
            Constant *func_name_constant = ConstantDataArray::getString(M.getContext(), func_name, true);
            GlobalVariable *func_name_global = new GlobalVariable(
                M, func_name_constant->getType(), true, GlobalValue::PrivateLinkage,
                func_name_constant, "__phx_func_name_" + func_relation.f->getName()
            );

            Constant *func_relation_struct = ConstantStruct::get(this_func_relation_type, {
                ConstantExpr::getBitCast(func_name_global, PointerType::get(b.getInt8Ty(), 0)),
                ConstantDataArray::get(M.getContext(), modify_type_copy),
                b.getInt32(func_relation.f->arg_size()),
                b.getInt32(taint_elements.size()),
                ConstantArray::get(ArrayType::get(taint_pair_type, scenario_count), taint_elements),
            });

            /* Create global variable for this function relation */
            GlobalVariable *func_relation_global = new GlobalVariable(
                M, this_func_relation_type, true, GlobalValue::PrivateLinkage,
                func_relation_struct, "__phx_func_relation_" + func_relation.f->getName()
            );

            // Add pointer to this struct to our array
            func_relation_ptrs.push_back(ConstantExpr::getBitCast(func_relation_global, func_relation_ptr_type));
        }

        injectorTestInitialRunMode();

        const size_t total_funcs = function_relations_table.size();

        // Note that if ever using bool in the code, regular storage is using
        // i8, while non-storage (e.g. args, retval) is using i1.

        // Create the array of pointers to function relations
        ArrayType *func_relations_array_type = ArrayType::get(func_relation_ptr_type, total_funcs);
        Constant *func_relations_array = ConstantArray::get(func_relations_array_type, func_relation_ptrs);

        createOrModifyGlobalArray("__phx_func_relations", func_relations_array_type, func_relations_array);

        assert(total_funcs <= UINT32_MAX);
        createOrModifyGlobalScalar("__phx_nfunc", b.getInt32Ty(), b.getInt32(total_funcs));

#define PHX_AUTO_UNSAFE_ABI 104
        createOrModifyGlobalScalar("__phx_auto_unsafe_abi", b.getInt32Ty(), b.getInt32(PHX_AUTO_UNSAFE_ABI));

        // Create array of root function info structs

        std::unordered_map<Function *, uint32_t> func_id_map;
        uint32_t func_id = 0;
        for (auto &func_relation : function_relations_table) {
            func_id_map[func_relation.f] = func_id++;
        }

        std::vector<__phx_root_info> root_info_elements_vec;

        for (const auto &[func, arg] : scope_root_funcs) {
            if (func_id_map.find(func) == func_id_map.end()) {
                lerrs() << "Scope root function " << func->getName()
                    << " is not in relation table, skipping root table\n";
                continue;
            }
            root_info_elements_vec.push_back({
                func_id_map.at(func),
                (uint32_t)arg.at(0)
            });
        }
        if (phx_preset == "redis") {
            for (const auto &funcname : redis_72_root) {
                Function *func = M.getFunction(funcname);
                if (func == nullptr) {
                    lerrs() << "Scope root " << funcname << " not found\n";
                    continue;
                }
                if (func_id_map.find(func) == func_id_map.end()) {
                    lerrs() << "Scope root function " << func->getName()
                        << " is not in relation table, skipping root table\n";
                    continue;
                }
                root_info_elements_vec.push_back({ func_id_map.at(func), 1 });
            }
        }

        std::sort(root_info_elements_vec.begin(), root_info_elements_vec.end(),
            [](const __phx_root_info &a, const __phx_root_info &b) {
                return a.func_id < b.func_id;
            });

        std::vector<Constant*> root_info_elements;
        StructType *root_info_type = StructType::get(b.getInt32Ty(), b.getInt32Ty());

        for (const auto &root_info : root_info_elements_vec) {
            root_info_elements.push_back(ConstantStruct::get(root_info_type, {
                b.getInt32(root_info.func_id),
                b.getInt32(root_info.initial_arg)
            }));
        }

        const size_t num_roots = root_info_elements.size();
        ArrayType *root_info_array_type = ArrayType::get(root_info_type, num_roots);
        Constant *root_info_array = ConstantArray::get(root_info_array_type, root_info_elements);

        createOrModifyGlobalScalar("__phx_nroots", b.getInt32Ty(), b.getInt32(num_roots));
        createOrModifyGlobalArray("__phx_func_roots", root_info_array_type, root_info_array);
    }

    void injectorTestInitialRunMode() {
        auto global_inject_run_mode = M.getGlobalVariable("__phx_inject_run_mode");
        assert_eq(global_inject_run_mode != nullptr, true);
        if (debug_set_initial_mode != 0) {
            // do not create initializer if its 0
            lerrs() << "Debug set initial mode to " << debug_set_initial_mode << '\n';
            global_inject_run_mode->setInitializer(
                ConstantInt::get(global_inject_run_mode->getValueType(), debug_set_initial_mode));
        }
    }


    // analyze
    void analyzeOneFunction(Function *f, std::shared_mutex *summary_lock, bool debug = false, bool debugSummary = false) {
        if (debug || debugSummary)
            lerrs() << "Found function " << f->getName() << "\n\n";

        auto fr = analysis::FunctionAnalyzer(*f, function_summaries,
                cloned_function_map, summary_lock, phx_preset);
        fr.isDebug = debug;
        fr.isDebugSummary = debugSummary;
        auto fa = fr.analyze();

        if (debug || debugSummary)
            lerrs() << '\n';

        std::unique_lock<std::shared_mutex> guard;
        if (summary_lock)
            guard = std::unique_lock<std::shared_mutex>(*summary_lock);
        function_summaries.insert({f, std::move(fa)});
    }

    // instrument
    bool instrumentOneFunction(Function *f, func_id_t func_id, FunctionRelation *func_relation) {
        const auto &fa = function_summaries.at(f);

        auto instru = instrument::FunctionInstrumenter(M, *f, func_id,
            f->arg_size() + 1, phx_preset); // +1 for empty arg taint (i.e. track global variable)
        instru.debugInstrumentPoint  = false;
        instru.debugSplitPoint       = false;
        instru.debugSplittedFunction = false;

        size_t modified_cnt = 0;
        size_t argmask = 0;

        std::vector<__phx_taint_pair> *relations = func_relation ? &func_relation->relations : nullptr;

        // Note: argmask 0 means no argument tracked, but global variable tracked.
        // fa.argument_effects already includes the effect for global variable,
        // therefore, argmask is [0, arg_size].
        for (const auto &effect : fa.argument_effects) {
            modified_cnt += instru.instrumentArgumentEffect(effect, argmask++, relations);
        }

        updateDebugCounters(modified_cnt);
        if (instru.anyDebug())
            lerrs() << "********************************\n";

        return bool(modified_cnt);
    }

    /* === Dead parallel code === */

    /* The following functions are for parallel analysis and instrumentation-only
     * parts.  The parallel code seems doesn't work well with LLVM, and the
     * below code does not implement injection.
     *
     * If parallel analysis can be fixed it would be greatly appreciated (at
     * least it is really useful for compiler developement itself and developer
     * compile release speed), but running injection experiment would probably
     * be fine since we will run parallel injection programs generation. */
#if 1
    void analyzeAndInstrumentParallel() {
        die() << "Parallel analysis unimplemented\n";
    }
#else
    void analyzeAndInstrument() {
        for (auto &[f, order] : sorted_func) {
            analyzeAndInstrumentFunction(f, nullptr);
        }
    }

    void analyzeAndInstrumentParallel() {
        ThreadPool pool;
        std::shared_mutex summary_lock;

        size_t qfront = 0, cur_order = 0;
        while (qfront != sorted_func.size()) {
            do {
                Function *f = sorted_func[qfront].first;
                size_t order = sorted_func[qfront].second;
                if (order > cur_order)
                    break;
                ++qfront;

                pool.enqueue([f, &summary_lock, this] {
                    analyzeAndInstrumentFunction(f, &summary_lock);
                });
            } while (qfront != sorted_func.size());

            pool.waitBatch();
            ++cur_order;
        }
    }

    bool analyzeAndInstrumentFunction(Function *f, std::shared_mutex *summary_lock) {
        lerrs() << "Found function " << f->getName() << "\n\n";

        // analyze
        auto fr = analysis::FunctionAnalyzer(*f, function_summaries,
                cloned_function_map, summary_lock);
        fr.isDebug = false;
        fr.isDebugSummary = true;
        auto fa = fr.analyze();

        lerrs() << '\n';

        // instrument
        auto instru = instrument::FunctionInstrumenter(M, *f, func_id,
            f->arg_size() + 1); // +1 for empty arg taint (i.e. track global variable)
        instru.debugInstrumentPoint  = false;
        instru.debugSplitPoint       = false;
        instru.debugSplittedFunction = false;
        size_t modified_cnt = 0;
        size_t argmask = 0;
        for (auto &effect : fa.argument_effects)
            modified_cnt += instru.instrumentArgumentEffect(effect, argmask++);

        modified_function += bool(modified_cnt);
        modified_scenario += modified_cnt;
        single_arg_func_count += (modified_cnt == 1);
        two_arg_func_count += (modified_cnt == 2);
        three_arg_func_count += (modified_cnt == 3);
        max_arg = std::max((size_t)max_arg, modified_cnt);
        lerrs() << "********************************\n";

        if (summary_lock)
            std::unique_lock<std::shared_mutex> guard(*summary_lock);
        function_summaries.insert({f, std::move(fa)});

        return bool(modified_cnt);
    }
#endif
};

bool ModuleAnalysis::run() {
    return RealModuleAnalysis(*this).run();
}

} // namespace analysis

} // namespace phoenix
