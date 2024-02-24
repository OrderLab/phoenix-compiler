#include "llvm/ADT/MapVector.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"

#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <queue>

#include "Utils.h"
#include "FieldChain.h"
#include "Instrumenter.h"
#include "ThreadPool.h"
#include "FunctionAnalysis.h"
#include "ModuleAnalysis.h"

using namespace llvm;

namespace phoenix {

namespace analysis {

std::vector<std::pair<Function *, size_t>> topology_sort(Module &M) {
    // function type
    typedef Function *ft;
    // function state
    struct fs {
        // number of callees, decrementing to 0 means all callee summaries have
        // been calculated. There could be duplicate call pairs (i.e. one
        // function has multiple instructions that call the same function), but
        // since the sum(ncallee) matches sum(callers.size()), the function
        // will still be added to the queue once and only once.
        size_t ncallees;
        bool visited;
        // When all callee summaries has been calculated, calculate the current
        // function, and notify all callers to decrement their ncallees.
        // Duplicate callers will work fine since ncallees also has duplicate counts.
        std::vector<ft> callers;
    };
    std::unordered_map<ft, fs> calls;

    for (auto &caller : M) {
        // touch caller to make sure leaf functions are also added
        calls[&caller];

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
                    lerrs() << "Recursion found! " << caller.getName() << "\n";
                    continue;
                }

                ++calls[&caller].ncallees;
                calls[callee].callers.push_back(&caller);
            }
        }
    }

    // queue, which is also the topology sort result
    std::vector<std::pair<ft, size_t>> q;
    // do not actually pop the queue, since we also need to return the queue
    size_t qfront = 0;

    // add all leaf nodes
    for (auto &[f, fs] : calls) {
        if (fs.ncallees == 0) {
            q.push_back({f, 0});
            fs.visited = true;
        }
    }

    while (qfront != q.size()) {
        auto [f, order] = q[qfront++];
        for (const auto &caller : calls[f].callers) {
            auto &fs = calls[caller];

            if (fs.ncallees == 0) {
                lerrs() << "Internal error: ncallees prematurely decrements to 0! "
                    << caller->getName() << "\n";
                continue;
            } else if (fs.visited) {
                lerrs() << "Internal error: function has been visited in dependency graph! "
                    << caller->getName() << "\n";
                continue;
            }

            if (--fs.ncallees == 0) {
                q.push_back({caller, order + 1});
                fs.visited = true;
            }
        }
    }

    if (q.size() != calls.size()) {
        auto fail_count = calls.size() - q.size();
        lerrs() << "Error: not all functions called are in the dependency graph! "
            "Possible loop found for " << fail_count << " functions \n";
        if (1 || fail_count <= 10) {
            for (auto &[f, ft] : calls) {
                if (!ft.visited) {
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
                    lerrs() << "Unvisited function: " << f->getName() << '\n';
                }
            }
        }
    }

    return q;
}

class RealModuleAnalysis : public ModuleAnalysis {
    // Defined fields in ModuleAnalysis:
    // Module &M;
    // bool parallel = true;

public:
    using ModuleAnalysis::ModuleAnalysis;

private:
    using SortedFunc = std::vector<std::pair<Function *, size_t>>;
    using FunctionSummaryMap = phoenix::analysis::FunctionSummaryMap;

    SortedFunc sorted_func;
    FunctionSummaryMap function_summaries;

    std::atomic<size_t> modified_scenario = 0, modified_function = 0;

public:
    bool run() {
        sorted_func = topology_sort(M);

        lerrs() << "Total functions: " << M.size() << '\n';
        lerrs() << "topology link length: " <<
            (sorted_func.size() ? sorted_func.back().second : 0) << '\n';

        if (parallel)
            analyzeAndInstrumentParallel();
        else
            analyzeAndInstrument();

        lerrs() << "Instrumented " << modified_function << " functions with "
            << modified_scenario << " scenarios\n";
        lerrs() << "Unmodified function " << (sorted_func.size() - modified_function) << '\n';

        return bool(modified_function);
    }

private:
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
        auto fr = analysis::FunctionAnalyzer(*f, function_summaries, summary_lock);
        fr.isDebug = false;
        fr.isDebugSummary = true;
        auto fa = fr.analyze();

        lerrs() << '\n';

        // instrument
        auto instru = instrument::FunctionInstrumenter(M, *f, f->arg_size() + 1);
        instru.debugInstrumentPoint  = false;
        instru.debugSplitPoint       = false;
        instru.debugSplittedFunction = false;
        size_t modified_cnt = 0;
        size_t argmask = 0;
        for (auto &effect : fa.argument_effects)
            modified_cnt += instru.instrumentArgumentEffect(effect, argmask++);

        modified_function += bool(modified_cnt);
        modified_scenario += modified_cnt;
        lerrs() << "********************************\n";

        if (summary_lock)
            std::unique_lock<std::shared_mutex> guard(*summary_lock);
        function_summaries.insert({f, std::move(fa)});

        return bool(modified_cnt);
    }
};

bool ModuleAnalysis::run() {
    return RealModuleAnalysis(M, parallel).run();
}

} // namespace analysis

} // namespace phoenix
