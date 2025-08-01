#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"

#include "ModuleAnalysis.h"
#include "Utils.h"

using namespace llvm;

cl::opt<bool> Parallel("phoenix-parallel", cl::init(false),
    cl::desc("Enable parallelization to speedup instrumentation"));

cl::opt<std::string> ScopeRoot("scope-root",
    cl::desc("The scope (function name) to detect single unsafe region within"));

cl::opt<std::string> ArgTypeRule("arg-type-rule",
    cl::desc("The argument field that should be used for taint analysis"));

cl::opt<std::string> AnnotateFunc("annotate-func",
    cl::desc("Pre-annotated function summaries"));

cl::opt<std::string> IndirectCallInfo("indirect-call-info",
    cl::desc("Indirect call information"));

cl::list<std::string> InjectParallelNames("phx-inject-parallel-names",
    cl::CommaSeparated,
    cl::desc("Create multiple random injections in one run (using fork after instrumentation). "
        "The output bc filename should be in the form of `file.<name>.bc'. "
        "Stderr will be reopened at `./inject.<name>.log'. "
        "The number of parallelism is (for now) the number of CPU cores. "
    ));

cl::opt<bool> PhxDebug("phx-debug",
    cl::desc("Print Phoenix analysis, instrumenter, and injector debug information"));

cl::list<std::string> InjectOffsets("phx-inject-offsets",
    cl::CommaSeparated,
    cl::desc("The offsets of the instructions to inject, overrides random selection."));

cl::opt<std::string> PHXPreset("phx-preset",
    cl::desc("Use the preset generated from gcov, etc."));

cl::opt<int> InjectCount("inject-count", cl::init(10),
    cl::desc("The number of instructions to inject"));

cl::opt<int> DebugSetInitialMode("debug-set-initial-mode", cl::init(0),
    cl::desc("Debug set the initial mode of the injector"));

namespace phoenix {

struct PhoenixPass : public llvm::ModulePass {
    static char ID;

    PhoenixPass() : llvm::ModulePass(ID) {}

    bool runOnModule(Module &M) override {
        dumpRedisCommandTable(M);

        if (DebugSetInitialMode < 0 || DebugSetInitialMode > 3) {
            die() << "Invalid debug-set-initial-mode: " << DebugSetInitialMode << '\n';
        }

        // Start the real analysis
        return analysis::ModuleAnalysis{
                M,
                Parallel,
                ScopeRoot,
                AnnotateFunc,
                IndirectCallInfo,
                InjectOffsets,
                InjectParallelNames,
                PHXPreset,
                InjectCount,
                DebugSetInitialMode
            }.run();
    }

    // Redis root functions. Not used anymore.
    void dumpRedisCommandTable(Module &M) {
        return;

        GlobalVariable *table = M.getGlobalVariable("redisCommandTable");
        if (!table) {
            errs() << "No redisCommandTable found\n";
        } else {
            // Value::ValueTy::ConstantAggregateLastVal;
            Constant *c = table->getInitializer();
            errs() << "Value ID is " << c->getValueID() << '\n';
            if (auto array = dyn_cast<ConstantArray>(c)) {
                auto type = dyn_cast<ArrayType>(c->getType());
                for (unsigned i = 0; i < type->getNumElements(); ++i) {
                    auto elem = array->getAggregateElement(i);
                    if (elem)
                        errs () << "elem[" << i << "] = " << *elem << '\n';
                }
            }
            errs() << "isa seq " << isa<ConstantArray>(c) << '\n';
            // return false;
        }
    }
};

} // namespace phoenix

char phoenix::PhoenixPass::ID = 1;
RegisterPass<phoenix::PhoenixPass> X(
        "phoenix-analysis", "Analysis to automatically instrument unsafe region for phoenix",
        true, true);
