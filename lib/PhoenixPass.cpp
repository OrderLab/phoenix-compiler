#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"

#include "ModuleAnalysis.h"

using namespace llvm;

cl::opt<bool> Parallel("phoenix-parallel",
    cl::desc("Enable parallelization to speedup instrumentation"));

namespace phoenix {

struct PhoenixPass : public llvm::ModulePass {
    static char ID;

    PhoenixPass() : llvm::ModulePass(ID) {}

    bool runOnModule(Module &M) override {
        return analysis::ModuleAnalysis(M, Parallel).run();
    }
};

} // namespace phoenix

char phoenix::PhoenixPass::ID = 1;
RegisterPass<phoenix::PhoenixPass> X(
        "phoenix-analysis", "Analysis to automatically instrument unsafe region for phoenix",
        true, true);
