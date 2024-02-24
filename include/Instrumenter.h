#ifndef __INSTRUMENTER_H__
#define __INSTRUMENTER_H__

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>

#include "FunctionAnalysis.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"

namespace phoenix {

namespace instrument {

class FunctionInstrumenter {
    llvm::Module &M;
    llvm::Function &f;
    size_t max_state_size;
public:
    bool debugInstrumentPoint = false;
    bool debugSplitPoint = false;
    bool debugSafeCut = false;
    bool debugSplittedFunction = false;

    FunctionInstrumenter(llvm::Module &M, llvm::Function &f, size_t max_state_size)
        : M(M), f(f), max_state_size(max_state_size) {}

    // return modified or not
    bool instrumentArgumentEffect(const analysis::ArgumentEffect &effect, size_t statemask);

private:
    llvm::Type *storage_type = nullptr;
    llvm::AllocaInst *storage = nullptr;

private:
    void prepareFunctionHook();
};

} // namespace instrument

} // namespace phoenix

#endif /* __INSTRUMENTER_H__ */
