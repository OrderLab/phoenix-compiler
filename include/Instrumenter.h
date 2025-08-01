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
    func_id_t thisfuncid;
    size_t state_count;

    const std::string &phx_preset;

public:
    bool debugInstrumentPoint = false;
    bool debugSplitPoint = false;
    bool debugSafeCut = false;
    bool debugSplittedFunction = false;

    FunctionInstrumenter(llvm::Module &M, llvm::Function &f, func_id_t thisfuncid,
        size_t state_count, const std::string &phx_preset)
        : M(M), f(f), thisfuncid(thisfuncid), state_count(state_count), phx_preset(phx_preset)
    {
        // Always prepare function hook, even if it is pure function.
        prepareFunctionHook();
    }


    // return modified or not
    bool instrumentArgumentEffect(const analysis::ArgumentEffect &effect, uint8_t argno,
        std::vector<__phx_taint_pair> *relations);

    void dumpDebugInstrumentPoint(std::vector<llvm::Instruction *> insts, std::string_view s) const;

    bool anyDebug() const {
        return debugInstrumentPoint ||
            debugSplitPoint ||
            debugSafeCut ||
            debugSplittedFunction;
    }

private:
    llvm::Type *storage_type = nullptr;
    llvm::AllocaInst *storage = nullptr;
    llvm::Value *unified_states_ptr = nullptr;
    llvm::Value *slot_flcallee_done = nullptr;
    llvm::Instruction *unified_states_initcall = nullptr;

private:
    void prepareFunctionHook();
};

} // namespace instrument

} // namespace phoenix

#endif /* __INSTRUMENTER_H__ */
