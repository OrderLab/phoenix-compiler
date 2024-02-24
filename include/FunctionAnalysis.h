#ifndef __PHOENIXANALYSIS_H__
#define __PHOENIXANALYSIS_H__

#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>

#include <unordered_set>
#include <vector>
#include <shared_mutex>

#include "Utils.h"

namespace phoenix {

namespace analysis {

enum class ModifyType { NO_MODIFY, MAY_MODIFY, MAY_MODIFY_SAFE, };
// MAY_MODIFY_SAFE need manual annotation. It means after the function
// returns, the mini-transaction finishes (for example, rehash hashtable
// does not change data).
enum class ReturnTaint { PURE, POINTER };

struct ArgumentEffect {
    ModifyType modify_type;
    ReturnTaint return_taint;
    std::unordered_set<const llvm::Instruction *> taints;
};

struct FunctionSummary {
    // index is which argument, consider single argument for now
    std::vector<ArgumentEffect> argument_effects;
};

using FunctionSummaryMap = std::unordered_map<const llvm::Function *, FunctionSummary>;

class FunctionAnalyzer {
    // fields
    const llvm::Function &f;
    const FunctionSummaryMap &summaries;
    std::shared_mutex *summary_lock;

public:
    bool isDebug = false;
    bool isDebugSummary = false;

    // methods
    FunctionAnalyzer(const llvm::Function &f, const FunctionSummaryMap &summaries,
            std::shared_mutex *summary_lock);

    FunctionSummary analyze();
private:
    locked_ostream dbg() const {
        return isDebug ? lerrs() : locked_ostream(llvm::nulls());
    }
    locked_ostream dbg_summary() const {
        return isDebugSummary ? lerrs() : locked_ostream(llvm::nulls());
    }
    ArgumentEffect analyzeSingleArgument(const llvm::Argument &arg) const;
};

} // namespace analysis

} // namespace phoenix

#endif /* __PHOENIXANALYSIS_H__ */
