#ifndef __PHOENIXANALYSIS_H__
#define __PHOENIXANALYSIS_H__

#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>

#include <unordered_set>
#include <unordered_map>
#include <queue>
#include <vector>
#include <shared_mutex>

#include "phx_instrument_compiler_abi.h"
#include "Utils.h"
#include "Injector.h"

namespace phoenix {

namespace analysis {

/* Whether the return value is tainted. */
enum class ReturnTaint {
    /* This function doesn't contain the tracked state.
     *
     * FIXME: do we need a ARGUMENT type?
     * For example,
     * int *f(int *x) {
     *   return x;
     * }
     * g() {
     *   int *x = malloc(sizeof(int));
     *   int *y = f(x);
     *   global.z = y;
     *   *y = 10;
     * }
     * We could end up missing that *y is a modification instruction.
     */
    PURE,
    /* The return value contains a pointer to some data in the tracked state,
     * caller should add it to the def-use chain analysis.
     *
     * TODO:
     * 1. not sure if we need two versions of this: 1) return already modified,
     *    2) return not modified yet but should be tracked.
     * 2. not sure if we should return the chain of pointer into the data
     * structure (since the memory in question may be nested deep in the
     * returned pointer), or just make everything behind the pointer tracked. */
    POINTER,
};

/*
 * Effect of whether **this** argument is modified when the called function
 * returns, and whether the return value will be tainted.
 *
 * Also contains function relation to be generated and to be used for Phoenix
 * runtime crash-time safe check.
 */
struct ArgumentEffect {

    /* === For Static Analysis Summary Use === */
    ModifyType modify_type;
    ReturnTaint return_taint;
    /*
     * Bitmap of arg index: which arguments are *also* tainted through this call.
     *
     * Future: we can actually also encode `return_taint` and `modify_type`
     * (except MAY_MODIFY_SAFE) in the bitmap.
     */
    ArgBitmap tainted_args;

    /* === For Static Unsafe Start/End Instrumentation Use === */
    /*
     * The set of instructions that is writing to the argument or tracked
     * global state.
     */
    std::unordered_set<const llvm::Instruction *> writes;

    /* === For Phoenix Runtime Use === */
    /*
     * Take this function as the caller, for each call instruction in the body,
     * which parameters are tainted?
     *
     * Note that this is different from `tainted_args`, which as function
     * summary tells caller who are tainted.
     *
     * This tells the Phoenix runtime at which each site, which callee args are
     * regarded as tainted, so that the stack trace unsafe region checker can
     * know which callee's information to collect.
     *
     * This need to be processed by instrumenter to allocate the callee number.
     * All middle calls (not FCALL or LCALL) can be discarded.
     *
     * Represented as the parameter index bitmap of the callee's argument list.
     * FIXME: Maybe we want an array of tainted variables in the future.
     */
    std::unordered_map<const llvm::Instruction *, ArgBitmap> callee_relation;
};

struct FunctionSummary {
    // index is which argument, consider single argument for now
    std::vector<ArgumentEffect> argument_effects;
};

using FunctionSummaryMap = std::unordered_map<const llvm::Function *, FunctionSummary>;

struct AnalysisInternal;

class FunctionAnalyzer {
    // fields
    const llvm::Function &f;
    const FunctionSummaryMap &summaries;
    const ClonedFunctionMap &cloned_function_map;
    std::shared_mutex *summary_lock;

    const std::string &phx_preset;

public:
    bool isDebug = false;
    bool isDebugSummary = false;

    // methods
    FunctionAnalyzer(const llvm::Function &f, const FunctionSummaryMap &summaries,
            const ClonedFunctionMap &cloned_function_map,
            std::shared_mutex *summary_lock,
            const std::string &phx_preset)
        : f(f), summaries(summaries),
          cloned_function_map(cloned_function_map),
          summary_lock(summary_lock),
          phx_preset(phx_preset) {}

    FunctionSummary analyze();
private:
    locked_ostream dbg() const {
        return isDebug ? lerrs() : lnulls();
    }
    locked_ostream dbg_summary() const {
        return isDebugSummary ? lerrs() : lnulls();
    }

    bool isSelfRecursion(const llvm::Function *callee) const {
        if (callee == &f)
            return true;
        auto it = cloned_function_map.find((llvm::Function *)callee);
        if (it == cloned_function_map.end())
            return false;

        for (auto &[version, func] : it->second) {
            if (func == (llvm::Function *)callee)
                return true;
        }
        return false;
    }

    ArgumentEffect analyzeSingleArgument(const llvm::Argument &arg) const;
    ArgumentEffect analyzeArgInsensitive(const llvm::Argument &arg) const;

    ArgumentEffect analyzeArgSensitive(const llvm::Argument &arg) const;

    bool analyzeArgSensitiveProcessUser(ArgumentEffect &effect,
            const AnalysisInternal &analysis_internal,
            const llvm::Instruction *user) const;

    bool isMayModifyExternalSafe(const llvm::Function &f) const;
};

std::optional<FunctionSummary> tryGetExternalFunctionSummary(
    const llvm::Function &f, const std::string &phx_preset);

bool isKnownExternalFunctions(const llvm::Function &f, const std::string &phx_preset);

} // namespace analysis

} // namespace phoenix

#endif /* __PHOENIXANALYSIS_H__ */
