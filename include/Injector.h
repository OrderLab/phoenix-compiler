#ifndef __PHX_INJECTOR_H__
#define __PHX_INJECTOR_H__

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <unordered_set>
#include <vector>

#include "Utils.h"
#include "ModuleAnalysis.h"

namespace phoenix {

namespace injector {

/* versions to be generated
 *
 * first instrument:  IO, IF
 * then fault-inject: OF, IF
 */
enum InjectVersion {
    OO = 0, // original non-injected
    OF = 1, // original fault-injected
    IO = 2, // instrumented non-injected
    IF = 3, // instrumented fault-injected
};

} // namespace injector

namespace analysis {
using ClonedFunctionMap = std::unordered_map<llvm::Function *, std::unordered_map<injector::InjectVersion, llvm::Function *>>;
} // namespace analysis

namespace injector {

struct Injector {
    /* All data should have been made private. Make public for now. */
public:
    llvm::Module &M;
    const std::string &inject_preset;
    const std::vector<std::string> &inject_parallel_names;
    std::string inject_parallel_output_file_prefix;

    Injector(llvm::Module &M, const std::string &inject_preset,
            const std::vector<std::string> &inject_parallel_names)
        : M(M), inject_preset(inject_preset), inject_parallel_names(inject_parallel_names)
    {
        // check whether output file name format is expected

        if (!inject_parallel_names.empty()) {
            checkAndSetOutputFileName();
        }

        // parse args
        // if (inject_args == "")
        //     return;

    }

    /* ======================= Shared knowledge ========================= */

    /* Prefix sum of injectable functions.
     * The injector state will be a quite strange thing.  Since this injector
     * has strong coupling with the main pass, it stores some of the temporary
     * variables that will correspond to the main pass's variables. */
    std::vector<std::pair<llvm::Function *, size_t>> func_injectable_count_prefix_sum;
    size_t total_injectable_count = 0;
    // std::vector<size_t> func_injectable_count;

    /* ======================= Injection target ========================= */

    struct InjectTarget {
        /* For debug only now: selection result: global prefix sum indices */
        std::unordered_set<size_t> inject_insts_idx;

        /* Processed inject_insts_idx <func, subindex>. */
        struct InjectInstInfo {
            size_t global_idx;  // for debug only
            llvm::Function *func;
            size_t to_count;
        };
        std::vector<InjectInstInfo> inject_insts_idx_orig_func;

        /* Collected instructions after caller has cloned the functions. */
        std::vector<std::vector<llvm::Instruction *>> inject_targets;
    };

    InjectTarget target;

private:
    /* Fork multiplex internal */
    size_t child_count = 0;

    /* ================ Public steps called by main pass ================ */
public:
    void preprocessPrefixSum(const analysis::TopologyFuncList &sorted_func);

    void select_injectable_instructions(
        const analysis::TopologyFuncList &sorted_func, size_t select_count,
        const std::vector<std::string> &inject_offsets_override);

    /* Output to the target::inject_targets.
     *
     * This requires caller coordinate with the instrumenter to hold back
     * injection. */
    void collect_injectable_instructions(
        const analysis::ClonedFunctionMap &cloned_function_map);

    void inject_all(void);

    /* Supports multi-run injection on the same instrumentation. */
    void fork_multiplexer_magic(void);
    void fork_multiplexer_tail(void);

    /* ======================== Helper functions ======================== */
private:
    InjectTarget select_injectable_instructions_one(size_t select_count) const;

public:
    /* Whether it's a injectable function based on our injection policies */
    bool isInjectableFunction(const llvm::Function &f) const;
    /* Whether it's the selected function to inject faults */
    bool isToInject(const llvm::Function &f) const;

    /* Injectable **instruction** based on our injection policies
     *
     * Future: Use `gcov` guided coverage to tell which instructions were used.
     * Right now only using function granularity policy in
     * isInjectableFunction should be fine.  This function is only used to
     * determine the types of instruction we support to inject faults:
     *   - Random change to 0/1/true/false to integer-compare operands/results
     *   - Random change to 0/1 to store operands
     *   - Random change to 0/1/NULL to binary operands
     *
     * TODO: Add more types of instructions to support.
     */
    static bool isInjectableInstruction(llvm::Instruction &inst) {
        using llvm::isa;
        return isa<llvm::ICmpInst>(inst) ||
            isa<llvm::StoreInst>(inst) ||
            isa<llvm::BinaryOperator>(inst);
        // isa<CallBase>(inst) && !isa<IntrinsicInst>(inst)
    }

private:
    void checkAndSetOutputFileName(void);

    /* Inject one instruction
     *
     * We currently support the following faults:
     * TBA */
    static void injectOneInstruction(llvm::Instruction *inst);

    /* =============================== */

    /* API that does three things combined:
     * 1. randomly select instruction to inject faults on original code
     * 2. duplicate function x2 or x4 times, and replace original func with proxy
     * 3. map the selected (to be faulty) instructions in the new function, and
     *    collect the corresponding instructions to be injected
     */
    void select_gen_map_combined();

    llvm::Function *get_map(llvm::Function *f, InjectVersion ver);

    void inject();
};

} // namespace analysis

} // namespace phoenix

#endif
