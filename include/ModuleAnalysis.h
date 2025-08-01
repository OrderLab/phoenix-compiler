#ifndef __MODULEANALYSIS_H__
#define __MODULEANALYSIS_H__

#include "llvm/IR/Module.h"

namespace phoenix {

namespace analysis {

using TopologyFuncList = std::vector<std::pair<llvm::Function *, size_t>>;

struct ModuleAnalysis {
    llvm::Module &M;
    /* === Configs === */
    bool parallel = true;
    const std::string &scope_root;
    const std::string &annotate_func;
    const std::string &indirect_call_info;
    const std::vector<std::string> &inject_offsets_override;
    const std::vector<std::string> &inject_parallel_names;
    const std::string &phx_preset;
    int inject_count;
    int debug_set_initial_mode;

    bool run();
};

} // namespace analysis

} // namespace phoenix

#endif /* __MODULEANALYSIS_H__ */
