#ifndef __MODULEANALYSIS_H__
#define __MODULEANALYSIS_H__

#include "llvm/IR/Module.h"

namespace phoenix {

namespace analysis {

class ModuleAnalysis {
protected:
    llvm::Module &M;
    bool parallel = true;

public:
    ModuleAnalysis(llvm::Module &M, bool parallel) : M(M), parallel(parallel) {}
    bool run();
};

} // namespace analysis

} // namespace phoenix

#endif /* __MODULEANALYSIS_H__ */
