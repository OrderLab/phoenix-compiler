# add_library(PhoenixAnalysisPass SHARED
#     PhoenixAnalysisPass.cpp
# )

add_llvm_library( PhoenixAnalysisPass MODULE
    PhoenixPass.cpp
    ModuleAnalysis.cpp
    FunctionAnalysis.cpp
    Instrumenter.cpp
    FieldChain.cpp
    ThreadPool.cpp
    Utils.cpp

    PLUGIN_TOOL
    opt
)
