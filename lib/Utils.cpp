#include "llvm/Demangle/Demangle.h"

#include <mutex>
#include <unordered_map>

#include "Utils.h"

using namespace llvm;

namespace phoenix {

std::string demangleName(std::string mangledName) {
  if (mangledName.size() == 0) return "";

  const char *mangled = mangledName.c_str();
  char *buffer = (char *)malloc(strlen(mangled));
  size_t length = strlen(mangled);
  int status;
  char *demangled = itaniumDemangle(mangled, buffer, &length, &status);

  if (demangled != NULL) {
    std::string str(demangled);
    // Strip out the function arguments
    size_t pos = str.find_first_of("(");
    free(demangled);
    return str.substr(0, pos);
  }
  free(demangled);
  return mangledName;
}


// Helper function to find a function given the name. Internally demangles the
// name
Function *getFunctionByName(std::string name, Module &M) {
  for (Module::iterator I = M.begin(), E = M.end(); I != E; ++I) {
    Function &F = *I;
    std::string demangled = demangleName(F.getName().str());
    // Search for exact match, but truncate parameters including parenthesis.
    size_t pos = demangled.find('(');
    if (pos != std::string::npos)
      demangled.resize(pos);
    if (demangled == name)
      return &F;
  }
  return NULL;
}

std::unique_lock<std::mutex> anyLock(const void *t) {
    static std::mutex self_lock;
    static std::unordered_map<const void *, std::mutex> lockmap;
    std::unique_lock<std::mutex> guard(self_lock);
    return std::unique_lock(lockmap[t]);
}

} // namespace phoenix
