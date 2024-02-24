#ifndef __UTILS_H__
#define __UTILS_H__

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"

#include <string>
#include <type_traits>
#include <memory>
#include <mutex>
#include <optional>
#include <iostream>

namespace phoenix {

std::string demangleName(std::string mangledName);

// Helper function to find a function given the name. Internally demangles the
// name
llvm::Function *getFunctionByName(std::string name, llvm::Module &M);

/* A helper function that locks anything by pointer. */
std::unique_lock<std::mutex> anyLock(const void *t);

/* LLVM ostream contains buffer, but is not locked by default.
 * Wrap the output with a lock guard held.
 * This would make the sequence of "errs() << sth1 << sth2 << sth3;" atomic.
 */
struct locked_ostream {
    // same as: std::invoke_result_t<decltype(&llvm::raw_fd_ostream::lock),
    //                               llvm::raw_fd_ostream>
    using GuardType = decltype(std::declval<llvm::raw_fd_ostream>().lock());
    // ostream lock seems does not work

    std::reference_wrapper<llvm::raw_ostream> os;
    // std::optional<GuardType> guard;
    std::optional<std::unique_lock<std::mutex>> guard2;

    locked_ostream(llvm::raw_ostream &os) : os(os) {}
    locked_ostream(llvm::raw_fd_ostream &os) : os(os), guard2(anyLock(&os)) {}

    template<typename T>
    locked_ostream &operator<<(T &&t) { os.get() << std::forward<T>(t); return *this; }
};

static inline locked_ostream lerrs() {
    return locked_ostream(llvm::errs());
}

}

#endif /* __UTILS_H__ */
