#ifndef __UTILS_H__
#define __UTILS_H__

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/FileSystem.h>

#include <string>
#include <type_traits>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <optional>
#include <iostream>
#include <random>

extern llvm::cl::opt<bool> PhxDebug;

namespace phoenix {

std::string demangleName(std::string &&mangledName);

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

    bool silenced = false;

    std::reference_wrapper<llvm::raw_ostream> os;
    std::optional<std::unique_lock<std::mutex>> guard;

    locked_ostream(bool silenced, llvm::raw_ostream &os, std::optional<std::unique_lock<std::mutex>> &&guard)
        : silenced(silenced), os(os), guard(std::move(guard)) {}

    locked_ostream(llvm::raw_fd_ostream &os) : locked_ostream(false, os, anyLock(&os)) {}

    locked_ostream(locked_ostream &&other)
        : silenced(other.silenced), os(other.os), guard(std::move(other.guard)) {}

    template<typename T>
    locked_ostream &operator<<(T &&t) {
        // latch (do not evaluate at all) is faster than llvm::nulls()
        if (!silenced)
            os.get() << std::forward<T>(t);
        return *this;
    }
};

static inline locked_ostream lnulls() {
    return locked_ostream { true, llvm::nulls(), std::nullopt };
}

static inline locked_ostream lerrs() {
    // return lnulls();
    // return locked_ostream(llvm::errs());
    return locked_ostream(!PhxDebug, llvm::errs(), std::nullopt);
}

std::unordered_set<size_t> generate_random_set(size_t count, size_t min_value, size_t max_value);

struct die_stream : locked_ostream {
    die_stream(llvm::raw_fd_ostream &os) : locked_ostream(os) {}

    [[noreturn]] ~die_stream() { exit(1); }
};

static inline die_stream die() {
    return die_stream(llvm::errs());
}

/* This should have been put in some other header file. */
static inline bool isInstrumentableFunction(const llvm::Function &f) {
    if (f.isDeclaration())
        return false;
    if (f.getName().contains_insensitive("phx"))
        return false;
    if (f.getName().contains_insensitive("main"))
        return false;
    return true;
}

#define STRINGIFY(x) STRINGIFY2(x)
#define STRINGIFY2(x) #x
#define assert_eq(x, y) do { \
        auto __xx = (x); \
        auto __yy = (y); \
        if (__xx != __yy) \
            die() << ("Assert failure" __FILE__ ":" STRINGIFY(__LINE__) " in ") << __func__ << (":\n" \
                "\t("#x") != ("#y")\n" \
                "\t") << __xx << " != " << __yy << '\n'; \
    } while (0)
#define assert_eq_custom(x, y, xdbg, ydbg) do { \
        if ((x) != (y)) \
            die() << ("Assert failure" __FILE__ ":" STRINGIFY(__LINE__) " in ") << __func__ << (":\n" \
                "\t("#x") != ("#y")\n" \
                "\t") << (xdbg) << " != " << (ydbg) << '\n'; \
    } while (0)
#define assert_eq_deref(x, y) do { \
        auto __xx = (x); \
        auto __yy = (y); \
        if (__xx != __yy) { \
            auto le = die(); \
            le << ("Assert failure" __FILE__ ":" STRINGIFY(__LINE__) " in ") << __func__ << (":\n" \
                "\t("#x") != ("#y")\n\t"); \
            __xx ? le << *__xx : le << "(null)"; \
            le << " != "; \
            __yy ? le << *__yy : le << "(null)"; \
            le << '\n'; \
        } \
    } while (0)

} // namespace phoenix

#endif /* __UTILS_H__ */
