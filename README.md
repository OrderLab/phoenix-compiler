# Phoenix Compiler

Dataflow analysis and instrumenter for Phoenix safe region

## Dependencies

- LLVM 15
- [WLLVM](https://github.com/travitch/whole-program-llvm)
- TBA

## Build

```bash
mkdir build && cd build
cmake .. -DLLVM_DIR=/path/to/llvm-15/lib/cmake/llvm/
# example: cmake .. -DLLVM_DIR=/opt/local/libexec/llvm-15/lib/cmake/llvm/
make -j`nproc`
```

TBA

## Usage

### Compile Application

Example: Redis

```bash
export LLVM_COMPILER=clang
CC=wllvm make USE_JEMALLOC=no -j
extract-bc src/redis-server   # generates src/redis-server.bc
# for readable LLVM IR: llvm-dis src/redis-server.bc
```

### Instrument

The legacy LLVM PM (Pass Manager) is disabled in LLVM 13 and above by default, but can still be enabled with a [command line toggle](https://releases.llvm.org/13.0.0/docs/WritingAnLLVMPass.html). Switch to new PM in the future.

```bash
opt -enable-new-pm=0 -load=build/lib/PhoenixAnalysisPass.dylib -phoenix-analysis test/leaf.bc -o test/leaf-instrumented.bc
```

TBA
