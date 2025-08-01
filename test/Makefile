.PHONY: optlib clean leaf_files runtime

LEAFROOT=flow:1,caller:1,passvalue:1,nested:1,caller_loop:1,modify_rebind_struct:1,modify_rebind_var:1

PHXARG=-scope-root=$(LEAFROOT) -annotate-func= -inject-count=3 -debug-set-initial-mode=1
PHXARG=-scope-root=$(LEAFROOT) -annotate-func= -inject-count=3 -debug-set-initial-mode=3
# PHXARG=-scope-root=$(LEAFROOT) -annotate-func= -inject-count=3

all: optlib runtime leaf_files # instru-translate.bc

LLVMSUFFIX=-15
ifeq ($(OS), Darwin)
	LLVMSUFFIX=-mp-15
	DYSUFFIX=dylib
	OPT=/opt/local/libexec/llvm-15/bin/opt
else
	DYSUFFIX=so
	OPT=opt$(LLVMSUFFIX)
endif

CC=clang$(LLVMSUFFIX)
DIS=llvm-dis$(LLVMSUFFIX)

INLINE_RUNTIME=0
RUNTIME_LIB=
ifeq ($(INLINE_RUNTIME), 0)
	RUNTIME_LIB = phxruntime.o
endif

SYSROOT=$(HOME)/sysroot
LDARGS=-L $(SYSROOT)/lib -I $(SYSROOT)/include -Wl,--rpath=$(SYSROOT)/lib -Wl,--dynamic-linker=$(SYSROOT)/lib/ld-linux-x86-64.so.2 -lphx

PHXLIB=../build/lib/PhoenixAnalysisPass.$(DYSUFFIX)

phxruntime.o: phxruntime.c ../include/phx_instrument_compiler_abi.h ../include/phx_instrument.h
	$(CC) -g -O3 -c $< -o $@

runtime: phxruntime.o

optlib:
	make -C ../build/ -j

leaf_files: \
	leaf.ll leaf \
	leaf-instrumented.ll leaf-instrumented \
	# leaf-opt-instrumented leaf-opt-instrumented.ll \

%.bc: %.c
	$(CC) -DINLINE_RUNTIME=$(INLINE_RUNTIME) -g3 -c -emit-llvm $^ -o $@

%-opt.bc: %.c
	$(CC) -DINLINE_RUNTIME=$(INLINE_RUNTIME)     -c -emit-llvm $^ -o $@ -O3

%-instrumented.bc: %.bc
	$(OPT) -enable-new-pm=0 -load=$(PHXLIB) -phoenix-analysis $(PHXARG) $^ -o $@

%.ll: %.bc
	$(DIS)  $^

%: %.bc $(RUNTIME_LIB)
	$(CC) $(LDARGS) -g $^ -o $@
	# $(CC) -O3 -g $^ -o $@

.%.dot: leaf-instrumented.ll
	$(OPT) -enable-new-pm=0 -disable-output -dot-cfg -cfg-func-name=$* $^

%-cfg.pdf: .%.dot
	dot -Tpdf $^ -o $@ && ( open $@; true )

# instru-translate.bc: instru-translate.c
#       $(CC) -g3 -c -emit-llvm $^ -o $@
#       $(CC) -c -emit-llvm $^ -o instru-translate-opt.bc -O3
#       llvm-dis-mp-15 $@
#       llvm-dis-mp-15 instru-translate-opt.bc

clean:
	rm -rf *.o *.bc *.ll *-instrumented *.dSYM leaf

# loop
# return value
# library function call
# inter function
