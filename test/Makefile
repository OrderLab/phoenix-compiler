.PHONY: clean

all: leaf.bc instru-translate.bc

leaf.bc: leaf.c
	clang-mp-15 -g3 -c -emit-llvm $^ -o $@
	clang-mp-15 -c -emit-llvm $^ -o leaf-opt.bc -O3
	llvm-dis-mp-15 $@
	llvm-dis-mp-15 leaf-opt.bc

instru-translate.bc: instru-translate.c
	clang-mp-15 -g3 -c -emit-llvm $^ -o $@
	clang-mp-15 -c -emit-llvm $^ -o instru-translate-opt.bc -O3
	llvm-dis-mp-15 $@
	llvm-dis-mp-15 instru-translate-opt.bc

clean:
	rm *.bc *.ll

# loop
# return value
# library function call
# inter function
