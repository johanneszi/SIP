#!/bin/bash

clang -c -emit-llvm ./src/InterestingProgram.c -o ./build/InterestingProgram.bc

LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libssl.so \
opt -load ./build/libCallPathAnalysisPass.so -callpath -ff funcsToCheck <./build/InterestingProgram.bc> ./build/InterestingProgram-inst.bc

#opt -O3 <build/InterestingProgram.bc> build/InterestingProgram-inst.bc

llc -filetype=obj ./build/InterestingProgram-inst.bc

g++ -rdynamic build/InterestingProgram-inst.o build/libcheck.o -o ./build/InterestingProgram-rewritten -L/usr/lib/x86_64-linux-gnu/ -lssl -lcrypto

