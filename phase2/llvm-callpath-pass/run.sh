#!/bin/bash

clang -c -emit-llvm ./src/InterestingProgram.c -o ./build/InterestingProgram.bc

opt -load ./build/libCallPathAnalysisPass.so -callpath <./build/InterestingProgram.bc> ./build/InterestingProgram-inst.bc

#opt -O3 <build/InterestingProgram.bc> build/InterestingProgram-inst.bc

llc -filetype=obj ./build/InterestingProgram-inst.bc

g++ -rdynamic build/InterestingProgram-inst.o ./build/libcheck.o ../merkle-tree/src/libMerkleTree.a -o ./build/InterestingProgram-rewritten

