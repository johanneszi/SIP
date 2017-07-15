#!/bin/bash

usage () {
	printf "Usage: $0 <llvm bitcode file> <desired path to new binary> <sensitive function list>\n"
	printf "Example: '$0 ../something.bc ./something sensitiveList.txt'\n"
	exit 1
}

if [ $# -ne 3 ]
then
	printf "Wrong number of parameters\n"
	usage
fi

opt-3.9 -load code/libFunctionPass.so -i $3 -functionpass < $1 > something_pass.bc
clang-3.9 -g -c -emit-llvm ../code/NewStackAnalysis.c -o NewStackAnalysis.bc
llvm-link-3.9 NewStackAnalysis.bc something_opt.bc -o something_tmp.bc
llc-3.9 -filetype=obj something_tmp.bc
g++ -g something_tmp.o -o $2 -lssl -lcrypto
