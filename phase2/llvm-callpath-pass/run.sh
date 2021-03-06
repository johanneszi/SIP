#!/bin/bash

build="build/"
filename=""
c=""
cfile=""
verbose=""

function usage {
    echo "usage: run [-f file ]"
    echo "	-f file containing new line separated functions to protect"
    echo "	-c source file to protect"
}

function exitIfFail {
    if [ $1 != 0 ]; then
    exit $1
fi
}

# Check if enough arguments supplied to program
if (($# < 4)) || (($# > 6)); then
    usage
    exit 1
fi

while [ "$1" != "" ]; do
    case $1 in
        -f | --file )           shift
                                filename=$1
                                ;;
        -c | --cfile )          shift
                                c=$1
                                ;;
        -v | --cfile )          shift
                                verbose="-vv"
                                ;;
        -h | --help )           usage
                                exit
                                ;;
        * )                     usage
                                exit 1
    esac
    shift
done

# Parce c file
arrC=(${c//// })
cfile=${arrC[${#arrC[@]}-1]}
arrC=(${cfile//./ })
cfile=${arrC[0]}

clang-3.9 -O0 -c -g -emit-llvm ${c} -o "$build$cfile.bc"
exitIfFail $?

LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libssl.so \
opt-3.9 -load "${build}libCallPathProtectorPass.so" \
            -callpath -ff $filename ${verbose} -o "${build}${cfile}-inst.bc" "${build}${cfile}.bc"
exitIfFail $?

llc-3.9 -O0 -filetype=obj "${build}${cfile}-inst.bc"
exitIfFail $?

g++ -O0 -g -rdynamic "${build}${cfile}-inst.o" "${build}libcheck.o" "${build}crypto.o" \
                -o "${build}${cfile}-rewritten" \
                -L/usr/lib/x86_64-linux-gnu/ -L/usr/lib/gcc/x86_64-linux-gnu/5 -lssl -lcrypto -lbacktrace
exitIfFail $?
