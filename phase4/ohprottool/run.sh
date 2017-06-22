#!/bin/bash

build="build/"
libs="/usr/local/lib/"
filename=""
cfile=""

function usage() {
    echo "usage: run.sh [-f file ]"
    echo "  -f file containing configuration"
}

function exitIfFail() {
    if [ $1 != 0 ]; then
        exit $1
    fi
}

if [ "$1" == "" ] || [ $# != 2 ]; then
    usage
    exit 1
fi

while [ "$1" != "" ]; do
    case $1 in
        -f | --file )           shift
                                filename=$1
                                ;;
        -h | --help )           usage
                                exit
                                ;;
        * )                     usage
                                exit 1
    esac
    shift
done

# Parse json to get c file name
c=$(jq -r '.program' $filename)
exitIfFail $?

# Parce c file
arrC=(${c//// })
cfile=${arrC[${#arrC[@]}-1]}
arrC=(${cfile//./ })
cfile=${arrC[0]}

clang-3.9 -c -O0 -emit-llvm ${c} -o "${build}${cfile}.bc"
exitIfFail $?

opt-3.9 -load "${libs}libInputDependency.so" \
        -load "${build}libOHProtectorPass.so" \
        "${build}${cfile}.bc" -OHProtect -ff $filename -o "${build}${cfile}-inst.bc"
exitIfFail $?

llc-3.9 -filetype=obj "${build}${cfile}-inst.bc"
exitIfFail $?

g++ -rdynamic "${build}${cfile}-inst.o" -o "${build}${cfile}-rewritten"
exitIfFail $?