#!/bin/bash

build="build/"
libs="/usr/local/lib/"
filename=""
cfile=""
outputFile="/tmp/output.data"
patcher="src/patcher.py"

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

clang-3.9 -c -O1 -emit-llvm ${c} -o "${build}${cfile}.bc"
exitIfFail $?

opt-3.9 -load "${libs}libInputDependency.so" \
        -load "${build}libOHProtectorPass.so" \
        -OHProtect -ff $filename -o "${build}${cfile}-inst.bc" "${build}${cfile}.bc"
exitIfFail $?

llc-3.9 -O0 -filetype=obj "${build}${cfile}-inst.bc"
exitIfFail $?

clang-3.9 -O0 "${build}${cfile}-inst.o" -o "${build}${cfile}-rewritten"
exitIfFail $?

./"${build}${cfile}-rewritten" |& tee $outputFile
exitIfFail $?

python3 $patcher "${build}${cfile}-rewritten" $outputFile
exitIfFail $?
