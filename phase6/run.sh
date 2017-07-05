#!/bin/bash

build="build/"
libs="/usr/local/lib/"
filename=""
cfile=""
outputFile="/tmp/output.data"
patcher="../phase4/ohprottool/src/patcher.py"
funcsToCheckFile="${build}funcsToCheck"
fileVersion=0

function usage() {
    echo "usage: run.sh [-f file ]"
    echo "  -f file containing configuration"
}

function exitIfFail() {
    if [ $1 != 0 ]; then
        exit $1
    fi
}

function printFuncsToCheck() {
    rm $funcsToCheckFile 2> /dev/null
    for func in $(jq -r '.funcsToCheck[]' $filename)
    do
        echo $func >> $funcsToCheckFile
    done
}

function OH() {
    opt-3.9 -load "${libs}libInputDependency.so" \
        -load "../phase4/ohprottool/${build}libOHProtectorPass.so" \
        "${build}${cfile}${fileVersion}.bc" -OHProtect -ff $filename -o "${build}${cfile}${fileVersion+1}.bc"
    exitIfFail $?
}

function CFG() {
    LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libssl.so \
    opt-3.9 -load "../phase2/llvm-callpath-pass/${build}libCallPathProtectorPass.so" \
        "${build}${cfile}${fileVersion}.bc" -callpath -ff ${funcsToCheckFile} -o "${build}${cfile}${fileVersion+1}.bc"
    exitIfFail $?
}

function RC() {
    opt-3.9 -load "../phase3/stins4llvm/${build}libStateProtectorPass.so" \
        "${build}${cfile}${fileVersion}.bc" -stateProtect -ff $filename -o "${build}${cfile}${fileVersion+1}.bc" 
    exitIfFail $?
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


mkdir -p ${build}

# Parse json to get c file name
c=$(jq -r '.program' $filename)
exitIfFail $?

inputmodes=($(jq -r '.modes[]' $filename))

# Parce c file
arrC=(${c//// })
cfile=${arrC[${#arrC[@]}-1]}
arrC=(${cfile//./ })
cfile=${arrC[0]}


clang-3.9 -c -O0 -emit-llvm ${c} -o "${build}${cfile}${fileVersion}.bc"
exitIfFail $?

flags_front=""
flags_back=""
oh_flag=false

for mode in $(jq -r '.modes[]' $filename)
do  
    echo $mode
    if [ $mode == "OH" ]; then
      OH  
      oh_flag=true
      fileVersion=${fileVersion+1}
    fi
    
    if [ $mode == "CFG" ]; then
      printFuncsToCheck
      CFG
      flags_front="${flags_front} ../phase2/llvm-callpath-pass/${build}libcheck.o ../phase2/llvm-callpath-pass/${build}crypto.o "
      flags_back="$flags_back -L/usr/lib/x86_64-linux-gnu/ -lssl -lcrypto "
      fileVersion=${fileVersion+1}
    fi
    
    if [ $mode == "RC" ]; then
      RC  
      flags_front="${flags_front} ../phase3/stins4llvm/${build}libcheck.o "
      fileVersion=${fileVersion+1}
    fi
done




llc-3.9 -filetype=obj "${build}${cfile}${fileVersion}.bc"
exitIfFail $?

g++ -rdynamic "${build}${cfile}${fileVersion}.o" $flags_front -o "${build}${cfile}-rewritten" $flags_back
exitIfFail $?

if [ $oh_flag == true ]; then
    ./"${build}${cfile}-rewritten" |& tee $outputFile
    exitIfFail $?

    python3 $patcher "${build}${cfile}-rewritten" $outputFile
    exitIfFail $?
fi
