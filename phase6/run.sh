#!/bin/bash

# Tools
OPT=opt-3.9
CLANG=clang-3.9
LINK=llvm-link-3.9
LLC=llc-3.9
CXX=g++

# Common folders
build="build/"
libs="/usr/local/lib/"

# Passes
cfiPass="../phase2/llvm-callpath-pass/${build}libCallPathProtectorPass.so"
rcPass="../phase3/stins4llvm/${build}libStateProtectorPass.so"
ohPass="../phase4/ohprottool/${build}libOHProtectorPass.so"
independentInputPass="${libs}libInputDependency.so"

# Passes' libraries and files
cfiLibrary="../phase2/llvm-callpath-pass/${build}libcheck.o ../phase2/llvm-callpath-pass/${build}crypto.o"
libssl="-L/usr/lib/x86_64-linux-gnu/ -lssl -lcrypto"
rcLibrary="../phase3/stins4llvm/${build}libcheck.o"
funcsToCheckFile="${build}functionsCFI"
ohOutputFile="/tmp/output.data"
ohPatcher="../phase4/ohprottool/src/patcher.py"

# Passes options
compilerFlagsFront=""
compilerFlagsBack=""
ohExecuted=false

# Configurations
config=""
resultFile=""
fileVersion=0

function usage {
    echo "usage: run.sh [-f file ]"
    echo "  -f file containing configuration"
    echo "  -c clean build folder"
}

function exitIfFail {
    if [ $1 != 0 ]; then
        exit $1
    fi
}

# https://stackoverflow.com/questions/1527049/join-elements-of-an-array
function joinBy {
    local IFS="$1"; shift; echo "$*";
}

function rmBuildDir {
    rm -rf $build 2> /dev/null
}

function makeBuildDir {
    mkdir -p ${build}
}

function printFuncsToCheck {
    rm $funcsToCheckFile 2> /dev/null
    for func in $(jq -r '.functionsCFI[]' $config)
    do
        echo $func >> $funcsToCheckFile
    done
}

function CFI {
    LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libssl.so \
    ${OPT} -load ${cfiPass} \
        "${build}${resultFile}${fileVersion}.bc" -callpath -ff ${funcsToCheckFile} -o "${build}${resultFile}${fileVersion+1}.bc"
    exitIfFail $?
}

function RC {
    ${OPT} -load ${rcPass} \
        "${build}${resultFile}${fileVersion}.bc" -stateProtect -ff $config -o "${build}${resultFile}${fileVersion+1}.bc"
    exitIfFail $?
}

function OH {
    ${OPT} -load ${independentInputPass} -load ${ohPass} \
        "${build}${resultFile}${fileVersion}.bc" -OHProtect -ff $config -o "${build}${resultFile}${fileVersion+1}.bc"
    exitIfFail $?
}

function ohPatch {
    if [ $ohExecuted == true ]; then
        ./${build}${resultFile} |& tee $ohOutputFile
        exitIfFail $?

        python3 $ohPatcher ${build}${resultFile} $ohOutputFile
        exitIfFail $?
    fi
}

function getBCFiles {
    local bcFiles

    for element in "$@"
    do
        file=$(basename "$element")
        bcFiles+="${file%.*}.bc "
    done

    echo "$bcFiles"
}

function executeProtection {
    local modes=("CFI" "RC" "OH")

    for mode in ${!1}
    do
        if [[ ! " ${modes[@]} " =~ " ${mode} " ]]; then
            echo "$mode does not recognised!"
            continue
        fi

        echo "Protecting in $mode mode..."

        if [ $mode == "OH" ]; then
            OH
            ohExecuted=true
        fi

        if [ $mode == "CFI" ]; then
            printFuncsToCheck
            CFI
            compilerFlagsFront+=" ${cfiLibrary} "
            compilerFlagsBack+=" ${libssl} "
        fi

        if [ $mode == "RC" ]; then
            RC
            compilerFlagsFront+=" ${rcLibrary} "
        fi

        fileVersion=${fileVersion+1}
        echo "Done protecting in $mode mode"
    done
}

# Check if enough arguments supplied to program
if (($# < 2)) || (($# > 3)); then
    usage
    exit 1
fi

# Parce input arguments
while [ "$1" != "" ]; do
    case $1 in
        -f | --file )           shift
                                config=$1
                                ;;
        -h | --help )           usage
                                exit
                                ;;
        -c | --clean )          rmBuildDir
                                ;;
        * )                     usage
                                exit 1
    esac
    shift
done

# Make build folder
makeBuildDir

# Parse json to get inputs
inputCFiles=($(jq -r '.program[]' $config))
exitIfFail $?
inputCFiles=$(joinBy ' ' "${inputCFiles[@]}")

inputBCFiles=$(getBCFiles $inputCFiles)

resultFile=$(jq -r '.binary' $config)
exitIfFail $?

clangFlags=$(jq -r 'select(.clangFlags != null) .clangFlags' $config)
exitIfFail $?

# Generate bc files
${CLANG} -c -emit-llvm ${inputCFiles} $clangFlags -O0
exitIfFail $?

${LINK} $inputBCFiles -o "${build}${resultFile}${fileVersion}.bc"
exitIfFail $?
rm $inputBCFiles 2> /dev/null

# Protect
inputmodes=($(jq -r '.modes[]' $config))
exitIfFail $?
executeProtection inputmodes[@]

# Generate object
${LLC} -filetype=obj "${build}${resultFile}${fileVersion}.bc"
exitIfFail $?

# Link
${CXX} -rdynamic "${build}${resultFile}${fileVersion}.o" $compilerFlagsFront -o ${build}${resultFile} $compilerFlagsBack
exitIfFail $?

# Patch if necessary
ohPatch
