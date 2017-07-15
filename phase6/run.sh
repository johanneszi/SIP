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

# SC tool
sctool="/home/sip/defaultProtection/self-checksumming/build/src/self-checksumming"
scpatcher="/home/sip/defaultProtection/self-checksumming/modify.py"

# Passes
cfiPass="/home/sip/defaultProtection/cfi/build/code/libFunctionPass.so"
rcPass="../phase3/stins4llvm/${build}libStateProtectorPass.so"
ohPass="../phase4/ohprottool/${build}libOHProtectorPass.so"
independentInputPass="${libs}libInputDependency.so"

# Passes' libraries and files
cfiStack="/home/sip/defaultProtection/cfi/code/NewStackAnalysis.c"
libssl="-L/usr/lib/x86_64-linux-gnu/ -lssl -lcrypto"
libbacktrace="-L/usr/lib/gcc/x86_64-linux-gnu/5 -lbacktrace"
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
    for func in $(jq -r 'select(.functionsCFI != null) .functionsCFI[]' $config)
    do
        echo $func >> $funcsToCheckFile
    done
}

function SC {
    local modes=${!1}
    local sc="SC"
    if [[ ! " ${modes[@]} " =~ " ${sc} " ]]; then
        return 0
    fi

    echo "Protecting in SC mode..."

    ${sctool} ${build}${resultFile} $2 $3
    exitIfFail $?

    python $scpatcher "${build}${resultFile}_modified"
    exitIfFail $?

    mv "${build}${resultFile}_modified" "${build}${resultFile}"
    exitIfFail $?

    echo "Done protecting in SC mode"
}

function CFI {
    ${OPT} -load ${cfiPass} \
        "${build}${resultFile}${fileVersion}.bc" -functionpass -i ${funcsToCheckFile} -o "${build}${resultFile}$((fileVersion+1)).bc"
    exitIfFail $?

    ${CLANG} -g -c -emit-llvm ${cfiStack} -o ${build}NewStackAnalysis.bc
    exitIfFail $?

    fileVersion=$((fileVersion+1))
    ${LINK} ${build}NewStackAnalysis.bc "${build}${resultFile}$((fileVersion)).bc" -o "${build}${resultFile}$((fileVersion+1)).bc"
    exitIfFail $?
}

function RC {
    ${OPT} -load ${rcPass} \
        "${build}${resultFile}${fileVersion}.bc" -stateProtect -ff $config -o "${build}${resultFile}$((fileVersion+1)).bc"
    exitIfFail $?
}

function OH {
    ${OPT} -load ${independentInputPass} -load ${ohPass} \
        "${build}${resultFile}${fileVersion}.bc" -OHProtect -ff $config -o "${build}${resultFile}$((fileVersion+1)).bc"
    exitIfFail $?
}

function ohPatch {
    if [ $ohExecuted == true ]; then
        execute=$(jq -r 'select(.execution != null) .execution' $config)

        if [[ -z "${execute// }" ]]; then
            execute="./${build}${resultFile}"
        fi

        ${execute} |& tee $ohOutputFile
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
            if [ $mode != "SC" ]; then
                echo "$mode is not recognised!"
            fi
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
            compilerFlagsBack+=" ${libbacktrace} "
        fi

        fileVersion=$((fileVersion+1))

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

gccFlags=$(jq -r 'select(.gccFlags != null) .gccFlags' $config)
exitIfFail $?

# Generate bc files
${CLANG} $clangFlags -c -g -emit-llvm ${inputCFiles} -O0
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
${CXX} -g "${build}${resultFile}${fileVersion}.o" $compilerFlagsFront -o ${build}${resultFile} $compilerFlagsBack $gccFlags
exitIfFail $?

# Patch if necessary
ohPatch

connectivitySC=$(jq -r 'select(.connectivitySC != null) .connectivitySC' $config)
exitIfFail $?

moduleSC=$(jq -r 'select(.module != null) .module' $config)
exitIfFail $?

# Patch SC if specified
SC inputmodes[@] $connectivitySC $moduleSC
