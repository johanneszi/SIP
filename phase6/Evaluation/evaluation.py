import time
from processtimer import ProcessTimer
import json
import os

path = "/home/sip/SIP/phase6/"
runscript = path + "run.sh"
composition_zopfli = ["OH", "RC", "CFI", "SC", "OH+CFI", "OH+SC", "RC+CFI+OH", "RC+CFI+OH+SC"]
composition = ["OH", "CFI", "SC", "OH+CFI", "OH+SC", "CFI+OH+SC"]

dataset = {"micro-snake": {
                "source": [path + "Docker/dataset/src/micro-snake/snake.c"],
                "binary": "snake-rewritten",
                "clangFlags": "-W -Wall -Werror -DVERSION=\"1.0.1\"",
                "functionsCFI": ["collision", "eat_gold", "setup_level", "move", "collide_self", "collide_object", "show_score", "collide_walls", "main"],
                "input": path + "Docker/dataset/inputs/micro-snake.in",
                "execution": "python3 " + path + "Docker/dataset/inputs/ptypipe.py {1} " + path + "build/{0}"
            },
            "csnake": {
                "source": [path + "Docker/dataset/src/c-snake/snake.c"],
                "binary": "csnake-rewritten",
                "gccFlags": "-lncurses",
                "functionsCFI": ["snake_game_over", "snake_in_bounds", "snake_draw_fruit", "snake_index_to_coordinate", "snake_cooridinate_to_index", "snake_move_player", "main"],
                "input": path + "Docker/dataset/inputs/c-snake.in",
                "execution": "python3 " + path + "Docker/dataset/inputs/ptypipe.py {1} " + path + "build/{0}"
            },
            "tetris": {
                "source": [path + "Docker/dataset/src/tetris/tetris.c"],
                "binary": "teris-rewritten",
                "clangFlags": "-DENABLE_SCORE -DENABLE_PREVIEW -DENABLE_HIGH_SCORE",
                "functionsCFI": ["fits_in", "next_shape", "place", "freeze", "update", "show_high_score"],
                "input": path + "Docker/dataset/inputs/tetris.in",
                "execution": "python3 " + path + "Docker/dataset/inputs/ptypipe.py {1} " + path + "build/{0}"
            },
            "zopfli": {
                "source": ["Docker/dataset/src/zopfli/src/zopfli/blocksplitter.c",
                    path + "Docker/dataset/src/zopfli/src/zopfli/cache.c",
                    path + "Docker/dataset/src/zopfli/src/zopfli/deflate.c",
                    path + "Docker/dataset/src/zopfli/src/zopfli/gzip_container.c",
                    path + "Docker/dataset/src/zopfli/src/zopfli/hash.c",
                    path + "Docker/dataset/src/zopfli/src/zopfli/katajainen.c",
                    path + "Docker/dataset/src/zopfli/src/zopfli/lz77.c",
                    path + "Docker/dataset/src/zopfli/src/zopfli/squeeze.c",
                    path + "Docker/dataset/src/zopfli/src/zopfli/tree.c",
                    path + "Docker/dataset/src/zopfli/src/zopfli/util.c",
                    path + "Docker/dataset/src/zopfli/src/zopfli/zlib_container.c",
                    path + "Docker/dataset/src/zopfli/src/zopfli/zopfli_lib.c",
                    path + "Docker/dataset/src/zopfli/src/zopfli/zopfli_bin.c"],
                "binary": "zopfli-rewritten",
                "clangFlags": "-W -Wall -Wextra -ansi -pedantic -O2 -Wno-unused-function",
                "functionsCFI": ["ZopfliUpdateHash", "AddHuffmanBits", "ZopfliCleanHash", "UpdateHashValue", "ZopfliWarmupHash"],
                "functionsRC": ["CeilDiv", "GetLengthScore", "StringsEqual", "CRC", "adler32", "LeafComparator"],
                "input": path + "Docker/dataset/inputs/zopfli.in",
                "execution": path + "build/{0} {1}"
            }
}

config = {
    "hashVariables" : 5,
    "checksPerHashVariable": 1,
    "obfuscationLevel":0,
    "debug" : False,
    "connectivityRC" : 1,
    "connectivitySC" : 1,
    "syminputC" : path + "../phase3/Docker/klee/syminputC.py",
    "syminputBC" : path + "../phase3/Docker/klee/syminputBC.py",
    "verbose" : False,
}


def writeConfig():
    with open("config.json", "w") as f:
        f.write(json.dumps(config, indent=4))


def writeResult(program, result):
    with open(program + ".json", "w") as f:
        f.write(json.dumps(result, indent=4))


def executeProgram(program):
    exec_input = dataset[program]['input']
    exec_file = dataset[program]['binary']
    ptimer = ProcessTimer(dataset[program]['execution'].format(exec_file, exec_input).split(" "))

    try:
        ptimer.execute()
        #poll as often as possible; otherwise the subprocess might
        # "sneak" in some extra memory usage while you aren't looking
        while ptimer.poll():
            time.sleep(.001)
    finally:
        #make sure that we don't leave the process dangling?
        ptimer.close()

    exec_time = ptimer.t1 - ptimer.t0
    exec_memory = ptimer.max_rss_memory

    statinfo = os.stat(path + "build/" + exec_file)

    return exec_time, exec_memory, statinfo.st_size


for program in dataset.keys():
    result = {"program" : program, "Results":[]}

    config["program"] = dataset[program]["source"]
    config["binary"] = dataset[program]["binary"]
    config["module"] = dataset[program]["binary"]
    config["clangFlags"] = "" if not dataset[program].get("clangFlags") else dataset[program]["clangFlags"]
    config["gccFlags"] = "" if not dataset[program].get("gccFlags") else dataset[program]["gccFlags"]
    config["functionsRC"] = "" if not dataset[program].get("functionsRC") else dataset[program]["functionsRC"]
    config["functionsCFI"] = "" if not dataset[program].get("functionsCFI") else dataset[program]["functionsCFI"]

    exec_input = dataset[program]['input']
    exec_file = dataset[program]['binary']
    config["execution"] = dataset[program]['execution'].format(exec_file, exec_input)

    config["modes"] = []
    writeConfig()

    ptimer = ProcessTimer([runscript, '-f','config.json'])

    try:
        ptimer.execute()
        #poll as often as possible; otherwise the subprocess might
        # "sneak" in some extra memory usage while you aren't looking
        while ptimer.poll():
            time.sleep(.001)
    finally:
        #make sure that we don't leave the process dangling?
        ptimer.close()

    unprotected_time, unprotected_memory, unprotected_size = executeProgram(program)
    comps = []
    if program == "zopfli":
        comps = composition_zopfli
    else:
        comps = composition
    for mode in comps:
        print("Protecting in " + mode + " mode " + program)

        intermediateResult = {"Composition" : mode}

        config["modes"] = mode.split("+")
        with open("config.json", "w") as f:
            f.write(json.dumps(config))

        ptimer = ProcessTimer([runscript, '-f','config.json'])

        try:
            ptimer.execute()
            #poll as often as possible; otherwise the subprocess might
            # "sneak" in some extra memory usage while you aren't looking
            while ptimer.poll():
                time.sleep(.001)
        finally:
            #make sure that we don't leave the process dangling?
            ptimer.close()

        protected_time, protected_memory, protected_size = executeProgram(program)
        intermediateResult["ProtetionTime"] = ptimer.t1 - ptimer.t0
        intermediateResult["RuntimeOverhead"] = (protected_time / unprotected_time) - 1 # TODO add percent

        intermediateResult["MemoryOverhead"] = (protected_memory / unprotected_memory) - 1 # TODO add percent
        intermediateResult["BinarySizeOverhead:"] = (protected_size / unprotected_size) - 1 # TODO add percent

        result['Results'] += [intermediateResult]
        print(result)

        writeResult(program, result)
