import time
from processtimer import ProcessTimer
import json
import subprocess
import resource

runscript = "/home/zhechev/Developer/SIP/phase6/run.sh"
composition = ["OH", "RC", "CFI", "SC", "OH+CFI", "OH+SC", "OH+RC+CFI", "OH+RC+CFI+SC"]

dataset = { "micro-snake": {
                "source": ["/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/micro-snake/snake.c"],
                "binary": "snake-rewritten",
                "clangFlags": "-W -Wall -Werror -DVERSION=\"1.0.1\"",
                "functionsCFI": [],
                "functionsRC": []
            },
            "csnake": {

                "source": ["/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/c-snake/snake.c"],
                "binary": "csnake-rewritten",
                "clangFlags" : "",
                "gccFlags": "-lncurses",
                "functionsCFI": [],
                "functionsRC": []
            },
            "micro-snake": {
                "source": ["/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/tetris/tetris.c"],
                "binary": "teris-rewritten",
                "clangFlags": "-DENABLE_SCORE -DENABLE_PREVIEW -DENABLE_HIGH_SCORE",
                "functionsCFI": [],
                "functionsRC": []
            },
            "zopfli": {
                "source": ["/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/zopfli/src/zopfli/blocksplitter.c",
                    "/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/zopfli/src/zopfli/cache.c", 
                    "/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/zopfli/src/zopfli/deflate.c",
                    "/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/zopfli/src/zopfli/gzip_container.c",
                    "/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/zopfli/src/zopfli/hash.c",
                    "/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/zopfli/src/zopfli/katajainen.c",
                    "/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/zopfli/src/zopfli/lz77.c",
                    "/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/zopfli/src/zopfli/squeeze.c",
                    "/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/zopfli/src/zopfli/tree.c",
                    "/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/zopfli/src/zopfli/util.c",
                    "/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/zopfli/src/zopfli/zlib_container.c",
                    "/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/zopfli/src/zopfli/zopfli_lib.c",
                    "/home/zhechev/Developer/SIP/phase6/Docker/dataset/src/zopfli/src/zopfli/zopfli_bin.c"],
                "binary": "zopfli-rewritten",
                "clangFlags": "-W -Wall -Wextra -ansi -pedantic -O2 -Wno-unused-function",
                "functionsCFI": [],
                "functionsRC": ["CeilDiv", "GetLengthScore"]
            }
}

config = {
    "hashVariables" : 5,
    "checksPerHashVariable": 1,
    "obfuscationLevel":0,
    "debug" : False,
    "connectivity" : 1,
    "syminputC" : "/home/zhechev/Developer/SIP/phase3/Docker/klee/syminputC.py",
    "syminputBC" : "/home/zhechev/Developer/SIP/phase3/Docker/klee/syminputBC.py",
    "verbose" : False,
}

for program in dataset.keys():  
    config["binary"] = dataset[program]["binary"]
    config["clangFlags"] = dataset[program]["clangFlags"]
    config["program"] = dataset[program]["source"]
    config["functionsRC"] = dataset[program]["functionsRC"]
    config["functionsCFI"] = dataset[program]["functionsCFI"]

    for mode in composition:
        config["modes"] = mode.split("+")
        with open("config.json", "w") as f:
            f.write(json.dumps(config))

        ptimer = ProcessTimer(['./zopfli','processtimer.py'])
        try:
            ptimer.execute()
            #poll as often as possible; otherwise the subprocess might
            # "sneak" in some extra memory usage while you aren't looking
            while ptimer.poll():
                time.sleep(.001)
        finally:
            #make sure that we don't leave the process dangling?
            ptimer.close()

        print('return code:',ptimer.p.returncode)
        print('time:', ptimer.t1)
        print('max_vms_memory:',ptimer.max_vms_memory)
        print('max_rss_memory:',ptimer.max_rss_memory)

        exit()
