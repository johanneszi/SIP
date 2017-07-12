import json
import subprocess
import resource

class ResourcePopen(subprocess.Popen):
    def _try_wait(self, wait_flags):
        """All callers to this function MUST hold self._waitpid_lock."""
        try:
            (pid, sts, res) = _eintr_retry_call(os.wait4, self.pid, wait_flags)
        except OSError as e:
            if e.errno != errno.ECHILD:
                raise
            # This happens if SIGCLD is set to be ignored or waiting
            # for child processes has otherwise been disabled for our
            # process.  This child is dead, we can't get the status.
            pid = self.pid
            sts = 0
        else:
            self.rusage = res
        return (pid, sts)

def resource_call(*popenargs, timeout=None, **kwargs):
    """Run command with arguments.  Wait for command to complete or
    timeout, then return the returncode attribute and resource usage.

    The arguments are the same as for the Popen constructor.  Example:

    retcode, rusage = call(["ls", "-l"])
    """
    with ResourcePopen(*popenargs, **kwargs) as p:
        try:
            retcode = p.wait(timeout=timeout)
            return [retcode, p.rusage]
        except:
            p.kill()
            p.wait()
            raise


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
    config["clangFlags"] = dataset[program]["flags"]
    config["program"] = dataset[program]["source"]
    config["functionsRC"] = dataset[program]["functionsRC"]
    config["functionsCFI"] = dataset[program]["functionsCFI"]
    
    for mode in composition:
        config["modes"] = mode.split("+")
        with open("config.json", "w") as f:
            f.write(json.dumps(config))
        result = resource_call(['ls', '-l']) #([runscript, "-f", "config.json"])
        print('spam used {}s of system time'.format(result[1].ru_stime))
        exit()
