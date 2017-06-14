#include <algorithm>
#include <cstring>
#include <string>
#include <ctime>
#include <cstdlib>
#include <cstdio>
#include <vector>

#include <execinfo.h>
#include <unistd.h>
#include <signal.h>

#define DEBUG 1

using std::vector;
using std::string;

const static string LIBCSTARTMAIN = "__libc_start_main";
const static int STACKTRACE = 256;
const static int REPORT = 2;

extern "C" int printme(int a) {
    printf("%d\n", a);

    return a + 1;
}

extern "C" int printmeCond(int a) {
    printf("%d\n", a);

    return a + 1;
}

extern "C" void initRandom() {
    srand(time(0));
}

extern "C" bool cmpstr(char *first, char *second) {
    return strcmp(first, second);
}

// Calculate backtrace
extern "C" bool checkTrace(const char *functionName) {
    vector<string> trace;
    void *array[STACKTRACE];
    size_t size;

    // Get void*'s for all entries on the stack
    size = backtrace(array, STACKTRACE);

    char **traces = backtrace_symbols(array, size);
    
    // Skip this function in backtrace
    for(unsigned int i = 1; i < size; i++) {
        char *begin = traces[i];
        for (char* p = traces[i]; *p; p++) {
            if (*p == '(') {
                begin = p + 1;
            } else if(*p == '+') {
                *p = '\0';
                break;
            }
        }

        string funcName(begin);

        // Skip everything after libc functions
        if (funcName == LIBCSTARTMAIN) { break; }

        trace.push_back(funcName);
    }

    bool functionOnStack = std::find(trace.begin(), trace.end(), functionName) != trace.end();

    return functionOnStack;
}

int generateRandom10() {
    return rand() % 10;
}

extern "C" void report() {
    #if DEBUG
    puts("Hash corrupted!");
    #endif

    int randNum = generateRandom10();

    #if DEBUG
    printf("Should report: %s (%d)\n", randNum >= REPORT ? "TRUE" : "FALSE", randNum);
    #endif

    // In 20% of the times don't do anything
    if (randNum < REPORT) {
        return;
    }

    // In the other 80% spawn a thread, sleep
    // and kill the process
    int parent = getpid();
    pid_t pid = fork();

    if (pid == 0) {
        randNum = generateRandom10();

        #if DEBUG
        printf("Kill in %d seconds...\n", randNum);
        #endif

        sleep(randNum);

        kill(parent, SIGKILL);
        exit(0);
    }
}

#undef DEBUG
#undef STACKTRACE
#undef REPORT
