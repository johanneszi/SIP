#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#define DEBUG 1

const static int REPORT = 2;

void initRandom() {
    srand(time(0));
}

__attribute__((always_inline))
inline int generateRandom10() {
    return rand() % 10;
}

void report() {
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
