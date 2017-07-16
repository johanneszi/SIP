#include <openssl/sha.h>
#include <algorithm>
#include <cstring>
#include <iostream>
#include "backtrace-supported.h"
#include "backtrace.h"

#include "crypto.h"

#define DEBUG 0

static void backtraceErrorCallback(void *vdata, const char *msg, int errnum) {
    fprintf(stderr, "%s", msg);
    if (errnum > 0)
        fprintf(stderr, ": %s", strerror(errnum));
    fprintf(stderr, "\n");
}

static void backtraceCallbackCreate(void *data, const char *msg, int errnum) {
    fprintf(stderr, "%s", msg);
    if (errnum > 0)
        fprintf(stderr, ": %s", strerror(errnum));
    fprintf(stderr, "\n");

    exit(EXIT_FAILURE);
}

static int collectBacktrace(void *vdata, uintptr_t pc, const char *filename, int lineno,
                            const char *function) {
    std::vector<std::string> *data = (std::vector<std::string> *)vdata;
    if (function != NULL) {
        std::vector<std::string>::iterator position =
            std::find(data->begin(), data->end(), function);

        if (position != data->end()) {
            data->erase(position);
        }

        data->push_back(function);
    }

    return 0;
}

backtrace_state *backtrace_state =
    backtrace_create_state("", BACKTRACE_SUPPORTED, backtraceCallbackCreate, NULL);

// Calculate backtrace
std::vector<std::string> stackTrace() {
    std::vector<std::string> trace;
    
    // Skip the first two frames
    backtrace_full(backtrace_state, 2, collectBacktrace, backtraceErrorCallback, &trace);

    size_t size = trace.size();
    std::string start = size == 0 ? "" : trace.front();

    std::reverse(trace.begin(), trace.end());

    unsigned int i = 0;
    while (i < size && trace[i] != start) {
        i++;
    };
    trace.erase(trace.begin() + i + 1, trace.end());

#if DEBUG
    for (auto func : trace) {
        std::cout << func << " ";
    }
    std::cout << std::endl;
#endif

    return trace;
}

extern "C" bool check(char *validHash, bool hasToCheck) {
    if (!hasToCheck) {
        std::vector<std::string> currentTrace = stackTrace();
        std::string hash = sha256(currentTrace);

        return std::memcmp(validHash, hash.c_str(), SHA256_DIGEST_LENGTH) == 0;
    }

    return true;
}

extern "C" void reporter(bool valid) {
    if (!valid) {
        std::cout << "Hash corrupted!" << std::endl;
        exit(1);
    }
}

#undef DEBUG
