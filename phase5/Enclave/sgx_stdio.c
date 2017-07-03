#include <stdarg.h>

#include "Enclave_t.h"
#include "sgx_stdio.h"

int stdin = 0, stdout = 1, stderr = 2;

void fprintf(int file, const char* fmt, ...) {
#define BUF_SIZE 1024
    char buf[BUF_SIZE] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUF_SIZE, fmt, ap);
    va_end(ap);
    size_t len = strlen(buf);
    write(file, buf, len);
}

int open(const char* filename, int flag, int mode) {
    int ret;
    if (ocall_open(&ret, filename, flag, mode) != SGX_SUCCESS) return -1;
    return ret;
}

int read(int file, void *buf, unsigned int size) {
    int ret;
    if (ocall_read(&ret, file, buf, size) != SGX_SUCCESS) return -1;
    return ret;
}

int write(int file, void *buf, unsigned int size) {
    int ret;
    if (ocall_write(&ret, file, buf, size) != SGX_SUCCESS) return -1;
    return ret;
}

int close(int file) {
    int ret;
    if (ocall_close(&ret, file) != SGX_SUCCESS) return -1;
    return ret;
}
