#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int ocall_open(const char* filename, int flag, int mode) {
        return open(filename, flag, mode);
}

int ocall_read(int file, void *buf, unsigned int size) {
        return read(file, buf, size);
}

int ocall_write(int file, void *buf, unsigned int size) {
        return write(file, buf, size);
}

int ocall_close(int file) {
        return close(file);
}
