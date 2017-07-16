#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "dir_utils.h"

void get_current_dir(char *current_dir, size_t size) {
    memset(current_dir, 0, size);

    // Find directory of binary
    if (readlink("/proc/self/exe", current_dir, size - 1) == -1) {
        fprintf(stderr, "Could not get current directory!\n");
        return;
    }

    int end = size - 1;
    while (end >= 0 && current_dir[end] != '/')
        current_dir[end--] = '\0';
}

void relative_path_to(const char *file, char *path, size_t size) {
    char current_dir[BUF_SIZE];

    // Get the current binary directory and append another path to it
    get_current_dir(current_dir, sizeof(current_dir));

    strncpy(path, current_dir, size - 1);
    strncat(path, file, size - strlen(current_dir) - 1);
}
