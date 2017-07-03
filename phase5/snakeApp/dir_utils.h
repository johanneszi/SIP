#ifndef DIR_UTILS_H_
#define DIR_UTILS_H_

#define BUF_SIZE 512

void get_current_dir(char *current_dir, size_t size);

void relative_path_to(const char *file, char *path, size_t size);

#endif
