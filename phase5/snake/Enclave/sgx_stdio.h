#ifndef __SGX_STDIO_H
#define __SGX_STDIO_H

#ifndef _INC_FCNTL
#define _INC_FCNTL

#define O_RDONLY       0x0000  /* open for reading only */
#define O_WRONLY       0x0001  /* open for writing only */
#define O_RDWR         0x0002  /* open for reading and writing */
#define O_APPEND       0x0400  /* writes done at eof */

#define O_CREAT        0x0040  /* create and open file */
#define O_TRUNC        0x0200  /* open and truncate */
#define O_EXCL         0x0080  /* open only if file doesn't already exist */

#define S_IRWXU        0x01C0  /* RWX mask for owner */
#define S_IRUSR        0x0100  /* R for owner */
#define S_IWUSR        0x0080  /* W for owner */
#define S_IXUSR        0x0040  /* X for owner */

#define S_IRWXG        0x0038  /* RWX mask for group */
#define S_IRGRP        0x0020  /* R for group */
#define S_IWGRP        0x0010  /* W for group */
#define S_IXGRP        0x0008  /* X for group */

#define S_IRWXO        0x0007  /* RWX mask for other */
#define S_IROTH        0x0004  /* R for other */
#define S_IWOTH        0x0002  /* W for other */
#define S_IXOTH        0x0001  /* X for other */

#endif

#ifdef __cplusplus
extern "C" {
#endif

extern int stdin, stdout, stderr;

void fprintf(int file, const char* fmt, ...);

int open(const char* filename, int flag, int mode);
int read(int file, void *buf, unsigned int size);
int write(int file, void *buf, unsigned int size);
int close(int file);

#ifdef __cplusplus
}
#endif

#endif
