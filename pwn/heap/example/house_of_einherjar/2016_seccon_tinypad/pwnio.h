#ifndef         _LOWLEVEL_H
# define        _LOWLEVEL_H
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

extern ssize_t read_n(char *buf, size_t n);
extern ssize_t read_until(char *buf, size_t n, int c);
extern ssize_t write_n(const char *buf, size_t n);
extern ssize_t write_errn(const char *buf, size_t n);
extern ssize_t writeln(const char *buf, size_t n);
extern ssize_t writerrln(const char *buf, size_t n);
extern int read_int(void);
#endif
