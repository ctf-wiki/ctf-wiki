#include "pwnio.h"

static inline ssize_t _read_n(int fd, char *buf, size_t n)
{
    if(buf == NULL) return -1;
    if(n == 0) return 0;

    ssize_t rx = 0;

    while(rx < n) {
        ssize_t r = read(fd, buf + rx, n - rx);
        if(r < 0) {
            // interupted or under non-block?
            if(errno == EAGAIN || errno == EINTR) continue;
            // another reason.
            return -1;
        } 
        // sending finished.
        if(r == 0) break;
        rx += r;
    }

    return rx;
}

static inline ssize_t _write_n(int fd, const char *buf, size_t n)
{
    if(buf == NULL) return -1;
    if(n == 0) return 0;

    ssize_t tx = 0;

    while(tx < n) {
        ssize_t r = write(fd, buf+tx, n - tx);
        if(r < 0) {
            // interupted or under non-block?
            if(errno == EAGAIN || errno == EINTR) continue;
            // another reason.
            return -1;
        }
        // sending finished.
        if(r == 0) break;
        tx += r;
    }

    return tx;
}

static inline void _dummyinput(int c)
{
    if(!c) return;
    char dummy = '\0';
    while(dummy != c) 
        read_n(&dummy, 1);
}

extern ssize_t read_n(char *buf, size_t n)
{
    return _read_n(STDIN_FILENO, buf, n);
}

extern ssize_t read_until(char *buf, size_t n, int c)
{
    size_t rx = 0;

    while(rx < n) {
        ssize_t r = _read_n(STDIN_FILENO, buf + rx, 1);
        if(r < 0) return -1;
        if(r == 0 || buf[rx] == c) break;
        rx += 1;
    }
    buf[rx] = '\0';

    if(rx == n && buf[n-1] != '\n')
        _dummyinput(c);

    return rx;
}

extern ssize_t write_n(const char *buf, size_t n)
{
    return _write_n(STDOUT_FILENO, buf, n);
}

extern ssize_t write_errn(const char *buf, size_t n)
{
    return _write_n(STDERR_FILENO, buf, n);
}

extern ssize_t writeln(const char *buf, size_t n)
{
    ssize_t sum = 0;
    sum += write_n(buf, n);
    sum += write_n("\n", 1);
    return sum;
}

extern ssize_t writerrln(const char *buf, size_t n)
{
    ssize_t sum = 0;
    sum += write_errn(buf, n);
    sum += write_errn("\n", 1);
    return sum;
}

extern int read_int(void)
{
    char buf[18] = {};
    read_until(buf, (sizeof(buf)/sizeof(buf[0])) - 1, '\n');
    return atoi(buf);
}
