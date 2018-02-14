#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
void showflag() { system("cat flag"); }
void vuln(char *file, char *buf) {
  int number;
  int index = 0;
  int fd = open(file, O_RDONLY);
  if (fd == -1) {
    perror("open file failed!!");
    return;
  }
  while (1) {
    number = read(fd, buf + index, 128);
    if (number <= 0) {
      break;
    }
    index += number;
  }
  buf[index + 1] = '\x00';
}
void check(char *file) {
  struct stat tmp;
  if (strcmp(file, "flag") == 0) {
    puts("file can not be flag!!");
    exit(0);
  }
  stat(file, &tmp);
  if (tmp.st_size > 255) {
    puts("file size is too large!!");
    exit(0);
  }
}
int main(int argc, char *argv[argc]) {
  char buf[256];
  if (argc == 2) {
    check(argv[1]);
    vuln(argv[1], buf);
  } else {
    puts("Usage ./prog <filename>");
  }
  return 0;
}
