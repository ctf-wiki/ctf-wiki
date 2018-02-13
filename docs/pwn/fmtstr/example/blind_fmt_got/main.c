#include <stdio.h>
int main() {
  char input[128];
  while (1) {
    read(0, input, 128);
    printf(input);
    fflush(stdout);
  }
  return 0;
}
