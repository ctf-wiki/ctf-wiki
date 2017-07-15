#include <stdio.h>
int main() {
  char flag[100] = "flag{this_is_flag}";
  char input[512];
  read(0, input, 512);
  printf(input);
  printf("flag is on the stack");
  return 0;
}
