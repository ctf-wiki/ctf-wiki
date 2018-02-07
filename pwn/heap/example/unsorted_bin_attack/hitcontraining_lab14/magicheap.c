#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void read_input(char *buf, size_t size) {
  int ret;
  ret = read(0, buf, size);
  if (ret <= 0) {
    puts("Error");
    _exit(-1);
  }
}

char *heaparray[10];
unsigned long int magic = 0;

void menu() {
  puts("--------------------------------");
  puts("       Magic Heap Creator       ");
  puts("--------------------------------");
  puts(" 1. Create a Heap               ");
  puts(" 2. Edit a Heap                 ");
  puts(" 3. Delete a Heap               ");
  puts(" 4. Exit                        ");
  puts("--------------------------------");
  printf("Your choice :");
}

void create_heap() {
  int i;
  char buf[8];
  size_t size = 0;
  for (i = 0; i < 10; i++) {
    if (!heaparray[i]) {
      printf("Size of Heap : ");
      read(0, buf, 8);
      size = atoi(buf);
      heaparray[i] = (char *)malloc(size);
      if (!heaparray[i]) {
        puts("Allocate Error");
        exit(2);
      }
      printf("Content of heap:");
      read_input(heaparray[i], size);
      puts("SuccessFul");
      break;
    }
  }
}

void edit_heap() {
  int idx;
  char buf[4];
  size_t size;
  printf("Index :");
  read(0, buf, 4);
  idx = atoi(buf);
  if (idx < 0 || idx >= 10) {
    puts("Out of bound!");
    _exit(0);
  }
  if (heaparray[idx]) {
    printf("Size of Heap : ");
    read(0, buf, 8);
    size = atoi(buf);
    printf("Content of heap : ");
    read_input(heaparray[idx], size);
    puts("Done !");
  } else {
    puts("No such heap !");
  }
}

void delete_heap() {
  int idx;
  char buf[4];
  printf("Index :");
  read(0, buf, 4);
  idx = atoi(buf);
  if (idx < 0 || idx >= 10) {
    puts("Out of bound!");
    _exit(0);
  }
  if (heaparray[idx]) {
    free(heaparray[idx]);
    heaparray[idx] = NULL;
    puts("Done !");
  } else {
    puts("No such heap !");
  }
}

void l33t() { system("cat ./flag"); }

int main() {
  char buf[8];
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  while (1) {
    menu();
    read(0, buf, 8);
    switch (atoi(buf)) {
    case 1:
      create_heap();
      break;
    case 2:
      edit_heap();
      break;
    case 3:
      delete_heap();
      break;
    case 4:
      exit(0);
      break;
    case 4869:
      if (magic > 4869) {
        puts("Congrt !");
        l33t();
      } else
        puts("So sad !");
      break;
    default:
      puts("Invalid Choice");
      break;
    }
  }
  return 0;
}
