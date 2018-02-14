#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct note {
  void (*printnote)();
  char *content;
};

struct note *notelist[5];
int count = 0;

void print_note_content(struct note *this) { puts(this->content); }
void add_note() {
  int i;
  char buf[8];
  int size;
  if (count > 5) {
    puts("Full");
    return;
  }
  for (i = 0; i < 5; i++) {
    if (!notelist[i]) {
      notelist[i] = (struct note *)malloc(sizeof(struct note));
      if (!notelist[i]) {
        puts("Alloca Error");
        exit(-1);
      }
      notelist[i]->printnote = print_note_content;
      printf("Note size :");
      read(0, buf, 8);
      size = atoi(buf);
      notelist[i]->content = (char *)malloc(size);
      if (!notelist[i]->content) {
        puts("Alloca Error");
        exit(-1);
      }
      printf("Content :");
      read(0, notelist[i]->content, size);
      puts("Success !");
      count++;
      break;
    }
  }
}

void del_note() {
  char buf[4];
  int idx;
  printf("Index :");
  read(0, buf, 4);
  idx = atoi(buf);
  if (idx < 0 || idx >= count) {
    puts("Out of bound!");
    _exit(0);
  }
  if (notelist[idx]) {
    free(notelist[idx]->content);
    free(notelist[idx]);
    puts("Success");
  }
}

void print_note() {
  char buf[4];
  int idx;
  printf("Index :");
  read(0, buf, 4);
  idx = atoi(buf);
  if (idx < 0 || idx >= count) {
    puts("Out of bound!");
    _exit(0);
  }
  if (notelist[idx]) {
    notelist[idx]->printnote(notelist[idx]);
  }
}

void magic() { system("cat flag"); }

void menu() {
  puts("----------------------");
  puts("       HackNote       ");
  puts("----------------------");
  puts(" 1. Add note          ");
  puts(" 2. Delete note       ");
  puts(" 3. Print note        ");
  puts(" 4. Exit              ");
  puts("----------------------");
  printf("Your choice :");
};

int main() {
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  char buf[4];
  while (1) {
    menu();
    read(0, buf, 4);
    switch (atoi(buf)) {
    case 1:
      add_note();
      break;
    case 2:
      del_note();
      break;
    case 3:
      print_note();
      break;
    case 4:
      exit(0);
      break;
    default:
      puts("Invalid choice");
      break;
    }
  }
  return 0;
}
