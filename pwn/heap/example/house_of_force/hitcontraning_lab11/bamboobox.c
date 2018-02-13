#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
struct item {
  int size;
  char *name;
};

struct item itemlist[100] = {0};

int num;

void hello_message() {
  puts("There is a box with magic");
  puts("what do you want to do in the box");
}

void goodbye_message() {
  puts("See you next time");
  puts("Thanks you");
}

struct box {
  void (*hello_message)();
  void (*goodbye_message)();
};

void menu() {
  puts("----------------------------");
  puts("Bamboobox Menu");
  puts("----------------------------");
  puts("1.show the items in the box");
  puts("2.add a new item");
  puts("3.change the item in the box");
  puts("4.remove the item in the box");
  puts("5.exit");
  puts("----------------------------");
  printf("Your choice:");
}

void show_item() {
  int i;
  if (!num) {
    puts("No item in the box");
  } else {
    for (i = 0; i < 100; i++) {
      if (itemlist[i].name) {
        printf("%d : %s", i, itemlist[i].name);
      }
    }
    puts("");
  }
}

int add_item() {

  char sizebuf[8];
  int length;
  int i;
  int size;
  if (num < 100) {
    printf("Please enter the length of item name:");
    read(0, sizebuf, 8);
    length = atoi(sizebuf);
    if (length == 0) {
      puts("invaild length");
      return 0;
    }
    for (i = 0; i < 100; i++) {
      if (!itemlist[i].name) {
        itemlist[i].size = length;
        itemlist[i].name = (char *)malloc(length);
        printf("Please enter the name of item:");
        size = read(0, itemlist[i].name, length);
        itemlist[i].name[size] = '\x00';
        num++;
        break;
      }
    }

  } else {
    puts("the box is full");
  }
  return 0;
}

void change_item() {

  char indexbuf[8];
  char lengthbuf[8];
  int length;
  int index;
  int readsize;

  if (!num) {
    puts("No item in the box");
  } else {
    printf("Please enter the index of item:");
    read(0, indexbuf, 8);
    index = atoi(indexbuf);
    if (itemlist[index].name) {
      printf("Please enter the length of item name:");
      read(0, lengthbuf, 8);
      length = atoi(lengthbuf);
      printf("Please enter the new name of the item:");
      readsize = read(0, itemlist[index].name, length);
      *(itemlist[index].name + readsize) = '\x00';
    } else {
      puts("invaild index");
    }
  }
}

void remove_item() {
  char indexbuf[8];
  int index;

  if (!num) {
    puts("No item in the box");
  } else {
    printf("Please enter the index of item:");
    read(0, indexbuf, 8);
    index = atoi(indexbuf);
    if (itemlist[index].name) {
      free(itemlist[index].name);
      itemlist[index].name = 0;
      itemlist[index].size = 0;
      puts("remove successful!!");
      num--;
    } else {
      puts("invaild index");
    }
  }
}

void magic() {
  int fd;
  char buffer[100];
  fd = open("./flag", O_RDONLY);
  read(fd, buffer, sizeof(buffer));
  close(fd);
  printf("%s", buffer);
  exit(0);
}

int main() {

  char choicebuf[8];
  int choice;
  struct box *bamboo;
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  bamboo = malloc(sizeof(struct box));
  bamboo->hello_message = hello_message;
  bamboo->goodbye_message = goodbye_message;
  bamboo->hello_message();

  while (1) {
    menu();
    read(0, choicebuf, 8);
    choice = atoi(choicebuf);
    switch (choice) {
    case 1:
      show_item();
      break;
    case 2:
      add_item();
      break;
    case 3:
      change_item();
      break;
    case 4:
      remove_item();
      break;
    case 5:
      bamboo->goodbye_message();
      exit(0);
      break;
    default:
      puts("invaild choice!!!");
      break;
    }
  }

  return 0;
}
