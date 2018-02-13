#include <stdio.h>
#include <stdlib.h>

char *shell = "/bin/sh";

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 1, 0LL);
    
    char buf[100];

    printf("This time, no system() and NO SHELLCODE!!!\n");
    printf("What do you plan to do?\n");
    gets(buf);

    return 0;
}
