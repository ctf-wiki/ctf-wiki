#include <stdio.h>
#include <string.h>

char buf2[100];

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 1, 0LL);

    char buf[100];

    printf("No system for you this time !!!\n");
    gets(buf);
    strncpy(buf2, buf, 100);
    printf("bye bye ~");

    return 0;
}
