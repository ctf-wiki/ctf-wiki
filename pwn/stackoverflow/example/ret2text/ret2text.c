#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void secure(void)
{
    int secretcode, input;
    srand(time(NULL));

    secretcode = rand();
    scanf("%d", &input);
    if(input == secretcode)
        system("/bin/sh");
}

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 1, 0LL);

    char buf[100];

    printf("There is something amazing here, do you know anything?\n");
    gets(buf);
    printf("Maybe I will tell you next time !");

    return 0;
}
