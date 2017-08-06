#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include<time.h>

int main(int argc, char **argv){

        assert(argc==3);
        int t = atoi(argv[1]);
        int m = atoi(argv[2]);
        srand(t);
        int i=0;
        int rands[8];
        for(i=0;i<=7;i++){
                rands[i]=rand();
        }
        int a = rands[1]+rands[2]-rands[3]+rands[4]+rands[5]-rands[6]+rands[7];
        m -= a;
        printf("%x\n",m);
        return 0;
}
