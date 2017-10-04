#include <stdio.h>
#include <unistd.h>
#include <string.h>
int i;
int check();
int main(void){
	setbuf(stdin,NULL);
	setbuf(stdout,NULL);
	setbuf(stderr,NULL);
    puts("WelCome my friend,Do you know password?");
	if(!check()){
        puts("Do not dump my memory");
	}else {
        puts("No password, no game");
	}
}
int check(){
    char buf[50];
    read(STDIN_FILENO,buf,1024);
    return strcmp(buf,"aslvkm;asd;alsfm;aoeim;wnv;lasdnvdljasd;flk");
}
