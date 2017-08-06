#include <stdio.h>

// 23byte shellcode from http://shell-storm.org/shellcode/files/shellcode-827.php
char sc[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
		"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

void shellcode(){
	// a buffer we are about to exploit!
	char buf[20];

	// prepare shellcode on executable stack!
	strcpy(buf, sc);

	// overwrite return address!
	*(int*)(buf+32) = buf;

	printf("get shell\n");
}

int main(){
        printf("What the hell is wrong with my shellcode??????\n");
        printf("I just copied and pasted it from shell-storm.org :(\n");
        printf("Can you fix it for me?\n");

	unsigned int index=0;
	printf("Tell me the byte index to be fixed : ");
	scanf("%d", &index);
	fflush(stdin);

	if(index > 22)	return 0;

	int fix=0;
	printf("Tell me the value to be patched : ");
	scanf("%d", &fix);

	// patching my shellcode
	sc[index] = fix;	

	// this should work..
	shellcode();
	return 0;
}
