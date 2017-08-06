
//import subprocess
//subprocess.Popen(['/home/otp/otp', ''], stderr=subprocess.STDOUT)
//Darn... I always forget to check the return value of fclose() :(


// >>> import subprocess
// >>> subprocess.Popen(['/home/otp/otp',''])
// <subprocess.Popen object at 0x7fa98bf54ed0>
// >>> OTP generated.
// Congratz!
// Darn... I always forget to check the return value of fclose() :(
//
// >>>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char* argv[]){
	char fname[128];
	unsigned long long otp[2];
  printf("sizof unsigned long long otp[2] is %d\n",sizeof(otp));

printf("argc is %d \n ",argc);
	if(argc!=2){
		printf("usage : ./otp [passcode]\n");
		return 0;
	}

	int fd = open("/dev/urandom", O_RDONLY);
	if(fd==-1) exit(-1);

	if(read(fd, otp, 16)!=16) exit(-1);
	close(fd);

	sprintf(fname, "/tmp/%llu", otp[0]);
	FILE* fp = fopen(fname, "w");
	if(fp==NULL){ exit(-1); }
	fwrite(&otp[1], 8, 1, fp);    //内存读取啊!!
	fclose(fp);

	printf("OTP generated.\n");

	unsigned long long passcode=0;
	FILE* fp2 = fopen(fname, "r");
	if(fp2==NULL){ exit(-1); }
	fread(&passcode, 8, 1, fp2);   //从前面也应该看出这是64位机了
	fclose(fp2);

	if(strtoul(argv[1], 0, 16) == passcode){    //就说输入16字节的密码,要等于随机生成的passcode
		printf("Congratz!\n");
		system("/bin/cat flag");
	}
	else{
		printf("OTP mismatch\n");
	}

	unlink(fname);
	return 0;
}
