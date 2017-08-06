#include<stdio.h>
#include <bits/types.h>
#include<sys/socket.h>
#include<unistd.h>
#include<sys/types.h>
int main()
{
  char *argv[101]={"/home/calvinrd/krpwn/input_solved/input",
[1 ... 99]="A",NULL};
printf("stage 1 .....\n");
argv['A']="\x00";
argv['B']="\x20\x0a\x0d";
argv['C']="55555";
//execve("/home/calvinrd/krpwn/input_solved/input",argv,NULL);
printf("stage 2 .....\n");
int pipe2stdin[2]={-1,-1};  //这里作为接受管道描述符的数组，其中fd[0] 用于读取管道，fd[1]用于写入管道。
int pipe2stderr[2]={-1,-1};
pid_t childpid;
if(pipe(pipe2stdin)<0 || pipe(pipe2stderr)<0)
{
  perror("cannot create the pipe");
  exit(1);
}
if((childpid=fork())<0)
{
  perror("cannot fork");
  exit(1);
}
if(childpid==0)
{
  //子进程
  close(pipe2stdin[0]);
  close(pipe2stderr[0]);
  printf("pipe2stdin[1] is %d\n",pipe2stdin[1]);
  printf("pipe2stderr[1] is %d\n",pipe2stderr[1]);
  printf("pipe2stdin[0] is %d\n",pipe2stdin[0]);
  printf("pipe2stderr[0] is %d\n",pipe2stderr[0]);
  write(pipe2stdin[1],"\x00\x0a\x00\xff",4);
  write(pipe2stderr[1],"\x00\x0a\x02\xff",4);
}
else{
  //当前进程
  close(pipe2stdin[1]);
  close(pipe2stderr[1]);
  dup2(pipe2stdin[0],0); //绑定stdin和之前pipe生成的文件描述符
  dup2(pipe2stderr[0],2);
  close(pipe2stdin[0]);
  close(pipe2stderr[0]);

//环境变量stage3
  char *env[2]={"\xde\xad\xbe\xef=\xca\xfe\xba\xbe",NULL};
  //STAGE4
  FILE* fp=fopen("\x0a","w");
  fwrite("\x00\x00\x00\x00",4,1,fp);
  fclose(fp);
//stage5

  execve("/home/calvinrd/krpwn/input_solved/input",argv,env);
}

}
