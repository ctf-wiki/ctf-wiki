# 基本堆介绍

## 什么是堆

在程序的运行过程中，堆可以提供动态分配的内存，允许程序去为在程序运行之前还未知大小的变量申请空间。

目前标准Linux发行版中使用的堆分配器就是glibc中提供的堆分配器，它被称为ptmalloc2。glibc主要是通过malloc/free函数来实现对内存块进行分配和释放。

Linux中早期的堆分配与回收由Doug Lea实现，但它在并行处理多个线程时，会共享进程的堆内存空间，因此会出现堆被线程加锁利用时，其它线程无法使用的情况，这就会降低内存分配和回收的高效性。同时，如果在多线程使用时，没能正确控制，也可能引起内存分配和回收的正确性。Wolfram Gloger在Doug Lea的基础上进行改进使其可以支持多线程，这个堆分配器就是ptmalloc。在glibc-2.3.x.之后，glibc中已经集成了ptmalloc2。

需要注意的是，堆其实就是程序的虚拟地址空间的一块连续的线性区域，它由低地址向高地址方向增长。

ptmalloc处于用户程序与内核中间，主要做以下工作

1. 响应用户的申请内存操作，向操作系统申请内存，然后将其返回给用户程序。同时，为了保持内存管理的高效性，内核一般都会预先分配很大的一块连续的内存，然后让ptmalloc通过某种算法管理这块内存。只有当出现了堆空间不足的情况，ptmalloc才会再次与操作系统进行交流。
2. 管理用户所释放的内存。也就是说用户释放的内存并不是直接返还给操作系统的，而是由ptmalloc进行管理。这些释放的chunk可以来响应用户新申请的内存的请求。

需要注意的是，在内存分配与使用的过程中，Linux有这样的一个基本内存管理思想，**只有当真正访问一个地址的时候，系统才会建立虚拟页面与物理页面的映射关系**。 所以虽然我们上面说操作系统已经给程序分配了很大的一块内存，但是这块内存其实只是虚拟内存。只有当用户使用到相应的内存时，系统才会真正分配物理页面给用户使用。

## 堆的基本操作

这里我们主要介绍一下基本的堆的操作，包括堆的分配，回收，堆分配背后的系统调用，最后会介绍堆目前的多线程支持。

### malloc

在glibc的[malloc.h](https://github.com/iromise/glibc/blob/master/malloc/malloc.c#L448)中，malloc的说明如下

```c++
/*
  malloc(size_t n)
  Returns a pointer to a newly allocated chunk of at least n bytes, or null
  if no space is available. Additionally, on failure, errno is
  set to ENOMEM on ANSI C systems.
  If n is zero, malloc returns a minumum-sized chunk. (The minimum
  size is 16 bytes on most 32bit systems, and 24 or 32 bytes on 64bit
  systems.)  On most systems, size_t is an unsigned type, so calls
  with negative arguments are interpreted as requests for huge amounts
  of space, which will often fail. The maximum supported value of n
  differs across systems, but is in all cases less than the maximum
  representable value of a size_t.
*/
```

可以看出，malloc操作返回了对应大小字节的内存块的指针。此外，该函数还对一些异常情况进行了处理

- 当n=0时，返回当前系统允许的堆的最小内存块。
- 当n为负数时，由于在大多数系统上，size_t是无符号数，所以程序就会申请很大的内存空间，但通常来说都会崩溃，因为系统没有那么多的内存可以分配。

### free

在glibc的[malloc.h](https://github.com/iromise/glibc/blob/master/malloc/malloc.c#L465)中，free的说明如下

```c++
/*
      free(void* p)
      Releases the chunk of memory pointed to by p, that had been previously
      allocated using malloc or a related routine such as realloc.
      It has no effect if p is null. It can have arbitrary (i.e., bad!)
      effects if p has already been freed.
      Unless disabled (using mallopt), freeing very large spaces will
      when possible, automatically trigger operations that give
      back unused memory to the system, thus reducing program footprint.
    */
```

可以看出，free函数主要是释放由p所指向的内存块，并且这个内存块有可能是通过malloc函数得到的，也有可能是通过相关的函数realloc得到的。此外，该函数也同样对异常情况进行了处理

- 当p为空指针时，函数不执行任何操作。
- 当p已经被释放之后，再次释放会出现乱七八糟的效果。
- 除了被禁用(mallopt)的情况下，当释放很大的内存空间时，程序会将这些内存空间还给系统，以便于减小程序所使用的内存空间。

### 内存分配背后的系统调用

在我们前面提到的函数中，无论是malloc函数还是free函数，我们都是直接在程序中可以使用的，说明它们是标准库函数。但是它们并不是真正与系统交互的函数。

这些函数背后的系统调用主要是[(s)brk](http://man7.org/linux/man-pages/man2/sbrk.2.html)函数以及[mmap,munmap](http://man7.org/linux/man-pages/man2/mmap.2.html)函数，如下图所示，我们主要考虑对堆进行申请内存块的操作。

![](/pwn/heap/figure/brk&mmap.png)

#### (s)brk

对于堆的操作，操作系统内部提供了brk函数，glibc库提供了sbrk函数，我们可以通过增加[brk](http://elixir.free-electrons.com/linux/v3.8/source/include/linux/mm_types.h#L365)(program break location, the program break is the address of the first location beyond the current end of the data region. https://en.wikipedia.org/wiki/Sbrk)的大小来向操作系统申请内存。

初始时，堆的起始地址[start_brk](http://elixir.free-electrons.com/linux/v3.8/source/include/linux/mm_types.h#L365) 以及堆的当前末尾[brk](http://elixir.free-electrons.com/linux/v3.8/source/include/linux/mm_types.h#L365) 指向同一地址，根据是否开启ASLR，情况会有所不同

- 当不开启ASLR保护时，start_brk以及brk会指向data/bss 段的结尾。
- 当开启ASLR保护时，start_brk以及brk也会指向同一位置，只是这个位置是在data/bss段结尾后的随机偏移处。

具体效果如下图（这个图片与网上流传的基本一致，这里是因为要画一张大图，所以自己单独画了下）所示

![](/pwn/heap/figure/program_virtual_address_memory_space.png)

**例子**

```c
/* sbrk and brk example */
##include <stdio.h>
##include <unistd.h>
##include <sys/types.h>

int main()
{
        void *curr_brk, *tmp_brk = NULL;

        printf("Welcome to sbrk example:%d\n", getpid());

        /* sbrk(0) gives current program break location */
        tmp_brk = curr_brk = sbrk(0);
        printf("Program Break Location1:%p\n", curr_brk);
        getchar();

        /* brk(addr) increments/decrements program break location */
        brk(curr_brk+4096);

        curr_brk = sbrk(0);
        printf("Program break Location2:%p\n", curr_brk);
        getchar();

        brk(tmp_brk);

        curr_brk = sbrk(0);
        printf("Program Break Location3:%p\n", curr_brk);
        getchar();

        return 0;
}
```

需要注意的是，在每一次执行完操作后，都执行了getchar()函数，这是为了我们方便我们查看程序真正的映射。

**在第一次调用brk之前**

从下面的输出可以看出，并没有出现堆。因此

- start_brk = brk = end_data = 0x804b000

```shell
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ ./sbrk 
Welcome to sbrk example:6141
Program Break Location1:0x804b000
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6141/maps
...
0804a000-0804b000 rw-p 00001000 08:01 539624     /home/sploitfun/ptmalloc.ppt/syscalls/sbrk
b7e21000-b7e22000 rw-p 00000000 00:00 0 
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$
```

**第一次增加brk后**

从下面的输出可以看出，已经出现了堆段

- start_brk = end_data = 0x804b000
- brk = 0x804c000

```shell
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ ./sbrk 
Welcome to sbrk example:6141
Program Break Location1:0x804b000
Program Break Location2:0x804c000
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6141/maps
...
0804a000-0804b000 rw-p 00001000 08:01 539624     /home/sploitfun/ptmalloc.ppt/syscalls/sbrk
0804b000-0804c000 rw-p 00000000 00:00 0          [heap]
b7e21000-b7e22000 rw-p 00000000 00:00 0 
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$
```

其中，关于堆的那一行

- 0x0804b000 是相应堆的起始地址
- rw-p表明堆具有可读可写权限，并且属于隐私数据。
- 00000000 表明文件偏移，由于这部分内容并不是从文件中映射得到的，所以为0。
- 00:00 是主从(Major/mirror)的设备号，这部分内容也不是从文件中映射得到的，所以也都为0。
- 0表示着Inode 号。由于这部分内容并不是从文件中映射得到的，所以为0。

#### mmap

malloc会使用 [mmap](http://lxr.free-electrons.com/source/mm/mmap.c?v=3.8#L1285)来创建隐私的匿名映射段。匿名映射的目的主要是可以申请以0填充的内存，并且这块内存仅被调用进程所使用。

**例子**

```c++
/* Private anonymous mapping example using mmap syscall */
##include <stdio.h>
##include <sys/mman.h>
##include <sys/types.h>
##include <sys/stat.h>
##include <fcntl.h>
##include <unistd.h>
##include <stdlib.h>

void static inline errExit(const char* msg)
{
        printf("%s failed. Exiting the process\n", msg);
        exit(-1);
}

int main()
{
        int ret = -1;
        printf("Welcome to private anonymous mapping example::PID:%d\n", getpid());
        printf("Before mmap\n");
        getchar();
        char* addr = NULL;
        addr = mmap(NULL, (size_t)132*1024, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr == MAP_FAILED)
                errExit("mmap");
        printf("After mmap\n");
        getchar();

        /* Unmap mapped region. */
        ret = munmap(addr, (size_t)132*1024);
        if(ret == -1)
                errExit("munmap");
        printf("After munmap\n");
        getchar();
        return 0;
}
```

**在执行mmap之前**

我们可以从下面的输出看到，目前只有.so文件的mmap段。

```shell
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6067/maps
08048000-08049000 r-xp 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
08049000-0804a000 r--p 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
0804a000-0804b000 rw-p 00001000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
b7e21000-b7e22000 rw-p 00000000 00:00 0 
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$
```

**mmap后**

从下面的输出可以看出，我们申请的内存与已经存在的内存段结合在了一起构成了b7e00000到b7e21000的mmap段。

```shell
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6067/maps
08048000-08049000 r-xp 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
08049000-0804a000 r--p 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
0804a000-0804b000 rw-p 00001000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
b7e00000-b7e22000 rw-p 00000000 00:00 0 
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$
```

**munmap**

从下面的输出，我们可以看到我们原来申请的内存段已经没有了，内存段又恢复了原来的样子了。

```shell
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6067/maps
08048000-08049000 r-xp 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
08049000-0804a000 r--p 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
0804a000-0804b000 rw-p 00001000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
b7e21000-b7e22000 rw-p 00000000 00:00 0 
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$
```

### 多线程支持

在原来的dlmalloc实现中，当两个线程同时要申请内存时，只有一个线程可以进入临界区申请内存，而另外一个线程则必须等待直到临界区中不再有线程。这是因为所有的线程共享一个堆。在glibc的ptmalloc实现中，比较好的一点就是支持了多线程的快速访问。在新的实现中，所有的线程共享多个堆。

这里给出一个例子。

```c++
/* Per thread arena example. */
##include <stdio.h>
##include <stdlib.h>
##include <pthread.h>
##include <unistd.h>
##include <sys/types.h>

void* threadFunc(void* arg) {
        printf("Before malloc in thread 1\n");
        getchar();
        char* addr = (char*) malloc(1000);
        printf("After malloc and before free in thread 1\n");
        getchar();
        free(addr);
        printf("After free in thread 1\n");
        getchar();
}

int main() {
        pthread_t t1;
        void* s;
        int ret;
        char* addr;

        printf("Welcome to per thread arena example::%d\n",getpid());
        printf("Before malloc in main thread\n");
        getchar();
        addr = (char*) malloc(1000);
        printf("After malloc and before free in main thread\n");
        getchar();
        free(addr);
        printf("After free in main thread\n");
        getchar();
        ret = pthread_create(&t1, NULL, threadFunc, NULL);
        if(ret)
        {
                printf("Thread creation error\n");
                return -1;
        }
        ret = pthread_join(t1, &s);
        if(ret)
        {
                printf("Thread join error\n");
                return -1;
        }
        return 0;
}
```

**第一次申请之前**， 没有任何任何堆段。

```shell
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
b7e05000-b7e07000 rw-p 00000000 00:00 0 
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$
```

**第一次申请后**， 从下面的输出可以看出，堆段被建立了，并且它就紧邻着数据段，这说明malloc的背后是用brk函数来实现的。同时，需要注意的是，我们虽然只是申请了1000个字节，但是我们却得到了0x0806c000-0x0804b000=0x21000个字节的堆。**这说明虽然程序可能只是向操作系统申请很小的内存，但是为了方便，操作系统会把很大的内存分配给程序。这样的话，就避免了多次内核态与用户态的切换，加快了程序的效率。**我们称这一块连续的内存区域为arena。此外，由于这块内存是由主线程申请的，所以我们称之为main_arena。对于后续的申请的内存会一直从这个arena中获取，直到空间不足。当出现arena空间不足时，它可以通过增加brk的方式来增加堆的空间。类似地，arena也可以通过减小brk来缩小自己的空间。

```shell
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
...
sploitfun@sploitfun-VirtualBox:~/lsploits/hof/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7e05000-b7e07000 rw-p 00000000 00:00 0 
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$
```

**在主线程释放内存后**，我们从下面的输出可以看出，其对应的arena并没有进行回收，而是交由glibc来进行管理。当后面程序再次申请内存时，在glibc中管理的内存充足的情况下，glibc就会根据堆分配的算法来给程序分配相应的内存。

```shell
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
After free in main thread
...
sploitfun@sploitfun-VirtualBox:~/lsploits/hof/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7e05000-b7e07000 rw-p 00000000 00:00 0 
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$
```

**在第一个线程malloc之前**，我们可以看到并没有出现与线程1相关的堆，但是出现了与线程1相关的栈。

```shell
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
After free in main thread
Before malloc in thread 1
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7604000-b7605000 ---p 00000000 00:00 0 
b7605000-b7e07000 rw-p 00000000 00:00 0          [stack:6594]
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$
```

**第一个线程malloc后**， 我们可以从下面输出看出线程1的堆段被建立了。而且它所在的位置为内存映射段区域，同样大小也是132KB(b7500000-b7521000)。因此这表明该线程申请的堆时，背后对应的函数为mmap函数。同时，我们可以看出实际真的分配给程序的内存为1M(b7500000-b7600000)。而且，只有132KB的部分具有可读可写权限，这一块连续的区域成为thread arena。

注意：

> 当用户请求的内存大于128KB时，并且没有任何arena有足够的空间时，那么系统就会执行mmap函数来分配相应的内存空间。这与这个请求来自于主线程还是从线程无关。

```shell
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
After free in main thread
Before malloc in thread 1
After malloc and before free in thread 1
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7500000-b7521000 rw-p 00000000 00:00 0 
b7521000-b7600000 ---p 00000000 00:00 0 
b7604000-b7605000 ---p 00000000 00:00 0 
b7605000-b7e07000 rw-p 00000000 00:00 0          [stack:6594]
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$
```

**在第一个线程释放内存后**， 我们可以从下面的输出看到，这样释放内存同样不会把内存重新给系统。

```shell
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
After free in main thread
Before malloc in thread 1
After malloc and before free in thread 1
After free in thread 1
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7500000-b7521000 rw-p 00000000 00:00 0 
b7521000-b7600000 ---p 00000000 00:00 0 
b7604000-b7605000 ---p 00000000 00:00 0 
b7605000-b7e07000 rw-p 00000000 00:00 0          [stack:6594]
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$
```

