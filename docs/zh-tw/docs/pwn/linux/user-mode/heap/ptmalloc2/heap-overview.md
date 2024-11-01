# 堆概述

## 什麼是堆

在程序運行過程中，堆可以提供動態分配的內存，允許程序申請大小未知的內存。堆其實就是程序虛擬地址空間的一塊連續的線性區域，它由低地址向高地址方向增長。我們一般稱管理堆的那部分程序爲堆管理器。

堆管理器處於用戶程序與內核中間，主要做以下工作

1. 響應用戶的申請內存請求，向操作系統申請內存，然後將其返回給用戶程序。同時，爲了保持內存管理的高效性，內核一般都會預先分配很大的一塊連續的內存，然後讓堆管理器通過某種算法管理這塊內存。只有當出現了堆空間不足的情況，堆管理器纔會再次與操作系統進行交互。
2. 管理用戶所釋放的內存。一般來說，用戶釋放的內存並不是直接返還給操作系統的，而是由堆管理器進行管理。這些釋放的內存可以來響應用戶新申請的內存的請求。

Linux 中早期的堆分配與回收由 Doug Lea 實現，但它在並行處理多個線程時，會共享進程的堆內存空間。因此，爲了安全性，一個線程使用堆時，會進行加鎖。然而，與此同時，加鎖會導致其它線程無法使用堆，降低了內存分配和回收的高效性。同時，如果在多線程使用時，沒能正確控制，也可能影響內存分配和回收的正確性。Wolfram Gloger 在 Doug Lea 的基礎上進行改進使其可以支持多線程，這個堆分配器就是 ptmalloc 。在 glibc-2.3.x. 之後，glibc 中集成了ptmalloc2。

目前 Linux 標準發行版中使用的堆分配器是 glibc 中的堆分配器：ptmalloc2。ptmalloc2 主要是通過 malloc/free 函數來分配和釋放內存塊。

需要注意的是，在內存分配與使用的過程中，Linux有這樣的一個基本內存管理思想，**只有當真正訪問一個地址的時候，系統纔會建立虛擬頁面與物理頁面的映射關係**。 所以雖然操作系統已經給程序分配了很大的一塊內存，但是這塊內存其實只是虛擬內存。只有當用戶使用到相應的內存時，系統纔會真正分配物理頁面給用戶使用。

## 堆的基本操作

這裏我們主要介紹

- 基本的堆操作，包括堆的分配，回收，堆分配背後的系統調用
- 介紹堆目前的多線程支持。

### malloc

在 glibc 的[malloc.c](https://github.com/iromise/glibc/blob/master/malloc/malloc.c#L448)中，malloc 的說明如下

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

可以看出，malloc 函數返回對應大小字節的內存塊的指針。此外，該函數還對一些異常情況進行了處理

- 當 n=0 時，返回當前系統允許的堆的最小內存塊。
- 當 n 爲負數時，由於在大多數系統上，**size_t 是無符號數（這一點非常重要）**，所以程序就會申請很大的內存空間，但通常來說都會失敗，因爲系統沒有那麼多的內存可以分配。

### free

在 glibc 的 [malloc.c](https://github.com/iromise/glibc/blob/master/malloc/malloc.c#L465) 中，free 的說明如下

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

可以看出，free 函數會釋放由 p 所指向的內存塊。這個內存塊有可能是通過 malloc 函數得到的，也有可能是通過相關的函數 realloc 得到的。

此外，該函數也同樣對異常情況進行了處理

- **當 p 爲空指針時，函數不執行任何操作。**
- 當 p 已經被釋放之後，再次釋放會出現亂七八糟的效果，這其實就是 `double free`。
- 除了被禁用 (mallopt) 的情況下，當釋放很大的內存空間時，程序會將這些內存空間還給系統，以便於減小程序所使用的內存空間。

### 內存分配背後的系統調用

在前面提到的函數中，無論是 malloc 函數還是 free 函數，我們動態申請和釋放內存時，都經常會使用，但是它們並不是真正與系統交互的函數。這些函數背後的系統調用主要是 [(s)brk](http://man7.org/linux/man-pages/man2/sbrk.2.html) 函數以及 [mmap, munmap](http://man7.org/linux/man-pages/man2/mmap.2.html) 函數。

如下圖所示，我們主要考慮對堆進行申請內存塊的操作。

![](./figure/brk&mmap.png)

#### (s)brk

對於堆的操作，操作系統提供了 brk 函數，glibc 庫提供了 sbrk 函數，我們可以通過增加 [brk](https://en.wikipedia.org/wiki/Sbrk) 的大小來向操作系統申請內存。

初始時，堆的起始地址 [start_brk](http://elixir.free-electrons.com/linux/v3.8/source/include/linux/mm_types.h#L365) 以及堆的當前末尾 [brk](http://elixir.free-electrons.com/linux/v3.8/source/include/linux/mm_types.h#L365) 指向同一地址。根據是否開啓ASLR，兩者的具體位置會有所不同

- 不開啓 ASLR 保護時，start_brk 以及 brk 會指向 data/bss 段的結尾。
- 開啓 ASLR 保護時，start_brk 以及 brk 也會指向同一位置，只是這個位置是在 data/bss 段結尾後的隨機偏移處。

具體效果如下圖（這個圖片與網上流傳的基本一致，這裏是因爲要畫一張大圖，所以自己單獨畫了下）所示

![](./figure/program_virtual_address_memory_space.png)

**例子**

```c
/* sbrk and brk example */
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

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

需要注意的是，在每一次執行完操作後，都執行了getchar()函數，這是爲了我們方便我們查看程序真正的映射。

**在第一次調用brk之前**

從下面的輸出可以看出，並沒有出現堆。因此

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

**第一次增加brk後**

從下面的輸出可以看出，已經出現了堆段

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

其中，關於堆的那一行

- 0x0804b000 是相應堆的起始地址
- rw-p表明堆具有可讀可寫權限，並且屬於隱私數據。
- 00000000 表明文件偏移，由於這部分內容並不是從文件中映射得到的，所以爲0。
- 00:00 是主從(Major/mirror)的設備號，這部分內容也不是從文件中映射得到的，所以也都爲0。
- 0表示着Inode 號。由於這部分內容並不是從文件中映射得到的，所以爲0。

#### mmap

malloc 會使用 [mmap](http://lxr.free-electrons.com/source/mm/mmap.c?v=3.8#L1285)來創建獨立的匿名映射段。匿名映射的目的主要是可以申請以0填充的內存，並且這塊內存僅被調用進程所使用。

**例子**

```c++
/* Private anonymous mapping example using mmap syscall */
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

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

**在執行mmap之前**

我們可以從下面的輸出看到，目前只有.so文件的mmap段。

```shell
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6067/maps
08048000-08049000 r-xp 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
08049000-0804a000 r--p 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
0804a000-0804b000 rw-p 00001000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
b7e21000-b7e22000 rw-p 00000000 00:00 0
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$
```

**mmap後**

從下面的輸出可以看出，我們申請的內存與已經存在的內存段結合在了一起構成了b7e00000到b7e21000的mmap段。

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

從下面的輸出，我們可以看到我們原來申請的內存段已經沒有了，內存段又恢復了原來的樣子了。

```shell
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6067/maps
08048000-08049000 r-xp 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
08049000-0804a000 r--p 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
0804a000-0804b000 rw-p 00001000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
b7e21000-b7e22000 rw-p 00000000 00:00 0
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$
```

### 多線程支持

在原來的 dlmalloc 實現中，當兩個線程同時要申請內存時，只有一個線程可以進入臨界區申請內存，而另外一個線程則必須等待直到臨界區中不再有線程。這是因爲所有的線程共享一個堆。在glibc的ptmalloc實現中，比較好的一點就是支持了多線程的快速訪問。在新的實現中，所有的線程共享多個堆。

這裏給出一個例子。

```c++
/* Per thread arena example. */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>

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

**第一次申請之前**， 沒有任何任何堆段。

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

**第一次申請後**， 從下面的輸出可以看出，堆段被建立了，並且它就緊鄰着數據段，這說明malloc的背後是用brk函數來實現的。同時，需要注意的是，我們雖然只是申請了1000個字節，但是我們卻得到了0x0806c000-0x0804b000=0x21000個字節的堆。**這說明雖然程序可能只是向操作系統申請很小的內存，但是爲了方便，操作系統會把很大的內存分配給程序。這樣的話，就避免了多次內核態與用戶態的切換，提高了程序的效率。**我們稱這一塊連續的內存區域爲 arena。此外，我們稱由主線程申請的內存爲 main_arena。後續的申請的內存會一直從這個 arena 中獲取，直到空間不足。當 arena 空間不足時，它可以通過增加brk的方式來增加堆的空間。類似地，arena 也可以通過減小 brk 來縮小自己的空間。

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

**在主線程釋放內存後**，我們從下面的輸出可以看出，其對應的 arena 並沒有進行回收，而是交由glibc來進行管理。當後面程序再次申請內存時，在 glibc 中管理的內存充足的情況下，glibc 就會根據堆分配的算法來給程序分配相應的內存。

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

**在第一個線程malloc之前**，我們可以看到並沒有出現與線程1相關的堆，但是出現了與線程1相關的棧。

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

**第一個線程malloc後**， 我們可以從下面輸出看出線程1的堆段被建立了。而且它所在的位置爲內存映射段區域，同樣大小也是132KB(b7500000-b7521000)。因此這表明該線程申請的堆時，背後對應的函數爲mmap函數。同時，我們可以看出實際真的分配給程序的內存爲1M(b7500000-b7600000)。而且，只有132KB的部分具有可讀可寫權限，這一塊連續的區域成爲thread arena。

注意：

> 當用戶請求的內存大於128KB時，並且沒有任何arena有足夠的空間時，那麼系統就會執行mmap函數來分配相應的內存空間。這與這個請求來自於主線程還是從線程無關。

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

**在第一個線程釋放內存後**， 我們可以從下面的輸出看到，這樣釋放內存同樣不會把內存重新給系統。

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

## 參考文獻

- [sploitfun](https://sploitfun.wordpress.com/archives/)
