# 堆溢出

## 介绍

堆溢出是指程序向某个堆块中写入的字节数超过了堆块本身可使用的字节数（**之所以是可使用而不是用户申请的字节数，是因为堆管理器会对用户所申请的字节数进行调整，这也导致可利用的字节数都不小于用户申请的字节数**），因而导致了数据溢出，并覆盖到**物理相邻的高地址**的下一个堆块。

不难发现，堆溢出漏洞发生的基本前提是

- 程序向堆上写入数据。
- 写入的数据大小没有被良好地控制。

对于攻击者来说，堆溢出漏洞轻则可以使得程序崩溃，重则可以使得攻击者控制程序执行流程。

堆溢出是一种特定的缓冲区溢出（还有栈溢出， bss 段溢出等)。但是其与栈溢出所不同的是，堆上并不存在返回地址等可以让攻击者直接控制执行流程的数据，因此我们一般无法直接通过堆溢出来控制 EIP 。一般来说，我们利用堆溢出的策略是

1.  覆盖与其**物理相邻的下一个 chunk** 的内容。
    -   prev_size
    -   size，主要有三个比特位，以及该堆块真正的大小。
        -   NON_MAIN_ARENA 
        -   IS_MAPPED  
        -   PREV_INUSE 
        -   the True chunk size
    -   chunk content，从而改变程序固有的执行流。
2.  利用堆中的机制（如 unlink 等 ）来实现任意地址写入（ Write-Anything-Anywhere）或控制堆块中的内容等效果，从而来控制程序的执行流。

## 基本示例

下面我们举一个简单的例子：

```
#include <stdio.h>

int main(void) 
{
  char *chunk;
  chunk=malloc(24);
  puts("Get input:");
  gets(chunk);
  return 0;
}
```

这个程序的主要目的是调用 malloc 分配一块堆上的内存，之后向这个堆块中写入一个字符串，如果输入的字符串过长会导致溢出 chunk 的区域并覆盖到其后的 top chunk 之中(实际上 puts 内部会调用 malloc 分配堆内存，覆盖到的可能并不是 top chunk)。
```
0x602000:	0x0000000000000000	0x0000000000000021 <===chunk
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000020fe1 <===top chunk
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
```
print 'A'*100
进行写入
```
0x602000:	0x0000000000000000	0x0000000000000021 <===chunk
0x602010:	0x4141414141414141	0x4141414141414141
0x602020:	0x4141414141414141	0x4141414141414141 <===top chunk(已被溢出)
0x602030:	0x4141414141414141	0x4141414141414141
0x602040:	0x4141414141414141	0x4141414141414141
```


## 小总结

堆溢出中比较重要的几个步骤:

### 寻找堆分配函数
通常来说堆是通过调用 glibc 函数 malloc 进行分配的，在某些情况下会使用 calloc 分配。calloc 与 malloc 的区别是 **calloc 在分配后会自动进行清空，这对于某些信息泄露漏洞的利用来说是致命的**。

```
calloc(0x20);
//等同于
ptr=malloc(0x20);
memset(ptr,0,0x20);
```
除此之外，还有一种分配是经由 realloc 进行的，realloc 函数可以身兼 malloc 和 free 两个函数的功能。
```
#include <stdio.h>

int main(void) 
{
  char *chunk,*chunk1;
  chunk=malloc(16);
  chunk1=realloc(chunk,32);
  return 0;
}
```
realloc的操作并不是像字面意义上那么简单，其内部会根据不同的情况进行不同操作

-   当realloc(ptr,size)的size不等于ptr的size时
    -   如果申请size>原来size
        -   如果chunk与top chunk相邻，直接扩展这个chunk到新size大小
        -   如果chunk与top chunk不相邻，相当于free(ptr),malloc(new_size) 
    -   如果申请size<原来size
        -   如果相差不足以容得下一个最小chunk(64位下32个字节，32位下16个字节)，则保持不变
        -   如果相差可以容得下一个最小chunk，则切割原chunk为两部分，free掉后一部分
-   当realloc(ptr,size)的size等于0时，相当于free(ptr)
-   当realloc(ptr,size)的size等于ptr的size，不进行任何操作

### 寻找危险函数
通过寻找危险函数，我们快速确定程序是否可能有堆溢出，以及有的话，堆溢出的位置在哪里。

常见的危险函数如下

-   输入
    -   gets，直接读取一行，忽略 `'\x00'`
    -   scanf
    -   vscanf
-   输出
    -   sprintf
-   字符串
    -   strcpy，字符串复制，遇到 `'\x00'` 停止
    -   strcat，字符串拼接，遇到 `'\x00'` 停止
    -   bcopy

### 确定填充长度
这一部分主要是计算**我们开始写入的地址与我们所要覆盖的地址之间的距离**。
一个常见的误区是malloc的参数等于实际分配堆块的大小，但是事实上 ptmalloc 分配出来的大小是对齐的。这个长度一般是字长的2倍，比如32位系统是8个字节，64位系统是16个字节。但是对于不大于2倍字长的请求，malloc会直接返回2倍字长的块也就是最小chunk，比如64位系统执行`malloc(0)`会返回用户区域为16字节的块。

```
#include <stdio.h>

int main(void) 
{
  char *chunk;
  chunk=malloc(0);
  puts("Get input:");
  gets(chunk);
  return 0;
}
```

```
//根据系统的位数，malloc会分配8或16字节的用户空间
0x602000:	0x0000000000000000	0x0000000000000021
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000020fe1
0x602030:	0x0000000000000000	0x0000000000000000
```
注意用户区域的大小不等于 chunk_hear.size，chunk_hear.size=用户区域大小+2*字长

还有一点是之前所说的用户申请的内存大小会被修改，其有可能会使用与其物理相邻的下一个chunk的prev_size字段储存内容。回头再来看下之前的示例代码
```
#include <stdio.h>

int main(void) 
{
  char *chunk;
  chunk=malloc(24);
  puts("Get input:");
  gets(chunk);
  return 0;
}
```
观察如上代码，我们申请的chunk大小是24个字节。但是我们将其编译为64位可执行程序时，实际上分配的内存会是16个字节而不是24个。
```
0x602000:	0x0000000000000000	0x0000000000000021
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000020fe1
```
16个字节的空间是如何装得下24个字节的内容呢？答案是借用了下一个块的pre_size域。我们可来看一下用户申请的内存大小与glibc中实际分配的内存大小之间的转换。

```c
/* pad request bytes into a usable size -- internal version */
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define request2size(req)                                                      \
    (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)                           \
         ? MINSIZE                                                             \
         : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
```

当req=24时，request2size(24)=32。而除去chunk 头部的16个字节。实际上用户可用chunk的字节数为16。而根据我们前面学到的知识可以知道chunk的pre_size仅当它的前一块块处于释放状态时才起作用。所以用户这时候其实还可以使用下一个chunk的prev_size字段，正好24个字节。**实际上 ptmalloc 分配内存是以双字为基本单位，以64位系统为例，分配出来的空间是16的整数倍，即用户申请的chunk都是16字节对齐的。**