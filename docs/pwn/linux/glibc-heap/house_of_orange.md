# House of Orange


## 介绍
House of Orange与其他的House of XX利用方法不同，这种利用方法来自于Hitcon CTF 2016中的一道同名题目。由于这种利用方法在此前的CTF题目中没有出现过，因此之后出现的一系列衍生题目的利用方法我们称之为House of Orange。

## 概述
House of Orange的利用比较特殊，首先需要目标漏洞是堆上的漏洞但是特殊之处在于题目中不存在free函数或其他释放堆块的函数。我们知道一般想要利用堆漏洞，需要对堆块进行malloc和free操作，但是在House of Orange利用中无法使用free函数，因此House of Orange核心就是通过漏洞利用获得free的效果。


## 原理
如我们前面所述，House of Orange的核心在于在没有free函数的情况下得到一个释放的堆块(unsorted bin)。
这种操作的原理简单来说是当前堆的top chunk尺寸不足以满足申请分配的大小的时候，原来的top chunk会被释放并被置入unsorted bin中，通过这一点可以在没有free函数情况下获取到unsorted bins。

我们来看一下这个过程的详细情况，我们假设目前的top chunk已经不满足malloc的分配需求。
首先我们在程序中的`malloc`调用会执行到libc.so的`_int_malloc`函数中，在`_int_malloc`函数中，会依次检验fastbin、small bins、unsorted bin、large bins是否可以满足分配要求，因为尺寸问题这些都不符合。接下来`_int_malloc`函数会试图使用top chunk，在这里top chunk也不能满足分配的要求，因此会执行如下分支。

```
/*
Otherwise, relay to handle system-dependent cases
*/
else {
      void *p = sysmalloc(nb, av);
      if (p != NULL && __builtin_expect (perturb_byte, 0))
	alloc_perturb (p, bytes);
      return p;
}
```

此时ptmalloc已经不能满足用户申请堆内存的操作，需要执行sysmalloc来向系统申请更多的空间。
但是对于堆来说有mmap和brk两种分配方式，我们需要让堆以brk的形式拓展，之后原有的top chunk会被置于unsorted bin中。

综上，我们要实现brk拓展top chunk，但是要实现这个目的需要绕过一些libc中的check。
首先，malloc的尺寸不能大于`mmp_.mmap_threshold`
```
if ((unsigned long)(nb) >= (unsigned long)(mp_.mmap_threshold) && (mp_.n_mmaps < mp_.n_mmaps_max))
```
如果所需分配的 chunk 大小大于 mmap 分配阈值，默认为 128K，并且当前进程使用 mmap()分配的内存块小于设定的最大值，将使用 mmap()系统调用直接向操作系统申请内存。

在sysmalloc函数中存在对top chunk size的check，如下

```
assert((old_top == initial_top(av) && old_size == 0) ||
	 ((unsigned long) (old_size) >= MINSIZE &&
	  prev_inuse(old_top) &&
	  ((unsigned long)old_end & pagemask) == 0));
```
这里检查了top chunk的合法性，如果第一次调用本函数，top chunk可能没有初始化，所以可能old_size为0。
如果top chunk已经初始化了，那么top chunk的大小必须大于等于MINSIZE，因为top chunk中包含了 fencepost，所以top chunk的大小必须要大于MINSIZE。其次Top chunk必须标识前一个chunk处于inuse状态，并且top chunk的结束地址必定是页对齐的。此外top chunk除去fencepost的大小必定要小于所需chunk的大小，否则在_int_malloc()函数中会使用top chunk分割出chunk。

我们总结一下伪造的top chunk size的要求

1.伪造的size必须要对齐到内存页

2.size要大于MINSIZE(0x10)

3.size要小于之后申请的chunk size + MINSIZE(0x10)

4.size的prev inuse位必须为1

之后原有的top chunk就会执行`_int_free`从而顺利进入unsorted bin中。


## 示例

这里给出了一个示例程序，程序模拟了一个溢出覆盖到top chunk的size域。我们试图把size改小从而实现brk扩展，并把原有的top chunk放入unsorted bin中。

```
#define fake_size 0x41

int main(void)
{
    void *ptr;
    
    ptr=malloc(0x10);
    ptr=(void *)((int)ptr+24);
    
    *((long long*)ptr)=fake_size; // overwrite top chunk size
    
    malloc(0x60);
    
    malloc(0x60);
}
```
这里我们把top chunk的size覆盖为0x41。之后申请大于这个尺寸的堆块，即0x60。
但是当我们执行这个示例时会发现，这个程序并不能利用成功，原因在于assert并没有被满足从而抛出了异常。

```
[#0] 0x7ffff7a42428 → Name: __GI_raise(sig=0x6)
[#1] 0x7ffff7a4402a → Name: __GI_abort()
[#2] 0x7ffff7a8a2e8 → Name: __malloc_assert(assertion=0x7ffff7b9e150 "(old_top == initial_top (av) && old_size == 0) || ((unsigned long) (old_size) >= MINSIZE && prev_inuse (old_top) && ((unsigned long) old_end & (pagesize - 1)) == 0)", file=0x7ffff7b9ab85 "malloc.c", line=0x95a, function=0x7ffff7b9e998 <__func__.11509> "sysmalloc")
[#3] 0x7ffff7a8e426 → Name: sysmalloc(nb=0x70, av=0x7ffff7dd1b20 <main_arena>)
```


## 正确的示例

我们回头来看一下assert的条件，可以发现之前列出的条目都被满足了除了第一条。

```
1.伪造的size必须要对齐到内存页
```

什么是对齐到内存页呢？我们知道现代操作系统都是以内存页为单位进行内存管理的，一般内存页的大小是4kb。那么我们伪造的size就必须要对齐到这个尺寸。在覆盖之前top chunk的size大小是20fe1，通过计算得知0x602020+0x20fe0=0x623000是对于0x1000（4kb）对齐的。

```
0x602000:	0x0000000000000000	0x0000000000000021
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000020fe1 <== top chunk
0x602030:	0x0000000000000000	0x0000000000000000
```
因此我们伪造的fake_size可以是0x0fe1、0x1fe1、0x2fe1、0x3fe1等对4kb对齐的size。而0x40不满足对齐，因此不能实现利用。

```
#define fake_size 0x1fe1

int main(void)
{
    void *ptr;
    
    ptr=malloc(0x10);
    ptr=(void *)((int)ptr+24);
    
    *((long long*)ptr)=fake_size;
    
    malloc(0x2000);
    
    malloc(0x60);
}
```

进行分配之后我们可以观察到原来的堆经过了brk扩展

```
//原有的堆
0x0000000000602000 0x0000000000623000 0x0000000000000000 rw- [heap]

//经过扩展的堆
0x0000000000602000 0x0000000000646000 0x0000000000000000 rw- [heap]
```

我们的申请被分配到0x623010的位置，同时原有的堆被置入unsorted bin

```
[+] unsorted_bins[0]: fw=0x602020, bk=0x602020
 →   Chunk(addr=0x602030, size=0x1fc0, flags=PREV_INUSE)
```

因为unsorted bin中存在块，所以我们一下次的分配会切割这个块

```
 malloc(0x60);
 0x602030

[+] unsorted_bins[0]: fw=0x602090, bk=0x602090
 →   Chunk(addr=0x6020a0, size=0x1f50, flags=PREV_INUSE)
```

可以看到分配的内存是从unsorted bin中切割的，内存布局如下

```
0x602030:	0x00007ffff7dd2208	0x00007ffff7dd2208 <== 未被清零的unsorted bin链表
0x602040:	0x0000000000602020	0x0000000000602020
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000001f51 <== 切割剩下的新unsorted bin
0x6020a0:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x6020b0:	0x0000000000000000	0x0000000000000000

```


其实house of orange的要点正在于此，之后的利用因为涉及到_IO_FILE的知识，放到IO_FILE独立章节分享。

