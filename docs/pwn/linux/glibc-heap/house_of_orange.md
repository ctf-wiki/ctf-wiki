[EN](./house_of_orange.md) | [ZH](./house_of_orange-zh.md)
# House of Orange





## Introduction
House of Orange differs from other House of XX methods in that it comes from a topic of the same name in Hitcon CTF 2016. Since this method of utilization has not appeared in the previous CTF topic, the use of a series of derivative topics that emerged later is called House of Orange.


## Overview
The use of House of Orange is quite special. First, the target vulnerability is a vulnerability on the heap. But the special thing is that there is no free function or other function that releases the heap block. We know that you generally want to use heap vulnerabilities, you need to perform malloc and free operations on the heap, but you can&#39;t use the free function in House of Orange utilization, so the House of Orange core is free to exploit the exploit.




## Principle
As we mentioned earlier, the core of House of Orange is to get a free unsorted bin without a free function.
The principle of this operation is simply that when the top heap size of the current heap is insufficient to meet the size of the application allocation, the original top chunk will be released and placed in the unsorted bin. This can be done without the free function. Get unsorted bins.


Let&#39;s take a look at the details of this process. Let&#39;s assume that the current top chunk does not meet the allocation requirements of malloc.
First, the `malloc` call in the program will be executed into the `_int_malloc` function of libc.so. In the `_int_malloc` function, we will check whether the fastbin, small bins, unsorted bin, and large bins can meet the allocation requirements. Size issues are not met. Next, the `_int_malloc` function will attempt to use the top chunk, where the top chunk will not meet the allocation requirements, so the following branch will be executed.


```

/*

Otherwise, relay to handle system-dependent cases

*/

else {

void * p = sysmalloc (nb, av);
      if (p != NULL && __builtin_expect (perturb_byte, 0))

	alloc_perturb (p, bytes);

      return p;

}

```



At this point ptmalloc can not meet the user&#39;s request for heap memory operations, you need to execute sysmalloc to apply for more space to the system.
But for the heap there are two distribution methods of mmap and brk, we need to make the heap expand in the form of brk, then the original top chunk will be placed in the unsorted bin.


In summary, we have to implement brk to extend the top chunk, but to achieve this goal we need to bypass some checks in libc.
First, the size of malloc cannot be greater than `mmp_.mmap_threshold`
```

if ((unsigned long)(nb) >= (unsigned long)(mp_.mmap_threshold) && (mp_.n_mmaps < mp_.n_mmaps_max))

```

If the chunk size to be allocated is greater than the mmap allocation threshold, the default is 128K, and the memory block allocated by the current process using mmap() is less than the set maximum value, and the mmap() system call will be used to directly request memory from the operating system.


There is a check for the top chunk size in the sysmalloc function, as follows


```

assert((old_top == initial_top(av) && old_size == 0) ||

	 ((unsigned long) (old_size) >= MINSIZE &&

	  prev_inuse(old_top) &&

	  ((unsigned long)old_end & pagemask) == 0));

```

This checks the legitimacy of the top chunk. If this function is called for the first time, the top chunk may not be initialized, so the old_size may be 0.
If the top chunk has already been initialized, then the size of the top chunk must be greater than or equal to MINSIZE, because the top chunk contains fencepost, so the top chunk must be larger than MINSIZE. Second, the Top chunk must identify that the previous chunk is in the inuse state, and the end chunk&#39;s end address must be page-aligned. In addition, the top chunk removes the fencepost size must be smaller than the required chunk size, otherwise the top chunk will be used to split the chunk in the _int_malloc() function.


Let&#39;s summarize the requirements for forged top chunk size


1. Forged size must be aligned to the memory page


2.size is greater than MINSIZE (0x10)


3.size is smaller than the chunk size + MINSIZE (0x10) applied afterwards


The prev inuse bit of 4.size must be 1


After that, the original top chunk will execute `_int_free` and smoothly enter the unsorted bin.




##example


Here is a sample program that simulates an overflow overlay to the size field of the top chunk. We tried to reduce the size to achieve the brk extension and put the original top chunk into the unsorted bin.


```

#define fake_size 0x41



int main(void)

{

void * ptr;
    

ptr = malloc (0x10);
ptr = (void *) ((int) ptr + 24);
    

    *((long long*)ptr)=fake_size; // overwrite top chunk size

    

    malloc(0x60);

    

    malloc(0x60);

}

```

Here we cover the size of the top chunk as 0x41. Then apply for a heap larger than this size, which is 0x60.
But when we execute this example, we find that this program can&#39;t be used successfully because the assert is not satisfied and throws an exception.


```

[#0] 0x7ffff7a42428 → Name: __GI_raise(sig=0x6)

[#1] 0x7ffff7a4402a → Name: __GI_abort()

[#2] 0x7ffff7a8a2e8 → Name: __malloc_assert(assertion=0x7ffff7b9e150 "(old_top == initial_top (av) && old_size == 0) || ((unsigned long) (old_size) >= MINSIZE && prev_inuse (old_top) && ((unsigned long) old_end & (pagesize - 1)) == 0)", file=0x7ffff7b9ab85 "malloc.c", line=0x95a, function=0x7ffff7b9e998 <__func__.11509> "sysmalloc")

[# 3] 0x7ffff7a8e426 → Name: sysmalloc (nb = 0x70, av = 0x7ffff7dd1b20 <main_arena> )
```





## The correct example


Looking back at the conditions of the assert, we can see that the previously listed entries are satisfied except for the first one.


```

1. Forged size must be aligned to the memory page
```



What is alignment to a memory page? We know that modern operating systems are memory managed in units of memory pages. The size of a typical memory page is 4 kb. Then our forged size must be aligned to this size. The size of the top chunk before the overlay is 20fe1, and it is calculated that 0x602020+0x20fe0=0x623000 is aligned for 0x1000 (4kb).


```

0x602000:	0x0000000000000000	0x0000000000000021

0x602010:	0x0000000000000000	0x0000000000000000

0x602020:	0x0000000000000000	0x0000000000020fe1 <== top chunk

0x602030:	0x0000000000000000	0x0000000000000000

```

Therefore, our fake fake_size can be 0x0fe1, 0x1fe1, 0x2fe1, 0x3fe1, etc. for 4kb aligned size. However, 0x40 does not satisfy the alignment, so it cannot be utilized.


```

#define fake_size 0x1fe1



int main(void)

{

void * ptr;
    

ptr = malloc (0x10);
ptr = (void *) ((int) ptr + 24);
    

    *((long long*)ptr)=fake_size;

    

    malloc(0x2000);

    
    malloc(0x60);

}

```



After the allocation, we can observe that the original heap has passed the brk extension.


```

//The original heap
0x0000000000602000 0x0000000000623000 0x0000000000000000 rw- [heap]



//The extended heap
0x0000000000602000 0x0000000000646000 0x0000000000000000 rw- [heap]

```



Our application was assigned to 0x623010 and the original heap was placed in the unsorted bin


```

[+] unsorted_bins[0]: fw=0x602020, bk=0x602020

 →   Chunk(addr=0x602030, size=0x1fc0, flags=PREV_INUSE)

```



Because there is a block in the unsorted bin, we will cut this block the next time we allocate it.


```

 malloc(0x60);

 0x602030



[+] unsorted_bins[0]: fw=0x602090, bk=0x602090

 →   Chunk(addr=0x6020a0, size=0x1f50, flags=PREV_INUSE)

```



You can see that the allocated memory is cut from the unsorted bin, the memory layout is as follows


```

0x602030: 0x00007ffff7dd2208 0x00007ffff7dd2208 &lt;== Unsorted bin list not cleared
0x602040:	0x0000000000602020	0x0000000000602020

0x602050:	0x0000000000000000	0x0000000000000000

0x602060:	0x0000000000000000	0x0000000000000000

0x602070:	0x0000000000000000	0x0000000000000000

0x602080:	0x0000000000000000	0x0000000000000000

0x602090: 0x0000000000000000 0x0000000000001f51 &lt;== cutting the remaining new unsorted bin
0x6020a0:	0x00007ffff7dd1b78	0x00007ffff7dd1b78

0x6020b0:	0x0000000000000000	0x0000000000000000



```





In fact, the main point of the house of orange is here, after the use of _IO_FILE knowledge, put it in the IO_FILE independent chapter to share.

