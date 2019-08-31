[EN](./leak_heap.md) | [ZH](./leak_heap-zh.md)
# Information leakage through the heap


## What is information leakage?
In the CTF, the Pwn topic is generally run on a remote server. Therefore, we can not know the address information such as libc.so address and Heap base address on the server, but these addresses are often needed when utilizing, and information leakage is required.


## Information leakage target
What are the targets of information leakage? We can know this by observing the memory space.


```

Start              End                Offset             Perm Path

0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/pwn

0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/pwn

0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/pwn

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

First, the first one is the base address of the main module, because the base address of the main module will change only when the PIE (address-independent code) is turned on. Therefore, the address of the main module does not need to be leaked normally.
The second is the heap address. The heap address is changed for each process. For example, when you need to control the data in the heap, you may need to leak the base address first.
The third is the address of libc.so. In many cases, we can only implement code execution through functions such as system in libc, and structures such as malloc_hook, one_gadgets, and IO_FILE are also stored in libc, so the address of libc is also leaked. The goal.


## By what to leak
Through the previous knowledge, we know that the heap is divided into unsorted bin, fastbin, smallbin, large bin, etc. We examine these structures one by one to see how to leak.


## unsorted bin

We construct two unsorted bins and look at its memory. Now there are two blocks in the unsorted bin list. The address of the first block is 0x602000 and the address of the second block is 0x6020f0.


```

0x602000:	0x0000000000000000	0x00000000000000d1

0x602010: 0x00007ffff7dd1b78 0x00000000006020f0 &lt;=== points to the next block
0x602020:	0x0000000000000000	0x0000000000000000

0x602030:	0x0000000000000000	0x0000000000000000

```



```

0x6020f0:	0x0000000000000000	0x00000000000000d1

0x602100: 0x0000000000602000 0x00007ffff7dd1b78 &lt;=== pointing to main_arena
0x602110:	0x0000000000000000	0x0000000000000000

0x602120:	0x0000000000000000	0x0000000000000000

```

So we know that through the unsorted bin we can get the address of a certain heap block and the address of main_areana. Once the address of a heap block is obtained, it can be calculated by the size of malloc to obtain the heap base address. Once the address of main_arena is obtained, since main_arena exists in libc.so, the offset can be calculated to get the base address of libc.so.
Therefore, through the unsorted bin, you can get: 1. The base address of 1.libc.so 2. Heap base address


## fastbin

We constructed two fastbins and looked at their memory. Now there are two blocks in the fastbin list. The address of the first block is 0x602040 and the address of the second block is 0x602000.


```

0x602000:	0x0000000000000000	0x0000000000000021

0x602010:	0x0000000000000000	0x0000000000000000

```



```

0x602040:	0x0000000000000000	0x0000000000000021

0x602050: 0x0000000000602000 0x0000000000000000 &lt;=== points to the first block
```

According to the previous knowledge, we know that the block fd field at the end of the fastbin list is 0, after which the fd field of each block points to the previous block. Therefore, only the base address of the heap can be leaked by fastbin.


## smallbin

We constructed two fastbins and looked at their memory. Now there are two blocks in the fastbin list. The address of the first block is 0x602000 and the address of the second block is 0x6020f0.
```

0x602000:	0x0000000000000000	0x00000000000000d1

0x602010: 0x00007ffff7dd1c38 0x00000000006020f0 &lt;=== Address of the next block
0x602020:	0x0000000000000000	0x0000000000000000

0x602030:	0x0000000000000000	0x0000000000000000

```



```

0x6020f0:	0x0000000000000000	0x00000000000000d1

0x602100: 0x0000000000602000 0x00007ffff7dd1c38 &lt;=== address of main_arena
0x602110:	0x0000000000000000	0x0000000000000000

0x602120:	0x0000000000000000	0x0000000000000000

```

Therefore, through the smallbin can get: 1.libc.so base address 2.heap base address


## Which vulnerabilities can be used for leaks
Through the previous knowledge, we can know what address information exists in the heap, but to obtain these addresses, we need to implement the vulnerability.
Generally speaking, the following vulnerabilities are available for information vulnerabilities.


* heap memory is not initialized
* Heap overflow
* Use-After-Free

* Cross-border reading
* heap extend 



# ## 0x01 read UAF


By, UAF, leaking heapbase:


```c

p0 = malloc(0x20);

p1 = malloc(0x20);



free(p0);

free(p1);

    

printf('heap base:%p',*p1);

```



Due to the nature of the fastbin list, when we construct a fastbin list


```bash

(0x30)     fastbin[1]: 0x602030 --> 0x602000 --> 0x0

```



There is a phenomenon of chunk 1 -&gt; chunk 0. If the UAF vulnerability exists at this time, we can print the address of chunk 0 through show chunk 1.






Similarly, leaking libc base


```c

p0 = malloc(0x100);

free(p0);

printf("libc: %p\n", *p0);


```







### 0x02  overlapping chunks











### 0x03 Partial Overwrite







### 0x04 Relative Write