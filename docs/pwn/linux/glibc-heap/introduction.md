[EN](./introduction.md) | [ZH](./introduction-zh.md)
#堆利用


In this chapter, we will follow the steps below


1. Introducing the macro operation of the heap we know well about dynamic memory allocation
2. Describe the data structures used to achieve these operations
3. Introduce the specific operations of using these data structures to achieve heap allocation and recycling
4. Introduce the various utilization techniques of the heap from shallow to deep.


For different applications, due to the different memory requirements, there are many implementations of the heap, as follows:


```text

dlmalloc  – General purpose allocator

ptmalloc2 – glibc

jemalloc  – FreeBSD and Firefox

tcmalloc  – Google

libumem - Solaris
```



Here we mainly introduce the implementation of the heap in glibc. If there is time later, it will continue to introduce the implementation of other heaps and their utilization.


The main reference materials in this section are as follows. There are many contents in the text that will be consistent with the reference materials, and will not be explained in the future.


- [black hat heap exploitation](https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf)

- [github heap exploition](https://heap-exploitation.dhavalkapil.com/)

- [sploitfun](https://sploitfun.wordpress.com/archives/)

- glibc source code
- For more references, please see the files in the ref directory.

