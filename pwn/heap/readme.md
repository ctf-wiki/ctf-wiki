# 堆利用

在这个章节中，我们会依次讲解堆的基本结构、堆的分配与回收的机制，以及堆的各种利用技巧。当然，目前关于堆的实现有很多种，具体如下

```text
dlmalloc  – General purpose allocator
ptmalloc2 – glibc
jemalloc  – FreeBSD and Firefox
tcmalloc  – Google
libumem   – Solaris
```

这里我们主要以glibc中堆的实现为主进行介绍。

主要参考的资料如下，很多内容会和这些内容一致，以后就不一一说明了。

- [black hat heap exploitation](https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf)
- [github heap exploition](https://heap-exploitation.dhavalkapil.com/)
- [sploitfun](https://sploitfun.wordpress.com/archives/)
- glibc 源码

