堆利用
======

在该章节中，我们会先给出堆的宏观的操作，然后介绍为了达到这些操作，堆所使用的数据结构，继而进一步介绍堆的内部如何利用这些数据结构来实现堆的分配与回收的操作，最后才会介绍堆的各种利用技巧。

目前关于堆的实现有很多种，具体如下

.. code:: text

    dlmalloc  – General purpose allocator
    ptmalloc2 – glibc
    jemalloc  – FreeBSD and Firefox
    tcmalloc  – Google
    libumem   – Solaris

这里我们主要以glibc中堆的实现为主进行介绍。如果后续有时间，会继续介绍其他堆的实现及其利用。

该部分主要参考的资料如下，文中有很多内容会和参考资料中一致，以后就不一一说明了。

-  `black hat heap
   exploitation <https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf>`__
-  `github heap
   exploition <https://heap-exploitation.dhavalkapil.com/>`__
-  `sploitfun <https://sploitfun.wordpress.com/archives/>`__
-  glibc 源码
-  更多的参考文献请看ref目录下的文件


.. toctree::
   :maxdepth: 2
   :caption: Heap Exploration

   heap_basic_intro.rst
   heap_structure.rst
   heap_implementation_details.rst
   heapoverflow_basic.rst
   off-by-one.rst
   fastbin-attack.rst

