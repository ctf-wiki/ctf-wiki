.. role:: raw-latex(raw)
   :format: latex
..

House Of Einherjar
==================

介绍
----

house of einherjar 是一种堆利用技术，由 ``Hiroki Matsukuma`` 提出。该堆利用技术可以强制使得 ``malloc`` 返回一个几乎任意地址的 chunk 。其主要在于滥用 ``free``
中的后向合并操作（合并低地址的chunk），从而使得尽可能避免碎片化。

此外，需要注意的是，在一些特殊大小的堆块中，off by one 不仅可以修改下一个堆块的 prev_size，还可以修改下一个堆块的 PREV_INUSE 比特位。

原理
----

后向合并操作
~~~~~~~~~~~~

``free`` 函数中的后向合并核心操作如下

.. code:: c

            /* consolidate backward */
            if (!prev_inuse(p)) {
                prevsize = prev_size(p);
                size += prevsize;
                p = chunk_at_offset(p, -((long) prevsize));
                unlink(av, p, bck, fwd);
            }

这里借用原作者的一张图片说明

|image0|

关于整体的操作，请参考 ``深入理解堆的实现`` 那一章节。

利用原理
~~~~~~~~

这里我们就介绍该利用的原理。首先，在之前的堆的介绍中，我们可以知道以下的知识

-  两个物理相邻的 chunk 会共享 ``prev_size``\ 字段，尤其是当低地址的 chunk 处于使用状态时，高地址的chunk的该字段便可以被低地址的 chunk 使用。因此，我们有希望可以通过写低地址 chunk 覆盖高地址 chunk 的
   ``prev_size`` 字段。
-  一个 chunk PREV_INUSE 位标记了其物理相邻的低地址 chunk 的使用状态，而且该位是和 prev_size 物理相邻的。
-  后向合并时，新的 chunk 的位置取决于 ``chunk_at_offset(p, -((long) prevsize))`` 。

**那么如果我们可以同时控制一个chunk prev_size 与 PREV_INUSE 字段，那么我们就可以将新的 chunk 指向几乎任何位置。**

利用过程
~~~~~~~~

溢出前
^^^^^^

假设溢出前的状态如下

|image1|

溢出
^^^^

这里我们假设 p0 堆块一方面可以写prev_size字段，另一方面，存在off by one的漏洞，可以写下一个 chunk 的PREV_INUSE 部分，那么

|image2|

溢出后
^^^^^^

**假设我们将 p1的 prev_size 字段设置为我们想要的目的 chunk 位置与p1的差值**\ 。在溢出后，我们释放p1，则我们所得到的新的 chunk 的位置 ``chunk_at_offset(p1, -((long) prevsize))`` 就是我们想要的 chunk
位置了。

当然，需要注意的是，由于这里会对新的 chunk 进行 unlink ，因此需要确保在对应 chunk 位置构造好了fake chunk 以便于绕过 unlink 的检测。

|image3|

总结
~~~~

这里我们总结下这个利用技术需要注意的地方

-  需要有溢出漏洞可以写物理相邻的高地址的 prev_size 与 PREV_INUSE 部分。
-  我们需要计算目的 chunk 与 p1 地址之间的差，所以需要泄漏地址。
-  我们需要在目的 chunk 附近构造相应的 fake chunk，从而绕过 unlink 的检测。

例题1-2016 Seccon tinypad
-------------------------

程序基本功能分析
~~~~~~~~~~~~~~~~

通过分析程序，我们不难看出，这个程序的基本功能是操作一个tinypad，主要有以下操作

-  添加
-  删除
-  编辑
-  退出

而与此同时，通过观察添加操作（因为一般只有添加后才可以编辑）

.. code:: c

          if ( cmd != 'A' )
            goto LABEL_43;
          while ( idx <= 3 && *(_QWORD *)&tinypad[16 * (idx + 16LL)] )
            ++idx;
          if ( idx == 4 )
          {
            writeln("No space is left.", 17LL);
          }
          else
          {
            v13 = -1;
            write_n("(SIZE)>>> ", 10LL);
            v13 = read_int();
            if ( v13 <= 0 )
            {
              v5 = 1;
            }
            else
            {
              v5 = v13;
              if ( (unsigned __int64)v13 > 0x100 )
                v5 = 256;
            }
            v13 = v5;
            *(_QWORD *)&tinypad[16 * (idx + 16LL)] = v5;
            *(_QWORD *)&tinypad[16 * (idx + 16LL) + 8] = malloc(v13);

一方面，我们可以发现该 tinypad 最多存储四个；另一方面，我们可以知道，程序只是从 tinypad 起始偏移16*16=256 处才开始使用，每个 tinypad 存储两个字段

-  该 tinypad 的大小
-  该 tinypad 对应的指针

所以我们可以创建一个新的结构体，并修改ida识别的tinypad，使之更加可读。（但是其实ida没有办法帮忙智能识别。）

此外，我们可以看出，用户申请的 chunk 的大小最大为 256 字节，和 tinypad 前面的未使用的 256 字节恰好一致。

漏洞发现
~~~~~~~~

**悬挂指针**

在程序进行 delete 操作时， 虽然对指针进行了 free，但是并没有将指针设置为NULL，这就导致在之后仍然可以使用。

.. code:: c

        if ( cmd == 'D' )                           // delete
        {
          write_n("(INDEX)>>> ", 11LL);
          idx = read_int();
          if ( idx > 0 && idx <= 4 )
          {
            if ( *(_QWORD *)&tinypad[16 * (idx - 1 + 16LL)] )
            {
              free(*(void **)&tinypad[16 * (idx - 1 + 16LL) + 8]);
              *(_QWORD *)&tinypad[16 * (idx - 1 + 16LL)] = 0LL;
              writeln("\nDeleted.", 9LL);
            }
            else
            {
              writeln("Not used", 8LL);
            }
          }
          else
          {
            writeln("Invalid index", 13LL);
          }

**off-by-one**

在程序添加tinypad时，我们可以发现如下代码存在off-by-one漏洞，因为 ``readuntil`` 会在自动填充 :raw-latex:`\x`00。

.. code:: c

            *(_QWORD *)&tinypad[16 * (idx + 16LL)] = v5;
            *(_QWORD *)&tinypad[16 * (idx + 16LL) + 8] = malloc(v13);
            if ( !*(_QWORD *)&tinypad[16 * (idx + 16LL) + 8] )
            {
              writerrln("[!] No memory is available.", 27LL);
              exit(-1);
            }
            write_n("(CONTENT)>>> ", 13LL);
            read_until(*(char **)&tinypad[16 * (idx + 16LL) + 8], v13, 0xAu);
            writeln("\nAdded.", 7LL);

在程序进行edit操作时使用strcpy时均有可能会出现off-by-one漏洞（当原始tinypad大小为256时）

.. code:: c

            if ( *(_QWORD *)&tinypad[16 * (idx - 1 + 16LL)] )
            {
              c = '0';
              strcpy(tinypad, *(const char **)&tinypad[16 * (idx - 1 + 16LL) + 8]);
              while ( toupper(c) != 'Y' )
              {
                write_n("CONTENT: ", 9LL);
                v6 = strlen(tinypad);
                writeln(tinypad, v6);
                write_n("(CONTENT)>>> ", 13LL);
                v7 = strlen(*(const char **)&tinypad[16 * (idx - 1 + 16LL) + 8]);
                read_until(tinypad, v7, 0xAu);
                writeln("Is it OK?", 9LL);
                write_n("(Y/n)>>> ", 9LL);
                read_until((char *)&c, 1uLL, 0xAu);
              }
              strcpy(*(char **)&tinypad[16 * (idx - 1 + 16LL) + 8], tinypad);
              writeln("\nEdited.", 8LL);
            }

参考文献
--------

-  https://www.slideshare.net/codeblue_jp/cb16-matsukuma-en-68459606

.. |image0| image:: /pwn/heap/figure/backward_consolidate.png
.. |image1| image:: /pwn/heap/figure/einherjar_before_overflow.png
.. |image2| image:: /pwn/heap/figure/einherjar_overflowing.png
.. |image3| image:: /pwn/heap/figure/einherjar_after_overflow.png
