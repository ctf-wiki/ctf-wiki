堆相关数据结构
==============

既然堆的操作本身这么复杂，那么在glibc内部必然也有相应的精妙设计的数据结构来管理它。与堆相应的数据结构主要分为

-  宏观结构，主要说明堆的宏观信息，可以通过这些数据结构来得到堆的一些基本信息。
-  微观结构，主要用于表示在宏观结构下更加细致的结构，一般堆的分配与回收主要是与这些结构进行交流。

Overview？？？？
----------------

**这里给一个宏观的图片。**

宏观结构
--------

arena
~~~~~

正如我们之前所说的，无论是主线程还是新创建的线程来说在第一次申请内存时，都会有自己独立的arena，那么会不会每个线程都有自己的arena呢？下面我们就具体介绍。

arena 数量
^^^^^^^^^^

不是每一个线程都会有对应的arena，这是因为每个系统的核数是有限的，当线程数大于核数的二倍时，就必然有线程处于等待状态。所以没有必要为每个线程分配一个arena的。具体的\ `约束 <https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/arena.c#L847>`__\ 如下

.. code:: text

    For 32 bit systems:
         Number of arena = 2 * number of cores.
    For 64 bit systems:
         Number of arena = 8 * number of cores.

至于为什么64位系统，要那么设置，我也没有想明白。

arena 分配规则
^^^^^^^^^^^^^^

**待补充。**

区别
^^^^

此外，与thread不同的是，main的arena header并不在申请的heap中，它是一个全局变量，在libc.so的数据段。

heap\_info
~~~~~~~~~~

该数据结构是专门为从Memory Mapping Segment处申请的内存准备的。当主线程申请较小的内存空间时，可以通过sbrk()函数扩展program break location获得（直到触及Memory Mapping
Segment），因此主线程只有一个heap，没有heap\_info数据结构。

heap\_info的主要结构如下

.. code:: cpp

    ##define HEAP_MIN_SIZE (32 * 1024)
    ##ifndef HEAP_MAX_SIZE
    ## ifdef DEFAULT_MMAP_THRESHOLD_MAX
    ##  define HEAP_MAX_SIZE (2 * DEFAULT_MMAP_THRESHOLD_MAX)
    ## else
    ##  define HEAP_MAX_SIZE (1024 * 1024) /* must be a power of two */
    ## endif
    ##endif

    /* HEAP_MIN_SIZE and HEAP_MAX_SIZE limit the size of mmap()ed heaps
       that are dynamically created for multi-threaded programs.  The
       maximum size must be a power of two, for fast determination of
       which heap belongs to a chunk.  It should be much larger than the
       mmap threshold, so that requests with a size just below that
       threshold can be fulfilled without creating too many heaps.  */

    /***************************************************************************/

    /* A heap is a single contiguous memory region holding (coalesceable)
       malloc_chunks.  It is allocated with mmap() and always starts at an
       address aligned to HEAP_MAX_SIZE.  */

    typedef struct _heap_info
    {
      mstate ar_ptr; /* Arena for this heap. */
      struct _heap_info *prev; /* Previous heap. */
      size_t size;   /* Current size in bytes. */
      size_t mprotect_size; /* Size in bytes that has been mprotected
                               PROT_READ|PROT_WRITE.  */
      /* Make sure the following data is properly aligned, particularly
         that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
         MALLOC_ALIGNMENT. */
      char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
    } heap_info;

该结构主要是描述堆的基本信息，包括

-  堆对应的heap arena的地址
-  该堆前面的heap\_info的地址，这里可以看到每个堆的heap\_info是通过单向链表进行链接的
-  size表示当前堆的大小
-  最后一部分确保对齐（\ **这里负数使用的缘由是什么呢**\ ？）

看起来该结构应该是相当重要的，但是如果如果我们仔细看完整个malloc的实现的话，就会发现它出现的频率并不高。

程序刚开始执行时，每个线程是没有heap区域的。当其申请内存时，就需要一个结构来记录对应的信息，而heap\_info的作用就是这个。而且当该heap的资源被使用完后，就必须得再次申请heap了。此外，一般申请的heap是不连续的，因此需要记录不同heap之间的链接结构。

malloc\_state
~~~~~~~~~~~~~

该结构用于管理堆，记录每个arena当前的申请内存的具体状态，比如说有什么大小的空闲chunk，如何快速判断有没有什么大小的空闲的chunk。无论是对于thread arena还是说main arena，它们都只有一个malloc
state结构。由于thread的arena可能有多个，malloc state结构会在最新申请的arena中。

**注意，main arena的malloc\_state并不是heap segment的一部分，而是一个全局变量，存储在libc.so的数据段。**

其结构如下

.. code:: cpp

    struct malloc_state {
        /* Serialize access.  */
        __libc_lock_define(, mutex);

        /* Flags (formerly in max_fast).  */
        int flags;

        /* Fastbins */
        mfastbinptr fastbinsY[ NFASTBINS ];

        /* Base of the topmost chunk -- not otherwise kept in a bin */
        mchunkptr top;

        /* The remainder from the most recent split of a small request */
        mchunkptr last_remainder;

        /* Normal bins packed as described above */
        mchunkptr bins[ NBINS * 2 - 2 ];

        /* Bitmap of bins, help to speed up the process of determinating if a given bin is definitely empty.*/
        unsigned int binmap[ BINMAPSIZE ];

        /* Linked list, points to the next arena */
        struct malloc_state *next;

        /* Linked list for free arenas.  Access to this field is serialized
           by free_list_lock in arena.c.  */
        struct malloc_state *next_free;

        /* Number of threads attached to this arena.  0 if the arena is on
           the free list.  Access to this field is serialized by
           free_list_lock in arena.c.  */
        INTERNAL_SIZE_T attached_threads;

        /* Memory allocated from the system in this arena.  */
        INTERNAL_SIZE_T system_mem;
        INTERNAL_SIZE_T max_system_mem;
    };

-  ​ \_\_libc\_lock\_define(, mutex);
-  该变量用于控制程序串行化访问同一个分配区，当一个线程获取了分配区之后，其它线程要想访问该分配区，就必须等待该线程分配完成候才能够使用。
-  flags
-  flags记录了分配区的一些标志，比如说bit0 记录了分配区是否有fast bin chunk，bit1标识分配区是否能返回连续的虚拟地址空间。
-  fastbinsY[ NFASTBINS ]
-  存放每个fast chunk链表头部的指针
-  top
-  指向分配区的top chunk
-  last\_reminder
-  一个chunk分割之后剩下的那部分
-  bins
-  用于存储unstored bin，small bins和large bins的chunk链表。
-  binmap
-  ptmalloc用一个bit来标识该bit对应的bin中是否包含空闲chunk。

关于其中每一个变量的具体意思，我们会在使用到的时候进行详细地说明。

malloc\_par
~~~~~~~~~~~

**待补充**

微观结构
--------

上面的结构就是堆的宏观结构，下面就是堆中比较细节的结构了，\ **关于堆的利用主要是集中在这些结构中**\ 。

malloc\_chunk
~~~~~~~~~~~~~

概述
^^^^

在程序的使用过程中，我们称由malloc申请的内存为chunk。该块内存在ptmalloc内部用malloc\_chunk结构体来表示。该chunk被free后会被加入到对应的管理列表中。非常有意思的是，\ **ptmalloc2中使用了一个统一的结构来实现chunk，无论一个chunk的大小如何，处于分配状态或者释放状态，它们所使用的数据结构相同**\ 。需要注意的是，虽然它们使用了同一个数据结构，但是根据是否被释放，它们的表现形式会有所不同。

malloc\_chunk的结构如下

.. code:: cpp

    /*
      This struct declaration is misleading (but accurate and necessary).
      It declares a "view" into memory allowing access to necessary
      fields at known offsets from a given base. See explanation below.
    */
    struct malloc_chunk {

      INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
      INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

      struct malloc_chunk* fd;         /* double links -- used only if free. */
      struct malloc_chunk* bk;

      /* Only used for large blocks: pointer to next larger size.  */
      struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
      struct malloc_chunk* bk_nextsize;
    };

具体的，每个字段的解释如下

-  **prev\_size**,
   如果该chunk的\ **物理相邻（即两个指针的地址的差值为chunk大小）的前一chunk**\ 是空闲的话，那该字段记录的是前一个chunk的大小(包括chunk头)。否则，该字段可以用来存储上一个chunk的数据。这里的前一chunk指的是较低地址的chunk。
-  **size** ，该chunk的大小，大小必须是8（32位）的整数倍。如果申请的大小不是8的整数倍，会被转换满足大小的最小的8的倍数。该字段的最低的三个比特位从高到低分别表示
-  NON\_MAIN\_ARENA 记录当前chunk是否不属于主线程，1表示不属于，0表示属于。
-  IS\_MAPPED 记录当前chunk是否是由mmap分配的。
-  PREV\_INUSE
   记录前一个chunk块是否被分配。一般来说，堆中第一个被分配的内存块的size字段的P位都会被设置为1，以便于防止访问前面的非法内存。而且，当一个chunk的size的P位为0时，我们能通过prev\_size字段来获取上一个chunk的地址。这也方便进行空闲chunk之间的合并。
-  **fd,bk**\ 。 chunk处于分配状态时，从fd字段开始是用户的数据，否则chunk空闲时，其字段的含义如下
-  fd指向下一个（非物理相邻）空闲的chunk
-  bk指向上一个（非物理相邻）空闲的chunk
-  通过fd和bk可以将空闲的chunk块加入到空闲的chunk块链表进行统一管理
-  **fd\_nextsize, bk\_nextsize**\ ，也是只有chunk空闲的时候才使用，不过其用于较大的chunk（large chunk）。
-  fd\_nextsize指向前一个与当前chunk大小不同的第一个空闲块，不包含bin的头指针（可暂不考虑）。
-  bk\_nextsize指向后一个与当前chunk大小不同的第一个空闲块，不包含bin的头指针（可暂不考虑）。
-  **这样做可以避免在寻找合适chunk时挨个遍历。**

一个已经分配的chunk的样子如下。\ **我们称前两个字段称为chunk header，后面的部分称为user data。每次malloc申请得到的内存指针，其实指向user data的起始处。**

当一个chunk处于使用状态时，它的下一个chunk的prev\_size域无效，所以下一个chunk的该部分也可以被当前chunk使用。\ **这就是chunk中的空间复用。**

.. code:: cpp

    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
    next    .                                                               |
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             (size of chunk, but used for application data)    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|1|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

被释放的chunk一般被记录在链表中（可能是循环链表，也可能是单向链表）。具体结构如下

.. code:: cpp

    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                     |A|0|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk in list             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk in list            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space (may be 0 bytes long)                .
            .                                                               .
     next   .                                                               |
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|0|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

我们可以发现，如果一个chunk处于free状态，其实是可能有两个位置记录其相应的大小的，一个是本身的记录，一个是其后一个chunk会记录。而一般来说相邻的两个空闲chunk会被合并为一个chunk，这也恰好加速了两个物理相邻的空闲chunk块的合并速度。

**一些关于堆的约束，后面详细考虑**

.. code:: cpp

    /*
        The three exceptions to all this are:
         1. The special chunk `top' doesn't bother using the
        trailing size field since there is no next contiguous chunk
        that would have to index off it. After initialization, `top'
        is forced to always exist.  If it would become less than
        MINSIZE bytes long, it is replenished.
         2. Chunks allocated via mmap, which have the second-lowest-order
        bit M (IS_MMAPPED) set in their size fields.  Because they are
        allocated one-by-one, each must contain its own trailing size
        field.  If the M bit is set, the other bits are ignored
        (because mmapped chunks are neither in an arena, nor adjacent
        to a freed chunk).  The M bit is also used for chunks which
        originally came from a dumped heap via malloc_set_state in
        hooks.c.
         3. Chunks in fastbins are treated as allocated chunks from the
        point of view of the chunk allocator.  They are consolidated
        with their neighbors only in bulk, in malloc_consolidate.
    */

chunk相关宏
^^^^^^^^^^^

这里主要介绍关于chunk的大小、对齐检查以及一些转换的宏代码。

**chunk与mem指针头部的转换**

.. code:: cpp

    /* conversion from malloc headers to user pointers, and back */

    ##define chunk2mem(p) ((void *) ((char *) (p) + 2 * SIZE_SZ))
    ##define mem2chunk(mem) ((mchunkptr)((char *) (mem) -2 * SIZE_SZ))

**最小可能的chunk**

.. code:: cpp

    /* The smallest possible chunk */
    ##define MIN_CHUNK_SIZE (offsetof(struct malloc_chunk, fd_nextsize))

这里，offsetof函数计算出fd\_nextsize在malloc\_chunk中的偏移，这说明，最小的chunk至少要包含到bk指针。

**最小申请的堆内存大小**

.. code:: cpp

    /* The smallest size we can malloc is an aligned minimal chunk */

    ##define MINSIZE                                                                \
        (unsigned long) (((MIN_CHUNK_SIZE + MALLOC_ALIGN_MASK) &                   \
                          ~MALLOC_ALIGN_MASK))

**检查分配给用户的内存与本身的chunk是否对齐**

.. code:: cpp

    /* Check if m has acceptable alignment */

    ##define aligned_OK(m) (((unsigned long) (m) & MALLOC_ALIGN_MASK) == 0)

    ##define misaligned_chunk(p)                                                    \
        ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem(p)) &       \
         MALLOC_ALIGN_MASK)

**请求字节数判断**

.. code:: cpp

    /*
       Check if a request is so large that it would wrap around zero when
       padded and aligned. To simplify some other code, the bound is made
       low enough so that adding MINSIZE will also not wrap around zero.
     */

    ##define REQUEST_OUT_OF_RANGE(req)                                              \
        ((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE))

**将用户请求内存大小转为实际分配大小**

.. code:: cpp

    /* pad request bytes into a usable size -- internal version */
    //MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
    ##define request2size(req)                                                      \
        (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)                           \
             ? MINSIZE                                                             \
             : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

    /*  Same, except also perform argument check */

    ##define checked_request2size(req, sz)                                          \
        if (REQUEST_OUT_OF_RANGE(req)) {                                           \
            __set_errno(ENOMEM);                                                   \
            return 0;                                                              \
        }                                                                          \
        (sz) = request2size(req);

当一个chunk处于已分配状态时，它的物理相邻的下一个chunk的prev\_size字段必然是无效的，故而这个字段就可以被当前这个chunk使用。这就是ptmalloc中chunk之间的复用。因此，实际要被分配的内存的大小应该为先添加上存储本chunk的大小字段的字节大小，然后再按照MALLOC的规定进行对齐，这里之所以不需要再加上prev\_size字段所占据的大小，就是可以复用下一个chunk的这一字段作为当前chunk的数据段。除此之外，我们必须得确保chunk实际所能利用的大小至少可以存储prev\_size，size，fd，bk这四个字段，所以我们会将其与MINSIZE进行比较。如果调整后不满足最低要求，那么我们就需要直接分配MINSIZE字节，否则，我们就可以按照之前的计算公式来进行计算。

**标记位相关**

.. code:: cpp

    /* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
    ##define PREV_INUSE 0x1

    /* extract inuse bit of previous chunk */
    ##define prev_inuse(p) ((p)->mchunk_size & PREV_INUSE)

    /* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
    ##define IS_MMAPPED 0x2

    /* check for mmap()'ed chunk */
    ##define chunk_is_mmapped(p) ((p)->mchunk_size & IS_MMAPPED)

    /* size field is or'ed with NON_MAIN_ARENA if the chunk was obtained
       from a non-main arena.  This is only set immediately before handing
       the chunk to the user, if necessary.  */
    ##define NON_MAIN_ARENA 0x4

    /* Check for chunk from main arena.  */
    ##define chunk_main_arena(p) (((p)->mchunk_size & NON_MAIN_ARENA) == 0)

    /* Mark a chunk as not being on the main arena.  */
    ##define set_non_main_arena(p) ((p)->mchunk_size |= NON_MAIN_ARENA)

    /*
       Bits to mask off when extracting size
       Note: IS_MMAPPED is intentionally not masked off from size field in
       macros for which mmapped chunks should never be seen. This should
       cause helpful core dumps to occur if it is tried by accident by
       people extending or adapting this malloc.
     */
    ##define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

**获取chunk size**

.. code:: cpp

    /* Get size, ignoring use bits */
    ##define chunksize(p) (chunksize_nomask(p) & ~(SIZE_BITS))

    /* Like chunksize, but do not mask SIZE_BITS.  */
    ##define chunksize_nomask(p) ((p)->mchunk_size)

**获取下一个物理相邻的chunk**

.. code:: cpp

    /* Ptr to next physical malloc_chunk. */
    ##define next_chunk(p) ((mchunkptr)(((char *) (p)) + chunksize(p)))

**获取前一个chunk的信息**

.. code:: cpp

    /* Size of the chunk below P.  Only valid if prev_inuse (P).  */
    ##define prev_size(p) ((p)->mchunk_prev_size)

    /* Set the size of the chunk below P.  Only valid if prev_inuse (P).  */
    ##define set_prev_size(p, sz) ((p)->mchunk_prev_size = (sz))

    /* Ptr to previous physical malloc_chunk.  Only valid if prev_inuse (P).  */
    ##define prev_chunk(p) ((mchunkptr)(((char *) (p)) - prev_size(p)))

**当前chunk使用状态相关操作**

.. code:: cpp

    /* extract p's inuse bit */
    ##define inuse(p)                                                               \
        ((((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size) & PREV_INUSE)

    /* set/clear chunk as being inuse without otherwise disturbing */
    ##define set_inuse(p)                                                           \
        ((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size |= PREV_INUSE

    ##define clear_inuse(p)                                                         \
        ((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size &= ~(PREV_INUSE)

**设置chunk的size字段**

.. code:: cpp

    /* Set size at head, without disturbing its use bit */
    // SIZE_BITS = 7
    ##define set_head_size(p, s)                                                    \
        ((p)->mchunk_size = (((p)->mchunk_size & SIZE_BITS) | (s)))

    /* Set size/use field */
    ##define set_head(p, s) ((p)->mchunk_size = (s))

    /* Set size at footer (only when chunk is not in use) */
    ##define set_foot(p, s)                                                         \
        (((mchunkptr)((char *) (p) + (s)))->mchunk_prev_size = (s))

**获取指定偏移的chunk**

.. code:: cpp

    /* Treat space at ptr + offset as a chunk */
    ##define chunk_at_offset(p, s) ((mchunkptr)(((char *) (p)) + (s)))

**指定偏移处chunk使用状态相关操作**

.. code:: cpp

    /* check/set/clear inuse bits in known places */
    ##define inuse_bit_at_offset(p, s)                                              \
        (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size & PREV_INUSE)

    ##define set_inuse_bit_at_offset(p, s)                                          \
        (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size |= PREV_INUSE)

    ##define clear_inuse_bit_at_offset(p, s)                                        \
        (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size &= ~(PREV_INUSE))

bin
~~~

概述
^^^^

我们曾经说到过，用户释放掉的chunk不会马上归还给系统，ptmalloc会统一管理heap和mmap映射区域中的空闲的chunk。当用户再一次请求分配内存时，ptmalloc分配器会试图在空闲的chunk中挑选一块合适的给用户。这样可以避免频繁的系统调用，降低内存分配的开销。

在具体的实现中，对于空闲的chunk，ptmalloc采用分箱式方法进行管理。首先，它会根据空闲的chunk的大小以及使用状态将chunk进行初步分为4类：fast bins，small bins，large bins，unsorted
bins。每类中仍然有更加细化的划分，相似大小的chunk会用双向链表链接起来。也就是说，在每类bin的内部仍然会有多个互不相关的链表来保存不同大小的chunk。

对于small bins，large bins，unsorted bins来说，Ptmalloc将它们维护在同一个数组中。这些bin对应的数据结构在malloc\_state中，如下

.. code:: cpp

    ##define NBINS 128
    /* Normal bins packed as described above */
    mchunkptr bins[ NBINS * 2 - 2 ];

虽然每个bin的表头使用mchunkptr这个数据结构，但是这只是为了方便我们将每个bin转化为malloc\_chunk指针。我们在使用时会将这个指针当做一个chunk的fd或bk指针来操作，以便于将处于空闲的堆块链接在一起。这样可以节省空间，并提高可用性。那到底是怎么节省的呢？这里我们以32位系统为例

+-----------+-----------------------------+-----------------------+-----------------------------+-----------------------+
| 含义      | bin1的fd/bin2的prev\_size   | bin1的bk/bin2的size   | bin2的fd/bin3的prev\_size   | bin2的bk/bin3的size   |
+===========+=============================+=======================+=============================+=======================+
| bin下标   | 0                           | 1                     | 2                           | 3                     |
+-----------+-----------------------------+-----------------------+-----------------------------+-----------------------+

可以看出除了第一个bin（unsorted bin）外，后面的每个bin会共享前面的bin的字段，将其视为malloc
chunk部分的prev\_size和size。这里也说明了一个问题，\ **bin的下标和我们所说的第几个bin并不是一致的**\ 。\ **这里也说明bin表头的chunk的prev\_size与size字段不能随便修改，因为这两个字段是被其它bin所利用的。**

相应的宏如下

.. code:: cpp

    typedef struct malloc_chunk *mbinptr;

    /* addressing -- note that bin_at(0) does not exist */
    ##define bin_at(m, i)                                                           \
        (mbinptr)(((char *) &((m)->bins[ ((i) -1) * 2 ])) -                        \
                  offsetof(struct malloc_chunk, fd))

    /* analog of ++bin */
    //获取下一个bin的地址
    ##define next_bin(b) ((mbinptr)((char *) (b) + (sizeof(mchunkptr) << 1)))

    /* Reminders about list directionality within bins */
    //这两个宏可以用来遍历bin
    //获取bin的位于链表头的chunk
    ##define first(b) ((b)->fd)
    //获取bin的位于链表尾的chunk
    ##define last(b) ((b)->bk)

**这里给出一个更加详细的图。?????**

数组中的bin依次介绍如下

1. 第一个为unsorted bin，字如其面，这里面的chunk没有进行排序，存储的chunk比较杂。
2. 索引从2到64的bin称为small bins，同一个small bin中的chunk的大小相同。两个相邻索引的small bin中的chunk大小相差的字节数为\ **2个机器字长**\ ，即32位相差8字节，64位相差16字节。
3. small bins后面的bin被称作large bins。large bins中的每一个bin都包含一定范围内的chunk，其中的chunk按大小序排列。相同大小的chunk同样按照最近使用顺序排列。

从small bin开始，每个bin的所存储的chunk的大小会不断增加。

此外，上述这些bin的排布都会遵循一个原则：\ **任意两个物理相邻的空闲chunk不能在一起**\ 。

需要注意的是，并不是所有的chunk被释放后就立即被放到bin中。ptmalloc为了提高分配的速度，会把一些小的的chunk\ **先**\ 放到fast
bins的容器内。\ **而且，fastbin中容器中的chunk的使用标记总是被置位的，所以不满足上面的那个原则。**

fast bin
^^^^^^^^

对于大多数程序来说，经常会申请以及释放一些比较小的内存块。而且，这个频率相对来说比较高。如果我们在将一些较小的chunk释放之后发现存在与之相邻的空闲的chunk并将它们进行合并，当我们下一次再次申请相应大小的chunk时，就需要对chunk进行分割，这样就大大降低了堆的利用效率。\ **因为我们把大部分时间花在了合并与分割以及中间检查的过程中。**\ 因此，ptmalloc中专门设计了fast
bin，对应的变量就是 malloc state 中的 fastbinsY ，对应的数据结构如下

.. code:: cpp

    /*
       Fastbins

        An array of lists holding recently freed small chunks.  Fastbins
        are not doubly linked.  It is faster to single-link them, and
        since chunks are never removed from the middles of these lists,
        double linking is not necessary. Also, unlike regular bins, they
        are not even processed in FIFO order (they use faster LIFO) since
        ordering doesn't much matter in the transient contexts in which
        fastbins are normally used.

        Chunks in fastbins keep their inuse bit set, so they cannot
        be consolidated with other free chunks. malloc_consolidate
        releases all chunks in fastbins and consolidates them with
        other free chunks.
     */
    typedef struct malloc_chunk *mfastbinptr;

    /*
        This is in malloc_state.
        /* Fastbins */
        mfastbinptr fastbinsY[ NFASTBINS ];
    */

为了更加高效地利用fast bin，glibc 直接采用单向链表对其中的每个bin进行组织，并且\ **每个bin采取LIFO策略**\ ，最近释放的 chunk
会更早地被分配，所以会更加适合于局部性。也就是说，当用户需要的chunk的大小小于 fastbin 的最大大小时， ptmalloc 会首先判断 fastbin
中是否有bin中有对应大小的空闲块，如果有的话，就会直接从这个bin中获取chunk。如果没有的话，ptmalloc才会做接下来的一系列操作。

默认情况下（32位为例）， fastbin 中默认支持最大的 chunk 的数据空间大小为64字节。但是其可以支持的chunk的数据空间最大为80字节。除此之外， fastbin
最多可以支持的bin的个数为10个，从数据空间为8字节开始一直到80字节，定义如下

.. code:: cpp

    ##define NFASTBINS (fastbin_index(request2size(MAX_FAST_SIZE)) + 1)

    ##ifndef DEFAULT_MXFAST
    ##define DEFAULT_MXFAST (64 * SIZE_SZ / 4)
    ##endif
      
    /* The maximum fastbin request size we support */
    ##define MAX_FAST_SIZE (80 * SIZE_SZ / 4)

    /*
       Since the lowest 2 bits in max_fast don't matter in size comparisons,
       they are used as flags.
     */

    /*
       FASTCHUNKS_BIT held in max_fast indicates that there are probably
       some fastbin chunks. It is set true on entering a chunk into any
       fastbin, and cleared only in malloc_consolidate.

       The truth value is inverted so that have_fastchunks will be true
       upon startup (since statics are zero-filled), simplifying
       initialization checks.
     */
    //判断分配区是否有 fast bin chunk，1表示没有
    ##define FASTCHUNKS_BIT (1U)

    ##define have_fastchunks(M) (((M)->flags & FASTCHUNKS_BIT) == 0)
    ##define clear_fastchunks(M) catomic_or(&(M)->flags, FASTCHUNKS_BIT)
    ##define set_fastchunks(M) catomic_and(&(M)->flags, ~FASTCHUNKS_BIT)

    /*
       NONCONTIGUOUS_BIT indicates that MORECORE does not return contiguous
       regions.  Otherwise, contiguity is exploited in merging together,
       when possible, results from consecutive MORECORE calls.

       The initial value comes from MORECORE_CONTIGUOUS, but is
       changed dynamically if mmap is ever used as an sbrk substitute.
     */
    // MORECODE是否返回连续的内存区域。
    // 主分配区中的MORECORE其实为sbr()，默认返回连续虚拟地址空间
    // 非主分配区使用mmap()分配大块虚拟内存，然后进行切分来模拟主分配区的行为
    // 而默认情况下mmap映射区域是不保证虚拟地址空间连续的，所以非主分配区默认分配非连续虚拟地址空间。
    ##define NONCONTIGUOUS_BIT (2U)

    ##define contiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) == 0)
    ##define noncontiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) != 0)
    ##define set_noncontiguous(M) ((M)->flags |= NONCONTIGUOUS_BIT)
    ##define set_contiguous(M) ((M)->flags &= ~NONCONTIGUOUS_BIT)

    /* ARENA_CORRUPTION_BIT is set if a memory corruption was detected on the
       arena.  Such an arena is no longer used to allocate chunks.  Chunks
       allocated in that arena before detecting corruption are not freed.  */

    ##define ARENA_CORRUPTION_BIT (4U)

    ##define arena_is_corrupt(A) (((A)->flags & ARENA_CORRUPTION_BIT))
    ##define set_arena_corrupt(A) ((A)->flags |= ARENA_CORRUPTION_BIT)

    /*
       Set value of max_fast.
       Use impossibly small value if 0.
       Precondition: there are no existing fastbin chunks.
       Setting the value clears fastchunk bit but preserves noncontiguous bit.
     */

    ##define set_max_fast(s)                                                        \
        global_max_fast =                                                          \
            (((s) == 0) ? SMALLBIN_WIDTH : ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK))
    ##define get_max_fast() global_max_fast

ptmalloc默认情况下会调用set\_max\_fast(s)将全局变量 global\_max\_fast 设置为DEFAULT\_MXFAST，也就是设置fast bins中chunk的最大值。当MAX\_FAST\_SIZE被设置为0时，系统就不会支持fastbin。

**fastbin的索引**

.. code:: cpp


    ##define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[ idx ])

    /* offset 2 to use otherwise unindexable first 2 bins */
    // 这里要减2，否则的话，前两个bin没有办法索引到。
    ##define fastbin_index(sz)                                                      \
        ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)

**需要特别注意的是，fastbin范围的chunk的inuse始终被置为1。因此它们不会和其它被释放的chunk合并。**

但是当释放的chunk与该chunk相邻的空闲chunk合并后的大小大于FASTBIN\_CONSOLIDATION\_THRESHOLD时，内存碎片可能比较多了，我们就需要把fast bins中的chunk都进行合并，以减少内存碎片对系统的影响。

.. code:: cpp

    /*
       FASTBIN_CONSOLIDATION_THRESHOLD is the size of a chunk in free()
       that triggers automatic consolidation of possibly-surrounding
       fastbin chunks. This is a heuristic, so the exact value should not
       matter too much. It is defined at half the default trim threshold as a
       compromise heuristic to only attempt consolidation if it is likely
       to lead to trimming. However, it is not dynamically tunable, since
       consolidation reduces fragmentation surrounding large chunks even
       if trimming is not used.
     */

    ##define FASTBIN_CONSOLIDATION_THRESHOLD (65536UL)

**malloc\_consolidate函数可以将fastbin中所有的chunk释放并合并在一起。？？？**

::

    /*
        Chunks in fastbins keep their inuse bit set, so they cannot
        be consolidated with other free chunks. malloc_consolidate
        releases all chunks in fastbins and consolidates them with
        other free chunks.
     */

small bin
^^^^^^^^^

small bins中每个chunk的大小与其所在的bin的index的关系为：chunk\_size =2 \* SIZE\_SZ \*index，具体如下

+--------+----------------------+----------------------+
| 下标   | SIZE\_SZ=4（32位）   | SIZE\_SZ=8（64位）   |
+========+======================+======================+
| 2      | 16                   | 32                   |
+--------+----------------------+----------------------+
| 3      | 24                   | 48                   |
+--------+----------------------+----------------------+
| 4      | 32                   | 64                   |
+--------+----------------------+----------------------+
| 5      | 40                   | 80                   |
+--------+----------------------+----------------------+
| x      | 2\*4\*x              | 2\*8\*x              |
+--------+----------------------+----------------------+
| 63     | 504                  | 1008                 |
+--------+----------------------+----------------------+

small
bins中一共有62个链表，每个链表中存储的chunk大小都一致。比如对于32位系统来说，下标2对应的双向链表中存储的chunk大小为均为16字节。每个链表都有链表头结点，这样可以方便对于链表内部结点的管理。此外，\ **small
bins中每个bin对应的链表采用FIFO的规则**\ ，所以同一个链表中先被释放的chunk会先被分配出去。

small bin相关的宏如下

.. code:: cpp

    ##define NSMALLBINS 64
    ##define SMALLBIN_WIDTH MALLOC_ALIGNMENT
    // 是否需要对small bin的下标进行纠正
    ##define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)

    ##define MIN_LARGE_SIZE ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
    //判断chunk的大小是否在small bin范围内
    ##define in_smallbin_range(sz)                                                  \
        ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)
    // 根据chunk的大小得到small bin对应的索引。
    ##define smallbin_index(sz)                                                     \
        ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4)                          \
                               : (((unsigned) (sz)) >> 3)) +                       \
         SMALLBIN_CORRECTION)

**或许，大家会很疑惑，那fastbin与small bin中chunk的大小会有很大一部分重合啊，那small bin中对应大小的bin是不是就没有什么作用啊？** 其实不然，fast bin中的chunk是有可能被放到small bin中去的。

large bin
^^^^^^^^^

large bins中一共包括63个bin，每个bin中的chunk的大小不再一致，而是处于一定区间范围内。此外，这63个bin被分成了6组，每组bin中的chunk大小之间的公差一致，具体如下：

+------+--------+-----------+
| 组   | 数量   | 公差      |
+======+========+===========+
| 1    | 32     | 64B       |
+------+--------+-----------+
| 2    | 16     | 512B      |
+------+--------+-----------+
| 3    | 8      | 4096B     |
+------+--------+-----------+
| 4    | 4      | 32768B    |
+------+--------+-----------+
| 5    | 2      | 262144B   |
+------+--------+-----------+
| 6    | 1      | 不限制    |
+------+--------+-----------+

这里我们以32位平台的large bin为例，第一个large bin的起始chunk大小为512字节，其位于第一组，所以该bin可以存储的chunk的大小范围为[512,512+64)。

关于large bin的宏如下，这里我们以32位平台下，第一个large bin的起始chunk大小为例，为512字节，那么

512>>6 = 8，所以其下标为56+8=64。

.. code:: cpp

    ##define largebin_index_32(sz)                                                  \
        (((((unsigned long) (sz)) >> 6) <= 38)                                     \
             ? 56 + (((unsigned long) (sz)) >> 6)                                  \
             : ((((unsigned long) (sz)) >> 9) <= 20)                               \
                   ? 91 + (((unsigned long) (sz)) >> 9)                            \
                   : ((((unsigned long) (sz)) >> 12) <= 10)                        \
                         ? 110 + (((unsigned long) (sz)) >> 12)                    \
                         : ((((unsigned long) (sz)) >> 15) <= 4)                   \
                               ? 119 + (((unsigned long) (sz)) >> 15)              \
                               : ((((unsigned long) (sz)) >> 18) <= 2)             \
                                     ? 124 + (((unsigned long) (sz)) >> 18)        \
                                     : 126)

    ##define largebin_index_32_big(sz)                                              \
        (((((unsigned long) (sz)) >> 6) <= 45)                                     \
             ? 49 + (((unsigned long) (sz)) >> 6)                                  \
             : ((((unsigned long) (sz)) >> 9) <= 20)                               \
                   ? 91 + (((unsigned long) (sz)) >> 9)                            \
                   : ((((unsigned long) (sz)) >> 12) <= 10)                        \
                         ? 110 + (((unsigned long) (sz)) >> 12)                    \
                         : ((((unsigned long) (sz)) >> 15) <= 4)                   \
                               ? 119 + (((unsigned long) (sz)) >> 15)              \
                               : ((((unsigned long) (sz)) >> 18) <= 2)             \
                                     ? 124 + (((unsigned long) (sz)) >> 18)        \
                                     : 126)

    // XXX It remains to be seen whether it is good to keep the widths of
    // XXX the buckets the same or whether it should be scaled by a factor
    // XXX of two as well.
    ##define largebin_index_64(sz)                                                  \
        (((((unsigned long) (sz)) >> 6) <= 48)                                     \
             ? 48 + (((unsigned long) (sz)) >> 6)                                  \
             : ((((unsigned long) (sz)) >> 9) <= 20)                               \
                   ? 91 + (((unsigned long) (sz)) >> 9)                            \
                   : ((((unsigned long) (sz)) >> 12) <= 10)                        \
                         ? 110 + (((unsigned long) (sz)) >> 12)                    \
                         : ((((unsigned long) (sz)) >> 15) <= 4)                   \
                               ? 119 + (((unsigned long) (sz)) >> 15)              \
                               : ((((unsigned long) (sz)) >> 18) <= 2)             \
                                     ? 124 + (((unsigned long) (sz)) >> 18)        \
                                     : 126)

    ##define largebin_index(sz)                                                     \
        (SIZE_SZ == 8 ? largebin_index_64(sz) : MALLOC_ALIGNMENT == 16             \
                                                    ? largebin_index_32_big(sz)    \
                                                    : largebin_index_32(sz))

unsorted bin
^^^^^^^^^^^^

unsorted bin可以视为small bins 与large bins 之间的缓冲。 unsorted bin只有一个链表，其中的空闲chunk不会进行排序，主要有两个来源

-  一个chunk被分割成两半后剩下的部分会被放到unsorted bin中。
-  所有的chunk在回收利用前都会放到unsorted bin中。

其在glibc中具体的说明如下

.. code:: cpp

    /*
       Unsorted chunks

        All remainders from chunk splits, as well as all returned chunks,
        are first placed in the "unsorted" bin. They are then placed
        in regular bins after malloc gives them ONE chance to be used before
        binning. So, basically, the unsorted_chunks list acts as a queue,
        with chunks being placed on it in free (and malloc_consolidate),
        and taken off (to be either used or placed in bins) in malloc.

        The NON_MAIN_ARENA flag is never set for unsorted chunks, so it
        does not have to be taken into account in size comparisons.
     */

从下面的宏我们可以看出

.. code:: cpp

    /* The otherwise unindexable 1-bin is used to hold unsorted chunks. */
    ##define unsorted_chunks(M) (bin_at(M, 1))

unsorted bin处于我们之前所说的数组下标1处。

common macro
^^^^^^^^^^^^

这里介绍一些通用的宏。

**根据chunk的大小统一地获得chunk所在的索引**

.. code:: cpp

    ##define bin_index(sz)                                                          \
        ((in_smallbin_range(sz)) ? smallbin_index(sz) : largebin_index(sz))

top chunk
~~~~~~~~~

glibc中对于top chunk的描述如下

.. code:: cpp

    /*
       Top

        The top-most available chunk (i.e., the one bordering the end of
        available memory) is treated specially. It is never included in
        any bin, is used only if no other chunk is available, and is
        released back to the system if it is very large (see
        M_TRIM_THRESHOLD).  Because top initially
        points to its own bin with initial zero size, thus forcing
        extension on the first malloc request, we avoid having any special
        code in malloc to check whether it even exists yet. But we still
        need to do so when getting memory from system, so we make
        initial_top treat the bin as a legal but unusable chunk during the
        interval between initialization and the first call to
        sysmalloc. (This is somewhat delicate, since it relies on
        the 2 preceding words to be zero during this interval as well.)
     */

    /* Conveniently, the unsorted bin can be used as dummy top on first call */
    ##define initial_top(M) (unsorted_chunks(M))

程序第一次进行malloc的时候，就会将heap分为两块，一块给用户，剩下的那块就是top chunk。其实，所谓的top
chunk就是处于当前堆的物理地址最高的chunk。这个chunk不属于任何一个bin，它的作用在于当所有的bin都无法满足用户请求的大小时，如果其大小不小于指定的大小，就进行分配，并将剩下的部分作为新的top
chunk。否则，就对heap进行扩展后再进行分配。在main arena中通过sbrk扩展heap，而在thread arena中通过mmap分配新的heap。

需要注意的是，top chunk的prev\_inuse比特位始终为1，否则其前面的chunk就会被合并到top chunk中。

last remainder
~~~~~~~~~~~~~~

在用户使用 malloc 请求分配内存时，ptmalloc2 找到的 chunk 可能并不是和申请的大小一致，这时候就将分割之后的剩余部分称之为 last remainder chunk ，unsort bin也会存这一块。
