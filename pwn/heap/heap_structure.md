# 堆数据结构

既然堆的操作本身这么复杂，那么在计算机系统内部必然也有相应的数据结构来管理堆。与堆相应的数据结构主要分为

- 控制结构，主要用于控制堆，可以通过这些数据结构来得到堆的一些基本信息。
- 存储结构，主要用于表示申请的内存块，以便于可以让用户正常的申请与释放这些堆块。

# Overview？？？？

**这里给一个宏观的图片。**

# 宏观结构

## arena

正如我们之前所说的，无论是主线程还是新创建的线程来说在第一次申请内存时，都会有自己独立的arena，那么会不会每个线程都有自己的arena呢？下面我们就具体介绍。

### arena 数量

首先，我们需要明确的是，不是每一个线程都会有自己对应的arena，这是因为每个系统的核数是有限的，当线程数大于核数的二倍时，就必然有线程处于等待状态。所以没有必要为每个线程分配一个arena的。具体的[约束](https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/arena.c#L847)如下

```text
For 32 bit systems:
     Number of arena = 2 * number of cores.
For 64 bit systems:
     Number of arena = 8 * number of cores.
```

至于为什么64位系统，要那么设置，我也没有想明白。

### arena 分配规则

待补充。

### 区别

此外，与thread不同的是，main的arena header并不在申请的heap中，它是一个全局变量，在libc.so的数据段。

## heap_info

该数据结构是专门为从Memory Mapping Segment处申请的内存准备的。当主线程申请较小的内存空间时，可以通过sbrk()函数扩展program break location获得（直到触及Memory Mapping Segment），因此只有一个heap。所以没有heap_info数据结构。

heap_info的主要结构如下

```c++
#define HEAP_MIN_SIZE (32 * 1024)
#ifndef HEAP_MAX_SIZE
# ifdef DEFAULT_MMAP_THRESHOLD_MAX
#  define HEAP_MAX_SIZE (2 * DEFAULT_MMAP_THRESHOLD_MAX)
# else
#  define HEAP_MAX_SIZE (1024 * 1024) /* must be a power of two */
# endif
#endif

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
```

该结构主要是描述堆的基本信息，包括

- 给出了该堆对应的heap arena的地址。
- 在该堆前面的heap_info的地址，这里可以看到用来描述每个堆的heap_info是通过单向链表进行链接的。
- size表示当前堆的大小。
- 最后一部分确保对齐。（**这里负数使用的缘由是什么呢**？）

看起来该结构应该是相当重要的，但是如果你仔细看看整个malloc的实现的话，它出现的频率并不高。

程序刚开始执行时，每个线程是没有heap区域的，当申请内存的时，就需要一个结构来记录对应的信息，而heap_info的作用就是这个。而且当该heap的资源被使用完后，就必须得再次申请heap了。此外，一般申请的heap是不连续的，因此使用heap_info结构去记录不同heap之间的链接结构。

## malloc_state

该结构用于管理堆，记录每个arena当前的申请内存的状态。无论是对于thread arena还是说main arena，它们都只有一个malloc state结构。由于thread的arena可能有多个，malloc state结构会在最新申请的arena中。该结构体中一般存储如下信息

- bins、top chunk的信息
- last_remainder的信息

注意，main arena的malloc_state并不是heap segment的一部分，而是一个全局变量，存储在libc.so的数据段。

其结构如下

```c++
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
```

关于其中每一个变量的具体意思，我们会在使用到的时候进行详细地说明。

# 微观结构

基本上上面的结构就给出了堆的宏观结构，下面就是堆中比较细节的结构了，而我们关于堆的利用业主要是集中在这些结构中。

## malloc_chunk

在程序中，由malloc申请的内存被称为chunk。该内存由malloc_chunk结构体来表示。当该chunk被free掉，会被加入到对应的管理列表中。非常有意思的是，**ptmalloc2中利用了一个统一的结构来实现chunk，无论一个chunk的大小如何，处于分配状态或者释放状态，它们所使用的数据结构相同**。但是，需要注意的是，虽然它们使用了同一个数据结构，但是根据堆是否被释放，它们的表现形式会有所不同。

malloc_chunk的结构如下

```c++
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
```

具体的，每个字段的解释如下

- **prev_size**,  如果该chunk的物理相邻的前一chunk是空闲的话，那该字段记录的是上一个chunk的大小(包括chunk头)。否则，该字段可以用来存储上一个chunk的数据。
- **size** ，该chunk的大小，大小必须是8（32位）的整数倍。如果申请的大小不是8的整数倍，会被转换满足大小的最小的8的倍数。该字段的最低的三个比特位从高到低分别表示
  - NON_MAIN_ARENA 记录当前chunk是否不属于主线程，1表示不属于，0表示属于。
  - IS_MAPPED 记录当前chunk是否是由mmap分配的。 
  - PREV_INUSE 记录前一个chunk块是否被分配。一般来说，对于堆中第一个申请的内存块来说，其size字段的P位都会被设置为1，以便于防止访问前面的非法内存。而且，当一个chunk的size的P位为0时，我们能通过prev_size字段来获取上一个chunk的地址。这也方便进行空闲chunk之间的合并。
- **fd,bk**。 chunk处于分配状态时，从fd字段开始就是用户的数据了，否则，在chunk是空闲的时候，其字段的含义如下
  - fd指向下一个（非物理相邻）空闲的chunk
  - bk指向上一个空闲（非物理相邻）的chunk
  - 由此可以构成一个双向链表。
- **fd_nextsize, bk_nextsize**，也是只有chunk空闲的时候才使用，不过其用于较大的chunk。

我们可以发现，如果一个chunk处于free状态的话，其实是可能有两个位置记录其相应的大小的，一个是本身的记录，一个是其后一个chunk会记录。而这也恰好加速了两个物理相邻的空闲chunk块的合并速度。

一个已经分配的chunk的样子如下。**一般来说，我们称前两个字段称为chunk header，后面的部分称为user data。此外，我们每次malloc申请得到的指针，其实指向user data的起始处。** 

```c++
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
```

被释放的chunk一般被记录在链表中（可能是循环链表，也可能是单向链表）。具体形状如下

```c++
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
```

**一些关于堆的约束？？？？**

```c++
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
```

关于chunk的大小以及一些转换的代码如下

```c++
/*
  ---------- Size and alignment checks and conversions ----------
*/

/* conversion from malloc headers to user pointers, and back */

#define chunk2mem(p) ((void *) ((char *) (p) + 2 * SIZE_SZ))
#define mem2chunk(mem) ((mchunkptr)((char *) (mem) -2 * SIZE_SZ))

/* The smallest possible chunk */
#define MIN_CHUNK_SIZE (offsetof(struct malloc_chunk, fd_nextsize))

/* The smallest size we can malloc is an aligned minimal chunk */

#define MINSIZE                                                                \
    (unsigned long) (((MIN_CHUNK_SIZE + MALLOC_ALIGN_MASK) &                   \
                      ~MALLOC_ALIGN_MASK))

/* Check if m has acceptable alignment */

#define aligned_OK(m) (((unsigned long) (m) &MALLOC_ALIGN_MASK) == 0)

#define misaligned_chunk(p)                                                    \
    ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem(p)) &       \
     MALLOC_ALIGN_MASK)

/*
   Check if a request is so large that it would wrap around zero when
   padded and aligned. To simplify some other code, the bound is made
   low enough so that adding MINSIZE will also not wrap around zero.
 */

#define REQUEST_OUT_OF_RANGE(req)                                              \
    ((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE))

/* pad request bytes into a usable size -- internal version */

#define request2size(req)                                                      \
    (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)                           \
         ? MINSIZE                                                             \
         : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/*  Same, except also perform argument check */

#define checked_request2size(req, sz)                                          \
    if (REQUEST_OUT_OF_RANGE(req)) {                                           \
        __set_errno(ENOMEM);                                                   \
        return 0;                                                              \
    }                                                                          \
    (sz) = request2size(req);

/*
   --------------- Physical chunk operations ---------------
 */

/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
#define PREV_INUSE 0x1

/* extract inuse bit of previous chunk */
#define prev_inuse(p) ((p)->mchunk_size & PREV_INUSE)

/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2

/* check for mmap()'ed chunk */
#define chunk_is_mmapped(p) ((p)->mchunk_size & IS_MMAPPED)

/* size field is or'ed with NON_MAIN_ARENA if the chunk was obtained
   from a non-main arena.  This is only set immediately before handing
   the chunk to the user, if necessary.  */
#define NON_MAIN_ARENA 0x4

/* Check for chunk from main arena.  */
#define chunk_main_arena(p) (((p)->mchunk_size & NON_MAIN_ARENA) == 0)

/* Mark a chunk as not being on the main arena.  */
#define set_non_main_arena(p) ((p)->mchunk_size |= NON_MAIN_ARENA)

/*
   Bits to mask off when extracting size
   Note: IS_MMAPPED is intentionally not masked off from size field in
   macros for which mmapped chunks should never be seen. This should
   cause helpful core dumps to occur if it is tried by accident by
   people extending or adapting this malloc.
 */
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask(p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p) ((p)->mchunk_size)

/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr)(((char *) (p)) + chunksize(p)))

/* Size of the chunk below P.  Only valid if prev_inuse (P).  */
#define prev_size(p) ((p)->mchunk_prev_size)

/* Set the size of the chunk below P.  Only valid if prev_inuse (P).  */
#define set_prev_size(p, sz) ((p)->mchunk_prev_size = (sz))

/* Ptr to previous physical malloc_chunk.  Only valid if prev_inuse (P).  */
#define prev_chunk(p) ((mchunkptr)(((char *) (p)) - prev_size(p)))

/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s) ((mchunkptr)(((char *) (p)) + (s)))

/* extract p's inuse bit */
#define inuse(p)                                                               \
    ((((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size) & PREV_INUSE)

/* set/clear chunk as being inuse without otherwise disturbing */
#define set_inuse(p)                                                           \
    ((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size |= PREV_INUSE

#define clear_inuse(p)                                                         \
    ((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size &= ~(PREV_INUSE)

/* check/set/clear inuse bits in known places */
#define inuse_bit_at_offset(p, s)                                              \
    (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size & PREV_INUSE)

#define set_inuse_bit_at_offset(p, s)                                          \
    (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size |= PREV_INUSE)

#define clear_inuse_bit_at_offset(p, s)                                        \
    (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size &= ~(PREV_INUSE))

/* Set size at head, without disturbing its use bit */
#define set_head_size(p, s)                                                    \
    ((p)->mchunk_size = (((p)->mchunk_size & SIZE_BITS) | (s)))

/* Set size/use field */
#define set_head(p, s) ((p)->mchunk_size = (s))

/* Set size at footer (only when chunk is not in use) */
#define set_foot(p, s)                                                         \
    (((mchunkptr)((char *) (p) + (s)))->mchunk_prev_size = (s))
```



## bin

简单地说，bin就是用来记录已经被释放的chunk的数据结构。其实它本身也使用malloc_chunk这个数据结构，但是它不会使用这个数据结构的数据段，而是使用fd和bk将处于空闲的堆块链接在一起。但是并不是所有的被释放的chunk都被放在一个bin中，它们会按照**一定的大小以及一些规则** 存储在不同的bin中。一些bin中会记录与申请的内存一样大小的chunk，而更多的bin则会记录处于一定区间段的chunk。但是，所有这些bin的排布都会遵循一个原则：**任意两个物理相邻的chunk都不能在一起**。

目前，大约一共有128个bin。虽然看起来非常多，但是却使得堆的管理异常有效。



在堆管理中，我们一般主要有以下的bin

- fast bin
- small bin
- unsorted bin
- large bin

对于不同的bin来说

## top chunk

## last remainder