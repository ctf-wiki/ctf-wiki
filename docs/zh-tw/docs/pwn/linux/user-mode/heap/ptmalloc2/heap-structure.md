# 堆相關數據結構

堆的操作就這麼複雜，那麼在 glibc 內部必然也有精心設計的數據結構來管理它。與堆相應的數據結構主要分爲

- 宏觀結構，包含堆的宏觀信息，可以通過這些數據結構索引堆的基本信息。
- 微觀結構，用於具體處理堆的分配與回收中的內存塊。

## Overview？？？？

**這裏給一個宏觀的圖片。**

## 微觀結構

這裏首先介紹堆中比較細節的結構，**堆的漏洞利用與這些結構密切相關**。

### malloc_chunk

#### 概述

在程序的執行過程中，我們稱由 malloc 申請的內存爲 chunk 。這塊內存在 ptmalloc 內部用 malloc_chunk 結構體來表示。當程序申請的 chunk 被 free 後，會被加入到相應的空閒管理列表中。

非常有意思的是，**無論一個 chunk 的大小如何，處於分配狀態還是釋放狀態，它們都使用一個統一的結構**。雖然它們使用了同一個數據結構，但是根據是否被釋放，它們的表現形式會有所不同。

malloc_chunk 的結構如下

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

首先，這裏給出一些必要的解釋 INTERNAL_SIZE_T，SIZE_SZ，MALLOC_ALIGN_MASK：

```c
/* INTERNAL_SIZE_T is the word-size used for internal bookkeeping of
   chunk sizes.
   The default version is the same as size_t.
   While not strictly necessary, it is best to define this as an
   unsigned type, even if size_t is a signed type. This may avoid some
   artificial size limitations on some systems.
   On a 64-bit machine, you may be able to reduce malloc overhead by
   defining INTERNAL_SIZE_T to be a 32 bit `unsigned int' at the
   expense of not being able to handle more than 2^32 of malloced
   space. If this limitation is acceptable, you are encouraged to set
   this unless you are on a platform requiring 16byte alignments. In
   this case the alignment requirements turn out to negate any
   potential advantages of decreasing size_t word size.
   Implementors: Beware of the possible combinations of:
     - INTERNAL_SIZE_T might be signed or unsigned, might be 32 or 64 bits,
       and might be the same width as int or as long
     - size_t might have different width and signedness as INTERNAL_SIZE_T
     - int and long might be 32 or 64 bits, and might be the same width
   To deal with this, most comparisons and difference computations
   among INTERNAL_SIZE_Ts should cast them to unsigned long, being
   aware of the fact that casting an unsigned int to a wider long does
   not sign-extend. (This also makes checking for negative numbers
   awkward.) Some of these casts result in harmless compiler warnings
   on some systems.  */
#ifndef INTERNAL_SIZE_T
# define INTERNAL_SIZE_T size_t
#endif

/* The corresponding word size.  */
#define SIZE_SZ (sizeof (INTERNAL_SIZE_T))

/* The corresponding bit mask value.  */
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)
```

一般來說，size_t 在 64 位中是 64 位無符號整數，32 位中是 32 位無符號整數。

每個字段的具體的解釋如下

-   **prev_size**,  如果該 chunk 的**物理相鄰的前一地址chunk（兩個指針的地址差值爲前一chunk大小）**是空閒的話，那該字段記錄的是前一個 chunk 的大小(包括 chunk 頭)。否則，該字段可以用來存儲物理相鄰的前一個chunk 的數據。**這裏的前一 chunk 指的是較低地址的 chunk **。
-   **size** ，該 chunk 的大小，大小必須是 2 * SIZE_SZ 的整數倍。如果申請的內存大小不是 2 * SIZE_SZ 的整數倍，會被轉換滿足大小的最小的 2 * SIZE_SZ 的倍數。32 位系統中，SIZE_SZ 是 4；64 位系統中，SIZE_SZ 是 8。 該字段的低三個比特位對 chunk 的大小沒有影響，它們從高到低分別表示
    -   NON_MAIN_ARENA，記錄當前 chunk 是否不屬於主線程，1表示不屬於，0表示屬於。
    -   IS_MAPPED，記錄當前 chunk 是否是由 mmap 分配的。 
    -   PREV_INUSE，記錄前一個 chunk 塊是否被分配。一般來說，堆中第一個被分配的內存塊的 size 字段的P位都會被設置爲1，以便於防止訪問前面的非法內存。當一個 chunk 的 size 的 P 位爲 0 時，我們能通過 prev_size 字段來獲取上一個 chunk 的大小以及地址。這也方便進行空閒chunk之間的合併。
-   **fd，bk**。 chunk 處於分配狀態時，從 fd 字段開始是用戶的數據。chunk 空閒時，會被添加到對應的空閒管理鏈表中，其字段的含義如下
    -   fd 指向下一個（非物理相鄰）空閒的 chunk
    -   bk 指向上一個（非物理相鄰）空閒的 chunk
    -   通過 fd 和 bk 可以將空閒的 chunk 塊加入到空閒的 chunk 塊鏈表進行統一管理
-   **fd_nextsize， bk_nextsize**，也是隻有 chunk 空閒的時候才使用，不過其用於較大的 chunk（large chunk）。
    -   fd_nextsize 指向前一個與當前 chunk 大小不同的第一個空閒塊，不包含 bin 的頭指針。
    -   bk_nextsize 指向後一個與當前 chunk 大小不同的第一個空閒塊，不包含 bin 的頭指針。
    -   一般空閒的 large chunk 在 fd 的遍歷順序中，按照由大到小的順序排列。**這樣做可以避免在尋找合適chunk 時挨個遍歷。**

一個已經分配的 chunk 的樣子如下。**我們稱前兩個字段稱爲 chunk header，後面的部分稱爲 user data。每次 malloc 申請得到的內存指針，其實指向 user data 的起始處。** 

當一個 chunk 處於使用狀態時，它的下一個 chunk 的 prev_size 域無效，所以下一個 chunk 的該部分也可以被當前chunk使用。**這就是chunk中的空間複用。**

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

被釋放的 chunk 被記錄在鏈表中（可能是循環雙向鏈表，也可能是單向鏈表）。具體結構如下

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

可以發現，如果一個 chunk 處於 free 狀態，那麼會有兩個位置記錄其相應的大小

1. 本身的 size 字段會記錄，

2. 它後面的 chunk 會記錄。

**一般情況下**，物理相鄰的兩個空閒 chunk 會被合併爲一個 chunk 。堆管理器會通過 prev_size 字段以及 size 字段合併兩個物理相鄰的空閒 chunk 塊。

**！！！一些關於堆的約束，後面詳細考慮！！！**

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

#### chunk相關宏

這裏主要介紹 chunk 的大小、對齊檢查以及一些轉換的宏。

**chunk 與 mem 指針頭部的轉換**

mem指向用戶得到的內存的起始位置。

```c++
/* conversion from malloc headers to user pointers, and back */
#define chunk2mem(p) ((void *) ((char *) (p) + 2 * SIZE_SZ))
#define mem2chunk(mem) ((mchunkptr)((char *) (mem) -2 * SIZE_SZ))
```

**最小的 chunk 大小**

```c++
/* The smallest possible chunk */
#define MIN_CHUNK_SIZE (offsetof(struct malloc_chunk, fd_nextsize))
```

這裏，offsetof 函數計算出 fd_nextsize 在 malloc_chunk 中的偏移，說明最小的 chunk 至少要包含 bk 指針。

**最小申請的堆內存大小**

用戶最小申請的內存大小必須是 2 * SIZE_SZ 的最小整數倍。

**注：就目前而看 MIN_CHUNK_SIZE 和 MINSIZE 大小是一致的，個人認爲之所以要添加兩個宏是爲了方便以後修改 malloc_chunk 時方便一些。**

```c++
/* The smallest size we can malloc is an aligned minimal chunk */
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define MINSIZE                                                                \
    (unsigned long) (((MIN_CHUNK_SIZE + MALLOC_ALIGN_MASK) &                   \
                      ~MALLOC_ALIGN_MASK))
```

**檢查分配給用戶的內存是否對齊**

2 * SIZE_SZ 大小對齊。

```c++
/* Check if m has acceptable alignment */
// MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define aligned_OK(m) (((unsigned long) (m) & MALLOC_ALIGN_MASK) == 0)

#define misaligned_chunk(p)                                                    \
    ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem(p)) &       \
     MALLOC_ALIGN_MASK)
```

**請求字節數判斷**

```c++
/*
   Check if a request is so large that it would wrap around zero when
   padded and aligned. To simplify some other code, the bound is made
   low enough so that adding MINSIZE will also not wrap around zero.
 */

#define REQUEST_OUT_OF_RANGE(req)                                              \
    ((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE))
```

**將用戶請求內存大小轉爲實際分配內存大小**

```c++
/* pad request bytes into a usable size -- internal version */
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
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
```

當一個 chunk 處於已分配狀態時，它的物理相鄰的下一個 chunk 的 prev_size 字段必然是無效的，故而這個字段就可以被當前這個 chunk 使用。這就是 ptmalloc 中 chunk 間的複用。具體流程如下

1. 首先，利用 REQUEST_OUT_OF_RANGE 判斷是否可以分配用戶請求的字節大小的 chunk。
2. 其次，需要注意的是用戶請求的字節是用來存儲數據的，即 chunk header 後面的部分。與此同時，由於chunk 間複用，所以可以使用下一個 chunk 的 prev_size 字段。因此，這裏只需要再添加 SIZE_SZ 大小即可以完全存儲內容。
3. 由於系統中所允許的申請的 chunk 最小是 MINSIZE，所以與其進行比較。如果不滿足最低要求，那麼就需要直接分配MINSIZE字節。
4. 如果大於的話，因爲系統中申請的 chunk 需要 2 * SIZE_SZ 對齊，所以這裏需要加上MALLOC_ALIGN_MASK 以便於對齊。

**個人認爲，這裏在 request2size 的宏的第一行中沒有必要加上 MALLOC_ALIGN_MASK。**

**需要注意的是，通過這樣的計算公式得到的 size 最終一定是滿足用戶需要的。**

**標記位相關**

```c++
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
```

**獲取chunk size**

```c++
/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask(p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p) ((p)->mchunk_size)
```

**獲取下一個物理相鄰的chunk**

```c++
/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr)(((char *) (p)) + chunksize(p)))
```

**獲取前一個chunk的信息**

```c++
/* Size of the chunk below P.  Only valid if !prev_inuse (P).  */
#define prev_size(p) ((p)->mchunk_prev_size)

/* Set the size of the chunk below P.  Only valid if !prev_inuse (P).  */
#define set_prev_size(p, sz) ((p)->mchunk_prev_size = (sz))

/* Ptr to previous physical malloc_chunk.  Only valid if !prev_inuse (P).  */
#define prev_chunk(p) ((mchunkptr)(((char *) (p)) - prev_size(p)))
```

**當前chunk使用狀態相關操作**

```c++
/* extract p's inuse bit */
#define inuse(p)                                                               \
    ((((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size) & PREV_INUSE)

/* set/clear chunk as being inuse without otherwise disturbing */
#define set_inuse(p)                                                           \
    ((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size |= PREV_INUSE

#define clear_inuse(p)                                                         \
    ((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size &= ~(PREV_INUSE)
```

**設置chunk的size字段**

```c++
/* Set size at head, without disturbing its use bit */
// SIZE_BITS = 7
#define set_head_size(p, s)                                                    \
    ((p)->mchunk_size = (((p)->mchunk_size & SIZE_BITS) | (s)))

/* Set size/use field */
#define set_head(p, s) ((p)->mchunk_size = (s))

/* Set size at footer (only when chunk is not in use) */
#define set_foot(p, s)                                                         \
    (((mchunkptr)((char *) (p) + (s)))->mchunk_prev_size = (s))
```

**獲取指定偏移的chunk**

```c++
/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s) ((mchunkptr)(((char *) (p)) + (s)))
```

**指定偏移處chunk使用狀態相關操作**

```c++
/* check/set/clear inuse bits in known places */
#define inuse_bit_at_offset(p, s)                                              \
    (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size & PREV_INUSE)

#define set_inuse_bit_at_offset(p, s)                                          \
    (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size |= PREV_INUSE)

#define clear_inuse_bit_at_offset(p, s)                                        \
    (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size &= ~(PREV_INUSE))
```

### bin

#### 概述

我們曾經說過，用戶釋放掉的 chunk 不會馬上歸還給系統，ptmalloc 會統一管理 heap 和 mmap 映射區域中的空閒的chunk。當用戶再一次請求分配內存時，ptmalloc 分配器會試圖在空閒的chunk中挑選一塊合適的給用戶。這樣可以避免頻繁的系統調用，降低內存分配的開銷。

在具體的實現中，ptmalloc 採用分箱式方法對空閒的 chunk 進行管理。首先，它會根據空閒的 chunk 的大小以及使用狀態將 chunk 初步分爲4類：fast bins，small bins，large bins，unsorted bin。每類中仍然有更細的劃分，相似大小的 chunk 會用雙向鏈表鏈接起來。也就是說，在每類 bin 的內部仍然會有多個互不相關的鏈表來保存不同大小的 chunk。

對於 small bins，large bins，unsorted bin 來說，ptmalloc 將它們維護在同一個數組中。這些bin對應的數據結構在 malloc_state 中，如下

```c++
#define NBINS 128
/* Normal bins packed as described above */
mchunkptr bins[ NBINS * 2 - 2 ];
```

`bins` 主要用於索引不同 bin 的 fd 和 bk。

爲了簡化在雙鏈接列表中的使用，每個bin的header都設置爲malloc_chunk類型。這樣可以避免header類型及其特殊處理。但是，爲了節省空間和提高局部性，只分配bin的fd/bk指針，然後使用repositioning tricks將這些指針視爲一個`malloc_chunk*`的字段。


以 32 位系統爲例，bins 前 4 項的含義如下

| 含義    | bin1的fd/bin2的prev_size | bin1的bk/bin2的size | bin2的fd/bin3的prev_size | bin2的bk/bin3的size |
| ----- | ---------------------- | ----------------- | ---------------------- | ----------------- |
| bin下標 | 0                      | 1                 | 2                      | 3                 |

可以看到，bin2 的 prev_size、size 和 bin1 的 fd、bk 是重合的。由於我們只會使用 fd 和 bk 來索引鏈表，所以該重合部分的數據其實記錄的是 bin1 的 fd、bk。 也就是說，雖然後一個 bin 和前一個 bin 共用部分數據，但是其實記錄的仍然是前一個 bin 的鏈表數據。通過這樣的複用，可以節省空間。

數組中的 bin 依次如下

1. 第一個爲 unsorted bin，字如其面，這裏面的 chunk 沒有進行排序，存儲的 chunk 比較雜。
2. 索引從 2 到 63 的 bin 稱爲 small bin，同一個 small bin 鏈表中的 chunk 的大小相同。兩個相鄰索引的 small bin 鏈表中的 chunk 大小相差的字節數爲**2個機器字長**，即32位相差8字節，64位相差16字節。
3. small bins 後面的 bin 被稱作 large bins。large bins 中的每一個 bin 都包含一定範圍內的 chunk，其中的chunk 按 fd 指針的順序從大到小排列。相同大小的chunk同樣按照最近使用順序排列。

此外，上述這些bin的排布都會遵循一個原則：**任意兩個物理相鄰的空閒chunk不能在一起**。

需要注意的是，並不是所有的 chunk 被釋放後就立即被放到 bin 中。ptmalloc 爲了提高分配的速度，會把一些小的 chunk **先**放到 fast bins 的容器內。**而且，fastbin 容器中的 chunk 的使用標記總是被置位的，所以不滿足上面的原則。**

bin 通用的宏如下

```c++
typedef struct malloc_chunk *mbinptr;

/* addressing -- note that bin_at(0) does not exist */
#define bin_at(m, i)                                                           \
    (mbinptr)(((char *) &((m)->bins[ ((i) -1) * 2 ])) -                        \
              offsetof(struct malloc_chunk, fd))

/* analog of ++bin */
//獲取下一個bin的地址
#define next_bin(b) ((mbinptr)((char *) (b) + (sizeof(mchunkptr) << 1)))

/* Reminders about list directionality within bins */
// 這兩個宏可以用來遍歷bin
// 獲取 bin 的位於鏈表頭的 chunk
#define first(b) ((b)->fd)
// 獲取 bin 的位於鏈表尾的 chunk
#define last(b) ((b)->bk)
```

#### Fast Bin

大多數程序經常會申請以及釋放一些比較小的內存塊。如果將一些較小的 chunk 釋放之後發現存在與之相鄰的空閒的 chunk 並將它們進行合併，那麼當下一次再次申請相應大小的 chunk 時，就需要對 chunk 進行分割，這樣就大大降低了堆的利用效率。**因爲我們把大部分時間花在了合併、分割以及中間檢查的過程中。**因此，ptmalloc 中專門設計了 fast bin，對應的變量就是 malloc state 中的 fastbinsY 

```c++
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
```

爲了更加高效地利用 fast bin，glibc 採用單向鏈表對其中的每個 bin 進行組織，並且**每個 bin 採取 LIFO 策略**，最近釋放的 chunk 會更早地被分配，所以會更加適合於局部性。也就是說，當用戶需要的 chunk 的大小小於 fastbin 的最大大小時， ptmalloc 會首先判斷 fastbin 中相應的 bin 中是否有對應大小的空閒塊，如果有的話，就會直接從這個 bin 中獲取 chunk。如果沒有的話，ptmalloc纔會做接下來的一系列操作。

默認情況下（**32位系統爲例**）， fastbin 中默認支持最大的 chunk 的數據空間大小爲 64 字節。但是其可以支持的chunk的數據空間最大爲80字節。除此之外， fastbin 最多可以支持的 bin 的個數爲 10 個，從數據空間爲 8 字節開始一直到 80 字節（注意這裏說的是數據空間大小，也即除去 prev_size 和 size 字段部分的大小）定義如下

```c++
#define NFASTBINS (fastbin_index(request2size(MAX_FAST_SIZE)) + 1)

#ifndef DEFAULT_MXFAST
#define DEFAULT_MXFAST (64 * SIZE_SZ / 4)
#endif
  
/* The maximum fastbin request size we support */
#define MAX_FAST_SIZE (80 * SIZE_SZ / 4)

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
//判斷分配區是否有 fast bin chunk，1表示沒有
#define FASTCHUNKS_BIT (1U)

#define have_fastchunks(M) (((M)->flags & FASTCHUNKS_BIT) == 0)
#define clear_fastchunks(M) catomic_or(&(M)->flags, FASTCHUNKS_BIT)
#define set_fastchunks(M) catomic_and(&(M)->flags, ~FASTCHUNKS_BIT)

/*
   NONCONTIGUOUS_BIT indicates that MORECORE does not return contiguous
   regions.  Otherwise, contiguity is exploited in merging together,
   when possible, results from consecutive MORECORE calls.

   The initial value comes from MORECORE_CONTIGUOUS, but is
   changed dynamically if mmap is ever used as an sbrk substitute.
 */
// MORECORE是否返回連續的內存區域。
// 主分配區中的MORECORE其實爲sbr()，默認返回連續虛擬地址空間
// 非主分配區使用mmap()分配大塊虛擬內存，然後進行切分來模擬主分配區的行爲
// 而默認情況下mmap映射區域是不保證虛擬地址空間連續的，所以非主分配區默認分配非連續虛擬地址空間。
#define NONCONTIGUOUS_BIT (2U)

#define contiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) == 0)
#define noncontiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) != 0)
#define set_noncontiguous(M) ((M)->flags |= NONCONTIGUOUS_BIT)
#define set_contiguous(M) ((M)->flags &= ~NONCONTIGUOUS_BIT)

/* ARENA_CORRUPTION_BIT is set if a memory corruption was detected on the
   arena.  Such an arena is no longer used to allocate chunks.  Chunks
   allocated in that arena before detecting corruption are not freed.  */

#define ARENA_CORRUPTION_BIT (4U)

#define arena_is_corrupt(A) (((A)->flags & ARENA_CORRUPTION_BIT))
#define set_arena_corrupt(A) ((A)->flags |= ARENA_CORRUPTION_BIT)

/*
   Set value of max_fast.
   Use impossibly small value if 0.
   Precondition: there are no existing fastbin chunks.
   Setting the value clears fastchunk bit but preserves noncontiguous bit.
 */

#define set_max_fast(s)                                                        \
    global_max_fast =                                                          \
        (((s) == 0) ? SMALLBIN_WIDTH : ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK))
#define get_max_fast() global_max_fast
```

ptmalloc 默認情況下會調用 set_max_fast(s) 將全局變量 global_max_fast 設置爲 DEFAULT_MXFAST，也就是設置 fast bins 中 chunk 的最大值。當 MAX_FAST_SIZE 被設置爲 0 時，系統就不會支持 fastbin 。

**fastbin的索引**

```c++

#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[ idx ])

/* offset 2 to use otherwise unindexable first 2 bins */
// chunk size=2*size_sz*(2+idx)
// 這裏要減2，否則的話，前兩個bin沒有辦法索引到。
#define fastbin_index(sz)                                                      \
    ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```

**需要特別注意的是，fastbin 範圍的 chunk 的 inuse 始終被置爲 1。因此它們不會和其它被釋放的 chunk 合併。**

但是當釋放的 chunk 與該 chunk 相鄰的空閒 chunk 合併後的大小大於FASTBIN_CONSOLIDATION_THRESHOLD時，內存碎片可能比較多了，我們就需要把 fast bins 中的chunk都進行合併，以減少內存碎片對系統的影響。

```c++
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

#define FASTBIN_CONSOLIDATION_THRESHOLD (65536UL)
```

**malloc_consolidate 函數可以將 fastbin 中所有能和其它 chunk 合併的 chunk 合併在一起。具體地參見後續的詳細函數的分析。** 

```
/*
	Chunks in fastbins keep their inuse bit set, so they cannot
    be consolidated with other free chunks. malloc_consolidate
    releases all chunks in fastbins and consolidates them with
    other free chunks.
 */
```

#### Small Bin

small bins 中每個 chunk 的大小與其所在的 bin 的 index 的關係爲：chunk_size = 2 * SIZE_SZ *index，具體如下

| 下標   | SIZE_SZ=4（32位） | SIZE_SZ=8（64位） |
| ---- | -------------- | -------------- |
| 2    | 16             | 32             |
| 3    | 24             | 48             |
| 4    | 32             | 64             |
| 5    | 40             | 80             |
| x    | 2\*4\*x        | 2\*8\*x        |
| 63   | 504            | 1008           |

small bins 中一共有 62 個循環雙向鏈表，每個鏈表中存儲的 chunk 大小都一致。比如對於 32 位系統來說，下標 2 對應的雙向鏈表中存儲的 chunk 大小爲均爲 16 字節。每個鏈表都有鏈表頭結點，這樣可以方便對於鏈表內部結點的管理。此外，**small bins 中每個 bin 對應的鏈表採用 FIFO 的規則**，所以同一個鏈表中先被釋放的 chunk 會先被分配出去。

small bin相關的宏如下

```c++
#define NSMALLBINS 64
#define SMALLBIN_WIDTH MALLOC_ALIGNMENT
// 是否需要對small bin的下標進行糾正
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)

#define MIN_LARGE_SIZE ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
//判斷chunk的大小是否在small bin範圍內
#define in_smallbin_range(sz)                                                  \
    ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)
// 根據chunk的大小得到small bin對應的索引。
#define smallbin_index(sz)                                                     \
    ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4)                          \
                           : (((unsigned) (sz)) >> 3)) +                       \
     SMALLBIN_CORRECTION)
```

**或許，大家會很疑惑，那 fastbin 與 small bin 中 chunk 的大小會有很大一部分重合啊，那 small bin 中對應大小的 bin 是不是就沒有什麼作用啊？** 其實不然，fast bin 中的 chunk 是有可能被放到 small bin 中去的，我們在後面分析具體的源代碼時會有深刻的體會。

#### Large Bin

large bins 中一共包括 63 個 bin，每個 bin 中的 chunk 的大小不一致，而是處於一定區間範圍內。此外，這 63 個 bin 被分成了 6 組，每組 bin 中的 chunk 大小之間的公差一致，具體如下：

| 組    | 數量   | 公差      |
| ---- | ---- | ------- |
| 1    | 32   | 64B     |
| 2    | 16   | 512B    |
| 3    | 8    | 4096B   |
| 4    | 4    | 32768B  |
| 5    | 2    | 262144B |
| 6    | 1    | 不限制     |

這裏我們以 32 位平臺的 large bin 爲例，第一個 large bin 的起始 chunk 大小爲 512 字節，位於第一組，所以該bin 可以存儲的 chunk 的大小範圍爲 [512,512+64)。

關於 large bin 的宏如下，這裏我們以 32 位平臺下，第一個 large bin 的起始 chunk 大小爲例，爲 512 字節，那麼 512>>6 = 8，所以其下標爲56+8=64。

```c++
#define largebin_index_32(sz)                                                  \
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

#define largebin_index_32_big(sz)                                              \
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
#define largebin_index_64(sz)                                                  \
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

#define largebin_index(sz)                                                     \
    (SIZE_SZ == 8 ? largebin_index_64(sz) : MALLOC_ALIGNMENT == 16             \
                                                ? largebin_index_32_big(sz)    \
                                                : largebin_index_32(sz))
```

#### Unsorted Bin

unsorted bin 可以視爲空閒 chunk 迴歸其所屬 bin 之前的緩衝區。

其在 glibc 中具體的說明如下

```c++
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
```

從下面的宏我們可以看出

```c++
/* The otherwise unindexable 1-bin is used to hold unsorted chunks. */
#define unsorted_chunks(M) (bin_at(M, 1))
```

unsorted bin 處於我們之前所說的 bin 數組下標 1 處。故而 unsorted bin 只有一個鏈表。unsorted bin 中的空閒 chunk 處於亂序狀態，主要有兩個來源

- 當一個較大的 chunk 被分割成兩半後，如果剩下的部分大於 MINSIZE，就會被放到 unsorted bin 中。
- 釋放一個不屬於 fast bin 的 chunk，並且該 chunk 不和 top chunk 緊鄰時，該 chunk 會被首先放到 unsorted bin 中。關於 top chunk 的解釋，請參考下面的介紹。

此外，Unsorted Bin 在使用的過程中，採用的遍歷順序是 FIFO 。

#### common macro

這裏介紹一些通用的宏。

**根據chunk的大小統一地獲得chunk所在的索引**

```c++
#define bin_index(sz)                                                          \
    ((in_smallbin_range(sz)) ? smallbin_index(sz) : largebin_index(sz))
```

### Top Chunk

glibc 中對於 top chunk 的描述如下

```c++
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
#define initial_top(M) (unsorted_chunks(M))
```

程序第一次進行 malloc 的時候，heap 會被分爲兩塊，一塊給用戶，剩下的那塊就是 top chunk。其實，所謂的top chunk 就是處於當前堆的物理地址最高的 chunk。這個 chunk 不屬於任何一個 bin，它的作用在於當所有的bin 都無法滿足用戶請求的大小時，如果其大小不小於指定的大小，就進行分配，並將剩下的部分作爲新的 top chunk。否則，就對heap進行擴展後再進行分配。在main arena中通過sbrk擴展heap，而在thread arena中通過mmap分配新的heap。

需要注意的是，top chunk 的 prev_inuse 比特位始終爲1，否則其前面的chunk就會被合併到top chunk中。

**初始情況下，我們可以將 unsorted chunk 作爲 top chunk。**

### last remainder

在用戶使用 malloc 請求分配內存時，ptmalloc2 找到的 chunk 可能並不和申請的內存大小一致，這時候就將分割之後的剩餘部分稱之爲 last remainder chunk ，unsort bin 也會存這一塊。top chunk 分割剩下的部分不會作爲last remainder.

## 宏觀結構

### arena

在我們之前介紹的例子中，無論是主線程還是新創建的線程，在第一次申請內存時，都會有獨立的arena。那麼會不會每個線程都有獨立的arena呢？下面我們就具體介紹。

#### arena 數量

對於不同系統，arena數量的[約束](https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/arena.c#L847)如下

```text
For 32 bit systems:
     Number of arena = 2 * number of cores.
For 64 bit systems:
     Number of arena = 8 * number of cores.
```

顯然，不是每一個線程都會有對應的 arena。至於爲什麼64位系統，要那麼設置，我也沒有想明白。此外，因爲每個系統的核數是有限的，當線程數大於核數的二倍（超線程技術）時，就必然有線程處於等待狀態，所以沒有必要爲每個線程分配一個 arena。

#### arena 分配規則

**待補充。**

#### 區別

與 thread 不同的是，main_arena 並不在申請的 heap 中，而是一個全局變量，在 libc.so 的數據段。

### heap_info

程序剛開始執行時，每個線程是沒有 heap 區域的。當其申請內存時，就需要一個結構來記錄對應的信息，而heap_info 的作用就是這個。而且當該heap的資源被使用完後，就必須得再次申請內存了。此外，一般申請的heap 是不連續的，因此需要記錄不同heap之間的鏈接結構。

**該數據結構是專門爲從 Memory Mapping Segment 處申請的內存準備的，即爲非主線程準備的。**

主線程可以通過 sbrk() 函數擴展 program break location 獲得（直到觸及Memory Mapping Segment），只有一個heap，沒有 heap_info 數據結構。

heap_info 的主要結構如下

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

該結構主要是描述堆的基本信息，包括

- 堆對應的 arena 的地址
- 由於一個線程申請一個堆之後，可能會使用完，之後就必須得再次申請。因此，一個線程可能會有多個堆。prev即記錄了上一個 heap_info 的地址。這裏可以看到每個堆的 heap_info 是通過單向鏈表進行鏈接的。
- size 表示當前堆的大小
- 最後一部分確保對齊

!!! note "pad 裏負數的緣由是什麼呢？"
    `pad` 是爲了確保分配的空間是按照 `MALLOC_ALIGN_MASK+1` (記爲 `MALLOC_ALIGN_MASK_1`) 對齊的。在 `pad` 之前該結構體一共有 6 個 `SIZE_SZ` 大小的成員, 爲了確保  `MALLOC_ALIGN_MASK_1` 字節對齊, 可能需要進行 `pad`，不妨假設該結構體的最終大小爲 `MALLOC_ALIGN_MASK_1*x`，其中 `x` 爲自然數，那麼需要 `pad` 的空間爲 `MALLOC_ALIGN_MASK_1 * x - 6 * SIZE_SZ = (MALLOC_ALIGN_MASK_1 * x - 6 * SIZE_SZ) % MALLOC_ALIGN_MASK_1 = 0 - 6 * SIZE_SZ % MALLOC_ALIGN_MASK_1=-6 * SIZE_SZ % MALLOC_ALIGN_MASK_1 = -6 * SIZE_SZ & MALLOC_ALIGN_MASK`。

看起來該結構應該是相當重要的，但是如果如果我們仔細看完整個 malloc 的實現的話，就會發現它出現的頻率並不高。

### malloc_state

該結構用於管理堆，記錄每個 arena 當前申請的內存的具體狀態，比如說是否有空閒chunk，有什麼大小的空閒chunk 等等。無論是 thread arena 還是 main arena，它們都只有一個 malloc state 結構。由於 thread 的 arena 可能有多個，malloc state結構會在最新申請的arena中。

**注意，main arena 的 malloc_state 並不是 heap segment 的一部分，而是一個全局變量，存儲在 libc.so 的數據段。**

其結構如下

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

-   __libc_lock_define(, mutex);
    -   該變量用於控制程序串行訪問同一個分配區，當一個線程獲取了分配區之後，其它線程要想訪問該分配區，就必須等待該線程分配完成後纔能夠使用。

-   flags
    -   flags記錄了分配區的一些標誌，比如 bit0 記錄了分配區是否有 fast bin chunk ，bit1 標識分配區是否能返回連續的虛擬地址空間。具體如下

```c

/*
   FASTCHUNKS_BIT held in max_fast indicates that there are probably
   some fastbin chunks. It is set true on entering a chunk into any
   fastbin, and cleared only in malloc_consolidate.
   The truth value is inverted so that have_fastchunks will be true
   upon startup (since statics are zero-filled), simplifying
   initialization checks.
 */

#define FASTCHUNKS_BIT (1U)

#define have_fastchunks(M) (((M)->flags & FASTCHUNKS_BIT) == 0)
#define clear_fastchunks(M) catomic_or(&(M)->flags, FASTCHUNKS_BIT)
#define set_fastchunks(M) catomic_and(&(M)->flags, ~FASTCHUNKS_BIT)

/*
   NONCONTIGUOUS_BIT indicates that MORECORE does not return contiguous
   regions.  Otherwise, contiguity is exploited in merging together,
   when possible, results from consecutive MORECORE calls.
   The initial value comes from MORECORE_CONTIGUOUS, but is
   changed dynamically if mmap is ever used as an sbrk substitute.
 */

#define NONCONTIGUOUS_BIT (2U)

#define contiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) == 0)
#define noncontiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) != 0)
#define set_noncontiguous(M) ((M)->flags |= NONCONTIGUOUS_BIT)
#define set_contiguous(M) ((M)->flags &= ~NONCONTIGUOUS_BIT)

/* ARENA_CORRUPTION_BIT is set if a memory corruption was detected on the
   arena.  Such an arena is no longer used to allocate chunks.  Chunks
   allocated in that arena before detecting corruption are not freed.  */

#define ARENA_CORRUPTION_BIT (4U)

#define arena_is_corrupt(A) (((A)->flags & ARENA_CORRUPTION_BIT))
#define set_arena_corrupt(A) ((A)->flags |= ARENA_CORRUPTION_BIT)

```

-   fastbinsY[NFASTBINS]
    -   存放每個 fast chunk 鏈表頭部的指針
-   top
    -   指向分配區的 top chunk
-   last_reminder
    -   最新的 chunk 分割之後剩下的那部分
-   bins
    -   用於存儲 unstored bin，small bins 和 large bins 的 chunk 鏈表。
-   binmap
    -   ptmalloc 用一個 bit 來標識某一個 bin 中是否包含空閒 chunk 。

### malloc_par

**！！待補充！！**
