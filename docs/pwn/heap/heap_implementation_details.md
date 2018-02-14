---
typora-root-url: ../../../docs
---

# 深入理解堆的实现

仔细想一下，任何堆的实现都离不开以下两个方面的问题

-   宏观角度
    -   创建堆
    -   堆初始化
    -   删除堆
-   微观角度
    -   申请内存块
    -   释放内存块

当然，这些都还是比较高层面的想法，不同的堆的底层的实现会有所不同。

## 堆实现概览

## 堆初始化

堆初始化是在用户第一次申请内存时执行 malloc_consolidate 再执行 malloc_init_state 实现的。这里不做过多讲解。可以参见 `malloc_state 相关函数`。

## 创建堆

## 双向链表相关操作

### unlink

unlink 用来将一个双向 bin 链表中的一个 chunk 取出来，可能在以下地方使用

-   malloc
    -   从恰好大小合适的 large bin 中获取 chunk。
        -   **这里需要注意的是 fastbin 与 small bin 就没有使用 unlink，这就是为什么漏洞会经常出现在它们这里的原因。**
        -   依次遍历处理unsorted bin时也是没有unlink的。
    -   从比所需要的 chunk 相应的 bin 大的 bin 中取 chunk。
-   Free
    -   后向合并，合并物理相邻低地址空闲 chunk。
    -   前向合并，合并物理相邻高地址空闲 chunk（除了 top chunk）。
-   malloc_consolidate
    -   后向合并，合并物理相邻低地址空闲 chunk。
    -   前向合并，合并物理相邻高地址空闲 chunk（除了 top chunk）。
-   realloc
    -   前向扩展，合并物理相邻高地址空闲 chunk（除了top chunk）。


由于 unlink 使用非常频繁，所以 unlink 被实现为了一个宏，如下

```c
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            \
    // 由于 P 已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致。
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");			      \
    FD = P->fd;                                                                      \
    BK = P->bk;                                                                      \
    // 防止攻击者简单篡改空闲的 chunk 的 fd 与 bk 来实现任意写的效果。
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {                                                                      \
        FD->bk = BK;                                                              \
        BK->fd = FD;                                                              \
        // 下面主要考虑 P 对应的 nextsize 双向链表的修改
        if (!in_smallbin_range (chunksize_nomask (P))                              \
            // 如果P->fd_nextsize为 NULL，表明 P 未插入到 largbin 链表中。
            // 那么其实也就没有必要对 nextsize 字段进行修改了。
            // 这里没有去判断 bk_nextsize 字段，可能会出问题。
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {                      \
            // 类似于小的 chunk 的检查思路
            if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)              \
                || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
              malloc_printerr (check_action,                                      \
                               "corrupted double-linked list (not small)",    \
                               P, AV);                                              \
            // 这里说明 P 已经在 nextsize 链表中了。
            // 如果 FD 没有在 nextsize 链表中
            if (FD->fd_nextsize == NULL) {                                      \
                // 如果 nextsize 串起来的双链表只有 P 本身，那就直接拿走 P
                // 令 FD 为 nextsize 串起来的
                if (P->fd_nextsize == P)                                      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;                      \
                else {                                                              \
                // 否则我们需要将 FD 插入到 nextsize 形成的双链表中
                    FD->fd_nextsize = P->fd_nextsize;                              \
                    FD->bk_nextsize = P->bk_nextsize;                              \
                    P->fd_nextsize->bk_nextsize = FD;                              \
                    P->bk_nextsize->fd_nextsize = FD;                              \
                  }                                                              \
              } else {                                                              \
                // 如果在的话，直接拿走即可
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;                      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;                      \
              }                                                                      \
          }                                                                      \
      }                                                                              \
}
```

这里我们只是以 small bin 的 unlink 为例子介绍一下。对于 large bin 的 unlink，与其类似，只是多了一个nextsize 的处理。

![](/pwn/heap/figure/unlink_smallbin_intro.png)

可以看出， **P 最后的 fd 和 bk 指针并没有发生变化**，但是当我们去遍历整个双向链表时，已经遍历不到对应的链表了。这一点没有变化还是很有用处的。

同时，对于无论是对于 fd，bk 还是 fd_nextsize ，bk_nextsize，程序都做了相应的检测。

```c
// fd bk
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
  malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
  
  // next_size related
              if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)              \
                || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
              malloc_printerr (check_action,                                      \
                               "corrupted double-linked list (not small)",    \
                               P, AV);   
```

看起来似乎很正常。我们以 fd 和 bk 为例，P 的 forward chunk 的 bk 很自然是 P ，同样 P 的 backward chunk 的 fd 也很自然是 P 。如果没有做相应的检查的话，我们可以修改 P 的 fd 与 bk，从而可以很容易地达到任意地址写的效果。关于更加详细的例子，可以参见利用部分的 unlink 。

**注意：堆的第一个chunk的话所记录的prev_inuse位默认为1。**

## 申请内存块

我们之前也说了，我们会使用 malloc 函数来申请内存块，可是当我们仔细看看 glibc 的源码实现时，其实并没有malloc 函数。其实该函数真正调用的是 \_\_libc_malloc 函数。为什么不直接写个 malloc 函数呢，因为有时候我们可能需要不同的名称。此外，__libc_malloc 函数只是用来简单封装 _int_malloc 函数。\_int_malloc 才是申请内存块的核心。下面我们来仔细分析一下实现。

### __libc_malloc

该函数会首先检查是否有内存分配函数的钩子函数（__malloc_hook）。该函数主要用于进程在创建新线程过程中分配内存或者用户自定义的分配函数。这里需要注意的是，**用户申请的字节一旦进入申请内存函数中就变成了无符号整数**。

```c++
// wapper for int_malloc
void *__libc_malloc(size_t bytes) {
    mstate ar_ptr;
    void * victim;
    // 检查是否有内存分配钩子，如果有，调用钩子并返回.
    void *(*hook)(size_t, const void *) = atomic_forced_read(__malloc_hook);
    if (__builtin_expect(hook != NULL, 0))
        return (*hook)(bytes, RETURN_ADDRESS(0));

```

接着会寻找一个 arena 来试图分配内存。

```c++
    arena_get(ar_ptr, bytes);
```

然后调用 _int_malloc 函数去申请对应的内存。

```c++
    victim = _int_malloc(ar_ptr, bytes);
```

如果分配失败的话，ptmalloc 会尝试再去寻找一个可用的 arena，并分配内存。

```c++
    /* Retry with another arena only if we were able to find a usable arena
       before.  */
    if (!victim && ar_ptr != NULL) {
        LIBC_PROBE(memory_malloc_retry, 1, bytes);
        ar_ptr = arena_get_retry(ar_ptr, bytes);
        victim = _int_malloc(ar_ptr, bytes);
    }
```

如果申请到了 arena，那么在退出之前还得解锁。

```c++
    if (ar_ptr != NULL) __libc_lock_unlock(ar_ptr->mutex);
```

判断目前的状态是否满足以下条件，要么没有申请到内存，要么是 mmap 的内存，**要么申请到的内存必须在其所分配的arena中**。

```c++
    assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
           ar_ptr == arena_for_chunk(mem2chunk(victim)));
```

最后返回内存。

```c++
    return victim;
}
```



### _int_malloc

_int_malloc 是内存分配的核心函数，其核心思路有如下

1. 它根据用户申请的内存块的大小以及相应大小 chunk 使用的频度（fastbin chunk, small chunk, large chunk），依次实现了不同的分配方法。
2. 它由小到大依次检查不同的 bin 中是否有相应的空闲块可以满足需求。
3. 当所有的空闲 chunk 都无法满足时，它会考虑 top chunk。
4. 当 top chunk 也无法满足时，堆分配器才会进行内存块申请。

在进入该函数后，函数立马定义了一系列自己需要的变量，并将用户申请的内存大小转换为内部的chunk大小。

```c++
static void *_int_malloc(mstate av, size_t bytes) {
    INTERNAL_SIZE_T nb;  /* normalized request size */
    unsigned int    idx; /* associated bin index */
    mbinptr         bin; /* associated bin */

    mchunkptr       victim;       /* inspected/selected chunk */
    INTERNAL_SIZE_T size;         /* its size */
    int             victim_index; /* its bin index */

    mchunkptr     remainder;      /* remainder from a split */
    unsigned long remainder_size; /* its size */

    unsigned int block; /* bit map traverser */
    unsigned int bit;   /* bit map traverser */
    unsigned int map;   /* current word of binmap */

    mchunkptr fwd; /* misc temp for linking */
    mchunkptr bck; /* misc temp for linking */

    const char *errstr = NULL;

    /*
       Convert request size to internal form by adding SIZE_SZ bytes
       overhead plus possibly more to obtain necessary alignment and/or
       to obtain a size of at least MINSIZE, the smallest allocatable
       size. Also, checked_request2size traps (returning 0) request sizes
       that are so large that they wrap around zero when padded and
       aligned.
     */

    checked_request2size(bytes, nb);
```

#### arena

```c++
    /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
       mmap.  */
    if (__glibc_unlikely(av == NULL)) {
        void *p = sysmalloc(nb, av);
        if (p != NULL) alloc_perturb(p, bytes);
        return p;
    }
```

#### fast bin

如果申请的 chunk 的大小位于 fastbin 范围内，**需要注意的是这里比较的是无符号整数**。**此外，是从 fastbin 的头结点开始取 chunk**。

```c++
    /*
       If the size qualifies as a fastbin, first check corresponding bin.
       This code is safe to execute even if av is not yet initialized, so we
       can try it without checking, which saves some time on this fast path.
     */

    if ((unsigned long) (nb) <= (unsigned long) (get_max_fast())) {
        // 得到对应的fastbin的下标
        idx             = fastbin_index(nb);
        // 得到对应的fastbin的头指针
        mfastbinptr *fb = &fastbin(av, idx);
        mchunkptr    pp = *fb;
        // 利用fd遍历对应的bin内是否有空闲的chunk块，
        do {
            victim = pp;
            if (victim == NULL) break;
        } while ((pp = catomic_compare_and_exchange_val_acq(fb, victim->fd,
                                                            victim)) != victim);
        // 存在可以利用的chunk
        if (victim != 0) {
            // 检查取到的 chunk 大小是否与相应的 fastbin 索引一致。
            // 根据取得的 victim ，利用 chunksize 计算其大小。
            // 利用fastbin_index 计算 chunk 的索引。
            if (__builtin_expect(fastbin_index(chunksize(victim)) != idx, 0)) {
                errstr = "malloc(): memory corruption (fast)";
            errout:
                malloc_printerr(check_action, errstr, chunk2mem(victim), av);
                return NULL;
            }
            // 细致的检查。。只有在 DEBUG 的时候有用
            check_remalloced_chunk(av, victim, nb);
            // 将获取的到chunk转换为mem模式
            void *p = chunk2mem(victim);
            // 如果设置了perturb_type, 则将获取到的chunk初始化为 perturb_type ^ 0xff
            alloc_perturb(p, bytes);
            return p;
        }
    }
```

#### small bin

如果获取的内存块的范围处于 small bin 的范围，那么执行如下流程

```c++
    /*
       If a small request, check regular bin.  Since these "smallbins"
       hold one size each, no searching within bins is necessary.
       (For a large request, we need to wait until unsorted chunks are
       processed to find best fit. But for small ones, fits are exact
       anyway, so we can check now, which is faster.)
     */

    if (in_smallbin_range(nb)) {
        // 获取 small bin 的索引
        idx = smallbin_index(nb);
        // 获取对应 small bin 中的 chunk 指针
        bin = bin_at(av, idx);
        // 先执行 victim = last(bin)，获取 small bin 的最后一个 chunk
        // 如果 victim = bin ，那说明该 bin 为空。
        // 如果不相等，那么会有两种情况
        if ((victim = last(bin)) != bin) {
            // 第一种情况，small bin 还没有初始化。
            if (victim == 0) /* initialization check */
                // 执行初始化，将 fast bins 中的 chunk 进行合并
                malloc_consolidate(av);
            // 第二种情况，small bin 中存在空闲的 chunk
            else {
                // 获取 small bin 中倒数第二个 chunk 。
                bck = victim->bk;
                // 检查 bck->fd 是不是 victim，防止伪造
                if (__glibc_unlikely(bck->fd != victim)) {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                // 设置 victim 对应的 inuse 位
                set_inuse_bit_at_offset(victim, nb);
                // 修改 small bin 链表，将 small bin 的最后一个 chunk 取出来
                bin->bk = bck;
                bck->fd = bin;
                // 如果不是 main_arena，设置对应的标志
                if (av != &main_arena) set_non_main_arena(victim);
                // 细致的检查，非调试状态没有作用
                check_malloced_chunk(av, victim, nb);
                // 将申请到的 chunk 转化为对应的 mem 状态
                void *p = chunk2mem(victim);
                // 如果设置了 perturb_type , 则将获取到的chunk初始化为 perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
        }
    }
```

#### large bin

当 fast bin、small bin 中的 chunk 都不能满足用户请求 chunk 大小时，就会考虑是不是 large bin。但是，其实在 large bin 中并没有直接去扫描对应 bin 中的chunk，而是先利用 malloc_consolidate（参见malloc_state相关函数） 函数处理 fast bin 中的chunk，将有可能能够合并的 chunk 先进行合并后放到 unsorted bin 中，不能够合并的就直接放到 unsorted bin 中，然后再在下面的大循环中进行相应的处理。**为什么不直接从相应的 bin 中取出 large chunk 呢？这是ptmalloc 的机制，它会在分配 large chunk 之前对堆中碎片 chunk 进行合并，以便减少堆中的碎片。**

```c++
    /*
       If this is a large request, consolidate fastbins before continuing.
       While it might look excessive to kill all fastbins before
       even seeing if there is space available, this avoids
       fragmentation problems normally associated with fastbins.
       Also, in practice, programs tend to have runs of either small or
       large requests, but less often mixtures, so consolidation is not
       invoked all that often in most programs. And the programs that
       it is called frequently in otherwise tend to fragment.
     */

    else {
        // 获取large bin的下标。
        idx = largebin_index(nb);
        // 如果存在fastbin的话，会处理 fastbin 
        if (have_fastchunks(av)) malloc_consolidate(av);
    }

```

#### 大循环

**如果程序执行到了这里，那么说明 与 chunk 大小正好一致的 bin (fast bin， small bin) 中没有 chunk可以直接满足需求 ，但是large chunk  则是在这个大循环中处理**。

在接下来的这个循环中，主要做了以下的操作

- 尝试从 unsorted bin 中分配用户所需的内存
- 尝试从 large bin 中分配用户所需的内存
- 尝试从 top  chunk 中分配用户所需内存

该部分是一个大循环，这是为了尝试重新分配 small bin chunk，这是因为我们虽然会首先使用 large bin，top chunk 来尝试满足用户的请求，但是如果没有满足的话，由于我们在上面没有分配成功 small bin，我们并没有对fast bin 中的 chunk 进行合并，所以这里会进行 fast bin chunk 的合并，进而使用一个大循环来尝试再次分配small bin chunk。

```c++
    /*
       Process recently freed or remaindered chunks, taking one only if
       it is exact fit, or, if this a small request, the chunk is remainder from
       the most recent non-exact fit.  Place other traversed chunks in
       bins.  Note that this step is the only place in any routine where
       chunks are placed in bins.

       The outer loop here is needed because we might not realize until
       near the end of malloc that we should have consolidated, so must
       do so and retry. This happens at most once, and only when we would
       otherwise need to expand memory to service a "small" request.
     */

    for (;;) {
        int iters = 0;
```

##### unsort bin 遍历

先考虑 unsorted bin，再考虑 last remainder ，但是对于small bin chunk 的请求会有所例外。

**注意 unsorted bin 的遍历顺序为 bk。**

```c++
        // 如果 unsorted bin 不为空
        // First In First Out
        while ((victim = unsorted_chunks(av)->bk) != unsorted_chunks(av)) {
            // victim 为 unsorted bin 的最后一个 chunk
            // bck 为 unsorted bin 的倒数第二个 chunk
            bck = victim->bk;
            // 判断得到的 chunk 是否满足要求，不能过小，也不能过大
            // 一般 system_mem 的大小为132K
            if (__builtin_expect(chunksize_nomask(victim) <= 2 * SIZE_SZ, 0) ||
                __builtin_expect(chunksize_nomask(victim) > av->system_mem, 0))
                malloc_printerr(check_action, "malloc(): memory corruption",
                                chunk2mem(victim), av);
            // 得到victim对应的chunk大小。
            size = chunksize(victim);
```

###### small request

如果用户的请求为 small bin chunk，那么我们首先考虑 last remainder，如果 last remainder 是 unsorted bin 中的唯一一块的话， 并且 last remainder 的大小分割够还可以作为一个 chunk ，**为什么没有等号**？

```c
            /*
               If a small request, try to use last remainder if it is the
               only chunk in unsorted bin.  This helps promote locality for
               runs of consecutive small requests. This is the only
               exception to best-fit, and applies only when there is
               no exact fit for a small chunk.
             */

            if (in_smallbin_range(nb) && bck == unsorted_chunks(av) &&
                victim == av->last_remainder &&
                (unsigned long) (size) > (unsigned long) (nb + MINSIZE)) {
                /* split and reattach remainder */
                // 获取新的 remainder 的大小
                remainder_size          = size - nb;
                // 获取新的 remainder 的位置
                remainder               = chunk_at_offset(victim, nb);
                // 更新 unsorted bin 的情况
                unsorted_chunks(av)->bk = unsorted_chunks(av)->fd = remainder;
                // 更新 av 中记录的 last_remainder
                av->last_remainder                                = remainder;
                // 更新last remainder的指针
                remainder->bk = remainder->fd = unsorted_chunks(av);
                if (!in_smallbin_range(remainder_size)) {
                    remainder->fd_nextsize = NULL;
                    remainder->bk_nextsize = NULL;
                }
                // 设置victim的头部，
                set_head(victim, nb | PREV_INUSE |
                                     (av != &main_arena ? NON_MAIN_ARENA : 0));
                // 设置 remainder 的头部
                set_head(remainder, remainder_size | PREV_INUSE);
                // 设置记录 remainder 大小的 prev_size 字段，因为此时 remainder 处于空闲状态。
                set_foot(remainder, remainder_size);
                // 细致的检查，非调试状态下没有作用
                check_malloced_chunk(av, victim, nb);
                // 将 victim 从 chunk 模式转化为mem模式
                void *p = chunk2mem(victim);
                // 如果设置了perturb_type, 则将获取到的chunk初始化为 perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
```

###### 初始取出

```c
            /* remove from unsorted list */
            unsorted_chunks(av)->bk = bck;
            bck->fd                 = unsorted_chunks(av);
```

###### exact fit

如果从 unsorted bin 中取出来的 chunk 大小正好合适，就直接使用。这里应该已经把合并后恰好合适的 chunk 给分配出去了。

```c
            /* Take now instead of binning if exact fit */
            if (size == nb) {
                set_inuse_bit_at_offset(victim, size);
                if (av != &main_arena) set_non_main_arena(victim);
                check_malloced_chunk(av, victim, nb);
                void *p = chunk2mem(victim);
                alloc_perturb(p, bytes);
                return p;
            }
```

###### place chunk in small bin

把取出来的 chunk 放到对应的 small bin 中。

```c
            /* place chunk in bin */

            if (in_smallbin_range(size)) {
                victim_index = smallbin_index(size);
                bck          = bin_at(av, victim_index);
                fwd          = bck->fd;
```

###### place chunk in large bin

把取出来的 chunk 放到对应的 large bin 中。

```c
            } else {
                // large bin范围
                victim_index = largebin_index(size);
                bck          = bin_at(av, victim_index);
                fwd          = bck->fd;

                /* maintain large bins in sorted order */
                /* 从这里我们可以总结出，largebin 以 fd_nextsize 递减排序。
                   同样大小的 chunk，后来的只会插入到之前同样大小的 chunk 后，
                   而不会修改之前相同大小的fd/bk_nextsize，这也很容易理解，
                   可以减低开销。此外，bin 头不参与 nextsize 链接。*/
                // 如果 large bin 链表不空
                if (fwd != bck) {
                    /* Or with inuse bit to speed comparisons */
                    // 加速比较，应该不仅仅有这个考虑，因为链表里的chunk都会设置该位。
                    size |= PREV_INUSE;
                    /* if smaller than smallest, bypass loop below */
                    // bck-bk 存储着相应 large bin 中最小的chunk。
                    // 如果遍历的chunk比当前最小的还要小，那就只需要插入到链表尾部。
                    // 判断 bck->bk 是不是在 main arena。
                    assert(chunk_main_arena(bck->bk));
                    if ((unsigned long) (size) <
                        (unsigned long) chunksize_nomask(bck->bk)) {
                        // 令 fwd 指向 bin 头
                        fwd = bck;
                        // 令 bck 指向 bin 尾
                        bck = bck->bk;
                        // victim 的 fd_nextsize 指向链表的第一个 chunk
                        victim->fd_nextsize = fwd->fd;
                        // victim 的 bk_nextsize 指向原来链表的第一个chunk 指向的bk_nextsize
                        victim->bk_nextsize = fwd->fd->bk_nextsize;
                        // 原来链表的第一个 chunk 的 bk_nextsize 指向 victim
                        // 原来指向链表第一个 chunk 的 fd_nextsize 指向 victim
                        fwd->fd->bk_nextsize =
                            victim->bk_nextsize->fd_nextsize = victim;
                    } else {
                        // 当前要插入的 victim 的大小大于最小的 chunk 
                        // 判断 fwd 是否在 main arena
                        assert(chunk_main_arena(fwd));
                        // 从链表头部开始找到不比 victim 大的 chunk
                        while ((unsigned long) size < chunksize_nomask(fwd)) {
                            fwd = fwd->fd_nextsize;
                            assert(chunk_main_arena(fwd));
                        }
                        // 如果找到了一个和 victim 一样大的 chunk，
                        // 那就直接将 chunk 插入到该chunk的后面，并不修改 nextsize 指针。
                        if ((unsigned long) size ==
                            (unsigned long) chunksize_nomask(fwd))
                            /* Always insert in the second position.  */
                            fwd = fwd->fd;
                        else {
                            // 如果找到的chunk和当前victim大小不一样
                            // 那么久需要构造 nextsize 双向链表了
                            victim->fd_nextsize              = fwd;
                            victim->bk_nextsize              = fwd->bk_nextsize;
                            fwd->bk_nextsize                 = victim;
                            victim->bk_nextsize->fd_nextsize = victim;
                        }
                        bck = fwd->bk;
                    }
                } else
                    // 如果空的话，直接简单使得 fd_nextsize 与 bk_nextsize 构成一个双向链表即可。
                    victim->fd_nextsize = victim->bk_nextsize = victim;
            }
```

###### 最终取出

```c
            // 放到对应的 bin 中，构成 bk<-->victim<-->fwd。
            mark_bin(av, victim_index);
            victim->bk = bck;
            victim->fd = fwd;
            fwd->bk    = victim;
            bck->fd    = victim;
```

###### while 迭代次数

while 最多迭代10000次后退出。

```c
            // 
##define MAX_ITERS 10000
            if (++iters >= MAX_ITERS) break;
        }
```

##### large chunk

**注： 或许会很奇怪，为什么这里没有先去看 small chunk 是否满足新需求了呢？这是因为small bin 在循环之前已经判断过了，这里如果有的话，就是合并后的才出现chunk。但是在大循环外，large chunk 只是单纯地找到其索引，所以觉得在这里直接先判断是合理的，而且也为了下面可以再去找较大的chunk。**

如果请求的 chunk 在 large chunk 范围内，就在对应的 bin 中从小到大进行扫描，找到第一个合适的。

```c++
        /*
           If a large request, scan through the chunks of current bin in
           sorted order to find smallest that fits.  Use the skip list for this.
         */
        if (!in_smallbin_range(nb)) {
            bin = bin_at(av, idx);
            /* skip scan if empty or largest chunk is too small */
            // 如果对应的 bin 为空或者其中的chunk最大的也很小，那就跳过
            // first(bin)=bin->fd 表示当前链表中最大的chunk
            if ((victim = first(bin)) != bin &&
                (unsigned long) chunksize_nomask(victim) >=
                    (unsigned long) (nb)) {
                // 反向遍历链表，直到找到第一个不小于所需chunk大小的chunk
                victim = victim->bk_nextsize;
                while (((unsigned long) (size = chunksize(victim)) <
                        (unsigned long) (nb)))
                    victim = victim->bk_nextsize;

                /* Avoid removing the first entry for a size so that the skip
                   list does not have to be rerouted.  */
                // 如果最终取到的chunk不是该bin中的最后一个chunk，并且该chunk与其前面的chunk
                // 的大小相同，那么我们就取其前面的chunk，这样可以避免调整bk_nextsize,fd_nextsize
                //  链表。因为大小相同的chunk只有一个会被串在nextsize链上。
                if (victim != last(bin) &&
                    chunksize_nomask(victim) == chunksize_nomask(victim->fd))
                    victim = victim->fd;
                // 计算分配后剩余的大小
                remainder_size = size - nb;
                // 进行unlink
                unlink(av, victim, bck, fwd);

                /* Exhaust */
                // 剩下的大小不足以当做一个块
                // 很好奇接下来会怎么办？
                if (remainder_size < MINSIZE) {
                    set_inuse_bit_at_offset(victim, size);
                    if (av != &main_arena) set_non_main_arena(victim);
                }
                /* Split */
                //  剩下的大小还可以作为一个chunk，进行分割。
                else {
                    // 获取剩下那部分chunk的指针，称为remainder
                    remainder = chunk_at_offset(victim, nb);
                    /* We cannot assume the unsorted list is empty and therefore
                       have to perform a complete insert here.  */
                    // 插入unsorted bin中
                    bck = unsorted_chunks(av);
                    fwd = bck->fd;
                    // 判断 unsorted bin 是否被破坏。
                    if (__glibc_unlikely(fwd->bk != bck)) {
                        errstr = "malloc(): corrupted unsorted chunks";
                        goto errout;
                    }
                    remainder->bk = bck;
                    remainder->fd = fwd;
                    bck->fd       = remainder;
                    fwd->bk       = remainder;
                    // 如果不处于small bin范围内，就设置对应的字段
                    if (!in_smallbin_range(remainder_size)) {
                        remainder->fd_nextsize = NULL;
                        remainder->bk_nextsize = NULL;
                    }
                    // 设置分配的chunk的标记
                    set_head(victim,
                             nb | PREV_INUSE |
                                 (av != &main_arena ? NON_MAIN_ARENA : 0));
                  
                    // 设置remainder的上一个chunk，即分配出去的chunk的使用状态
                    // 其余的不用管，直接从上面继承下来了
                    set_head(remainder, remainder_size | PREV_INUSE);
                    // 设置remainder的大小
                    set_foot(remainder, remainder_size);
                }
                // 检查
                check_malloced_chunk(av, victim, nb);
                // 转换为mem状态
                void *p = chunk2mem(victim);
                // 如果设置了perturb_type, 则将获取到的chunk初始化为 perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
        }
```

##### 寻找较大 chunk

如果走到了这里，那说明对于用户所需的chunk，不能直接从其对应的合适的bin中获取chunk，所以我们需要来查找比当前 bin 更大的 fast bin ， small bin 或者 large bin。

```c++
        /*
           Search for a chunk by scanning bins, starting with next largest
           bin. This search is strictly by best-fit; i.e., the smallest
           (with ties going to approximately the least recently used) chunk
           that fits is selected.

           The bitmap avoids needing to check that most blocks are nonempty.
           The particular case of skipping all bins during warm-up phases
           when no chunks have been returned yet is faster than it might look.
         */

        ++idx;
        // 获取对应的bin
        bin   = bin_at(av, idx);
        // 获取当前索引在binmap中的block索引
        // #define idx2block(i) ((i) >> BINMAPSHIFT)  ,BINMAPSHIFT=5
        // Binmap按block管理，每个block为一个int，共32个bit，可以表示32个bin中是否有空闲chunk存在
        // 所以这里是右移5
        block = idx2block(idx);
        // 获取当前块大小对应的映射，这里可以得知相应的bin中是否有空闲块
        map   = av->binmap[ block ];
        // #define idx2bit(i) ((1U << ((i) & ((1U << BINMAPSHIFT) - 1))))
        // 将idx对应的比特位设置为1，其它位为0
        bit   = idx2bit(idx);
        for (;;) {
```

###### 找到一个合适的 map

```c++
            /* Skip rest of block if there are no more set bits in this block.
             */
            // 如果bit>map，则表示该 map 中没有比当前所需要chunk大的空闲块
            // 如果bit为0，那么说明，上面idx2bit带入的参数为0。
            if (bit > map || bit == 0) {
                do {
                    // 寻找下一个block，直到其对应的map不为0。
                    // 如果已经不存在的话，那就只能使用top chunk了
                    if (++block >= BINMAPSIZE) /* out of bins */
                        goto use_top;
                } while ((map = av->binmap[ block ]) == 0);
                // 获取其对应的bin，因为该map中的chunk大小都比所需的chunk大，而且
                // map本身不为0，所以必然存在满足需求的chunk。
                bin = bin_at(av, (block << BINMAPSHIFT));
                bit = 1;
            }
```

###### 找到合适的 bin

```c
            /* Advance to bin with set bit. There must be one. */
            // 从当前map的最小的bin一直找，直到找到合适的bin。
            // 这里是一定存在的
            while ((bit & map) == 0) {
                bin = next_bin(bin);
                bit <<= 1;
                assert(bit != 0);
            }
```

###### 简单检查 chunk

```c

            /* Inspect the bin. It is likely to be non-empty */
            // 获取对应的bin
            victim = last(bin);

            /*  If a false alarm (empty bin), clear the bit. */
            // 如果victim=bin，那么我们就将map对应的位清0，然后获取下一个bin
            // 这种情况发生的概率应该很小。
            if (victim == bin) {
                av->binmap[ block ] = map &= ~bit; /* Write through */
                bin                 = next_bin(bin);
                bit <<= 1;
            }
```

###### 真正取出chunk

```c
            else {
                // 获取对应victim的大小
                size = chunksize(victim);

                /*  We know the first chunk in this bin is big enough to use. */
                assert((unsigned long) (size) >= (unsigned long) (nb));
                // 计算分割后剩余的大小
                remainder_size = size - nb;

                /* unlink */
                unlink(av, victim, bck, fwd);

                /* Exhaust */
                // 如果分割后不够一个chunk怎么办？
                if (remainder_size < MINSIZE) {
                    set_inuse_bit_at_offset(victim, size);
                    if (av != &main_arena) set_non_main_arena(victim);
                }

                /* Split */
                // 如果够，尽管分割
                else {
                    // 计算剩余的chunk的偏移
                    remainder = chunk_at_offset(victim, nb);

                    /* We cannot assume the unsorted list is empty and therefore
                       have to perform a complete insert here.  */
                    // 将剩余的chunk插入到unsorted bin中
                    bck = unsorted_chunks(av);
                    fwd = bck->fd;
                    if (__glibc_unlikely(fwd->bk != bck)) {
                        errstr = "malloc(): corrupted unsorted chunks 2";
                        goto errout;
                    }
                    remainder->bk = bck;
                    remainder->fd = fwd;
                    bck->fd       = remainder;
                    fwd->bk       = remainder;

                    /* advertise as last remainder */
                    // 如果在small bin范围内，就将其标记为remainder
                    if (in_smallbin_range(nb)) av->last_remainder = remainder;
                    if (!in_smallbin_range(remainder_size)) {
                        remainder->fd_nextsize = NULL;
                        remainder->bk_nextsize = NULL;
                    }
                    // 设置victim的使用状态
                    set_head(victim,
                             nb | PREV_INUSE |
                                 (av != &main_arena ? NON_MAIN_ARENA : 0));
                    // 设置remainder的使用状态，这里是为什么呢？
                    set_head(remainder, remainder_size | PREV_INUSE);
                    // 设置remainder的大小
                    set_foot(remainder, remainder_size);
                }
                // 检查
                check_malloced_chunk(av, victim, nb);
                // chunk状态转换到mem状态
                void *p = chunk2mem(victim);
                // 如果设置了perturb_type, 则将获取到的chunk初始化为 perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
```

##### 使用 top chunk

如果所有的 bin 中的 chunk 都没有办法直接满足要求（即不合并），或者说都没有空闲的 chunk。那么我们就只能使用 top chunk 了。

```c++
    use_top:
        /*
           If large enough, split off the chunk bordering the end of memory
           (held in av->top). Note that this is in accord with the best-fit
           search rule.  In effect, av->top is treated as larger (and thus
           less well fitting) than any other available chunk since it can
           be extended to be as large as necessary (up to system
           limitations).

           We require that av->top always exists (i.e., has size >=
           MINSIZE) after initialization, so if it would otherwise be
           exhausted by current request, it is replenished. (The main
           reason for ensuring it exists is that we may need MINSIZE space
           to put in fenceposts in sysmalloc.)
         */
        // 获取当前的top chunk，并计算其对应的大小
        victim = av->top;
        size   = chunksize(victim);
        // 如果分割之后，top chunk 大小仍然满足 chunk 的最小大小，那么就可以直接进行分割。
        if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) {
            remainder_size = size - nb;
            remainder      = chunk_at_offset(victim, nb);
            av->top        = remainder;
            // 这里设置 PREV_INUSE 是因为 top chunk 的 chunk 如果不是 fastbin，就必然会和
            // top chunk 合并，所以这里设置了 PREV_INUSE。
            set_head(victim, nb | PREV_INUSE |
                                 (av != &main_arena ? NON_MAIN_ARENA : 0));
            set_head(remainder, remainder_size | PREV_INUSE);

            check_malloced_chunk(av, victim, nb);
            void *p = chunk2mem(victim);
            alloc_perturb(p, bytes);
            return p;
        }
        // 否则，判断是否有 fast chunk
        /* When we are using atomic ops to free fast chunks we can get
           here for all block sizes.  */
        else if (have_fastchunks(av)) {
            // 先执行一次fast bin的合并
            malloc_consolidate(av);
            /* restore original bin index */
            // 判断需要的chunk是在small bin范围内还是large bin范围内
            // 并计算对应的索引
            // 等待下次再看看是否可以
            if (in_smallbin_range(nb))
                idx = smallbin_index(nb);
            else
                idx = largebin_index(nb);
        }

        /*
           Otherwise, relay to handle system-dependent cases
         */
        // 否则的话，我们就只能从系统中再次申请一点内存了。
        else {
            void *p = sysmalloc(nb, av);
            if (p != NULL) alloc_perturb(p, bytes);
            return p;
        }
```



### _libc_calloc

calloc 也是 libc 中的一种申请内存块的函数。在 `libc`中的包装为 `_libc_calloc`，具体介绍如下

```c
/*
  calloc(size_t n_elements, size_t element_size);
  Returns a pointer to n_elements * element_size bytes, with all locations
  set to zero.
*/
void*  __libc_calloc(size_t, size_t);
```

### sysmalloc

有时间的时候再分析。

## 释放内存块

### __libc_free

类似于 malloc，free 函数也有一层封装，命名格式与 malloc 基本类似。代码如下

```c++
void __libc_free(void *mem) {
    mstate    ar_ptr;
    mchunkptr p; /* chunk corresponding to mem */
    // 判断是否有钩子函数 __free_hook
    void (*hook)(void *, const void *) = atomic_forced_read(__free_hook);
    if (__builtin_expect(hook != NULL, 0)) {
        (*hook)(mem, RETURN_ADDRESS(0));
        return;
    }
    // free NULL没有作用
    if (mem == 0) /* free(0) has no effect */
        return;
    // 将mem转换为chunk状态
    p = mem2chunk(mem);
    // 如果该块内存是mmap得到的
    if (chunk_is_mmapped(p)) /* release mmapped memory. */
    {
        /* See if the dynamic brk/mmap threshold needs adjusting.
       Dumped fake mmapped chunks do not affect the threshold.  */
        if (!mp_.no_dyn_threshold && chunksize_nomask(p) > mp_.mmap_threshold &&
            chunksize_nomask(p) <= DEFAULT_MMAP_THRESHOLD_MAX &&
            !DUMPED_MAIN_ARENA_CHUNK(p)) {
            mp_.mmap_threshold = chunksize(p);
            mp_.trim_threshold = 2 * mp_.mmap_threshold;
            LIBC_PROBE(memory_mallopt_free_dyn_thresholds, 2,
                       mp_.mmap_threshold, mp_.trim_threshold);
        }
        munmap_chunk(p);
        return;
    }
    // 根据chunk获得分配区的指针
    ar_ptr = arena_for_chunk(p);
    // 执行释放
    _int_free(ar_ptr, p, 0);
}
```

### _int_free

函数初始时刻定义了一系列的变量，并且得到了用户想要释放的 chunk 的大小

```c++
static void _int_free(mstate av, mchunkptr p, int have_lock) {
    INTERNAL_SIZE_T size;      /* its size */
    mfastbinptr *   fb;        /* associated fastbin */
    mchunkptr       nextchunk; /* next contiguous chunk */
    INTERNAL_SIZE_T nextsize;  /* its size */
    int             nextinuse; /* true if nextchunk is used */
    INTERNAL_SIZE_T prevsize;  /* size of previous contiguous chunk */
    mchunkptr       bck;       /* misc temp for linking */
    mchunkptr       fwd;       /* misc temp for linking */

    const char *errstr = NULL;
    int         locked = 0;

    size = chunksize(p);
```

#### 简单的检查

```c++
    /* Little security check which won't hurt performance: the
       allocator never wrapps around at the end of the address space.
       Therefore we can exclude some size values which might appear
       here by accident or by "design" from some intruder.  */
    // 指针不能指向非法的地址, 必须小于等于-size，为什么？？？
    // 指针必须得对齐，2*SIZE_SZ 这个对齐得仔细想想
    if (__builtin_expect((uintptr_t) p > (uintptr_t) -size, 0) ||
        __builtin_expect(misaligned_chunk(p), 0)) {
        errstr = "free(): invalid pointer";
    errout:
        if (!have_lock && locked) __libc_lock_unlock(av->mutex);
        malloc_printerr(check_action, errstr, chunk2mem(p), av);
        return;
    }
    /* We know that each chunk is at least MINSIZE bytes in size or a
       multiple of MALLOC_ALIGNMENT.  */
    // 大小没有最小的chunk大，或者说，大小不是MALLOC_ALIGNMENT的整数倍
    if (__glibc_unlikely(size < MINSIZE || !aligned_OK(size))) {
        errstr = "free(): invalid size";
        goto errout;
    }
    // 检查该chunk是否处于使用状态，非调试状态下没有作用
    check_inuse_chunk(av, p);
```

其中

```c
/* Check if m has acceptable alignment */

#define aligned_OK(m) (((unsigned long) (m) &MALLOC_ALIGN_MASK) == 0)

#define misaligned_chunk(p)                                                    \
    ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem(p)) &       \
     MALLOC_ALIGN_MASK)
```



#### fast bin

如果上述检查都合格的话，判断当前的 bin 是不是在 fast bin 范围内，在的话就插入到 **fastbin 头部**，即成为对应 fastbin 链表的**第一个 free chunk**。

```c++
    /*
      If eligible, place chunk on a fastbin so it can be found
      and used quickly in malloc.
    */

    if ((unsigned long) (size) <= (unsigned long) (get_max_fast())

#if TRIM_FASTBINS
        /*
      If TRIM_FASTBINS set, don't place chunks
      bordering top into fastbins
        */
       //默认 #define TRIM_FASTBINS 0，因此默认情况下下面的语句不会执行
       // 如果当前chunk是fast chunk，并且下一个chunk是top chunk，则不能插入
        && (chunk_at_offset(p, size) != av->top)
#endif
            ) {
        // 下一个chunk的大小不能小于两倍的SIZE_SZ,并且
        // 下一个chunk的大小不能大于system_mem， 一般为132k
        // 如果出现这样的情况，就报错。
        if (__builtin_expect(
                chunksize_nomask(chunk_at_offset(p, size)) <= 2 * SIZE_SZ, 0) ||
            __builtin_expect(
                chunksize(chunk_at_offset(p, size)) >= av->system_mem, 0)) {
            /* We might not have a lock at this point and concurrent
               modifications
               of system_mem might have let to a false positive.  Redo the test
               after getting the lock.  */
            if (have_lock || ({
                    assert(locked == 0);
                    __libc_lock_lock(av->mutex);
                    locked = 1;
                    chunksize_nomask(chunk_at_offset(p, size)) <= 2 * SIZE_SZ ||
                        chunksize(chunk_at_offset(p, size)) >= av->system_mem;
                })) {
                errstr = "free(): invalid next size (fast)";
                goto errout;
            }
            if (!have_lock) {
                __libc_lock_unlock(av->mutex);
                locked = 0;
            }
        }
        // 将chunk的mem部分全部设置为perturb_byte 
        free_perturb(chunk2mem(p), size - 2 * SIZE_SZ);
        // 设置fast chunk的标记位
        set_fastchunks(av);
        // 根据大小获取fast bin的索引
        unsigned int idx = fastbin_index(size);
        // 获取对应fastbin的头指针，被初始化后为NULL。
        fb               = &fastbin(av, idx);

        /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
        // 使用原子操作将P插入到链表中
        mchunkptr    old     = *fb, old2;
        unsigned int old_idx = ~0u;
        do {
            /* Check that the top of the bin is not the record we are going to
               add
               (i.e., double free).  */
            // so we can not double free one fastbin chunk
            // 防止对 fast bin double free
            if (__builtin_expect(old == p, 0)) {
                errstr = "double free or corruption (fasttop)";
                goto errout;
            }
            /* Check that size of fastbin chunk at the top is the same as
               size of the chunk that we are adding.  We can dereference OLD
               only if we have the lock, otherwise it might have already been
               deallocated.  See use of OLD_IDX below for the actual check.  */
            if (have_lock && old != NULL)
                old_idx = fastbin_index(chunksize(old));
            p->fd = old2 = old;
        } while ((old = catomic_compare_and_exchange_val_rel(fb, p, old2)) !=
                 old2);
        // 确保fast bin的加入前与加入后相同
        if (have_lock && old != NULL && __builtin_expect(old_idx != idx, 0)) {
            errstr = "invalid fastbin entry (free)";
            goto errout;
        }
    }
```

#### 合并非 mmap 的空闲 chunk

**只有不是 fast bin 的情况下才会触发unlink**

首先我们先说一下为什么会合并chunk，这是为了避免heap中有太多零零碎碎的内存块，合并之后可以用来应对更大的内存块请求。合并的主要顺序为

- 先考虑物理低地址空闲块
- 后考虑物理高地址空闲块

**合并后的 chunk 指向合并的 chunk 的低地址。**

在没有锁的情况下，先获得锁。

```c++
    /*
      Consolidate other non-mmapped chunks as they arrive.
    */

    else if (!chunk_is_mmapped(p)) {
        if (!have_lock) {
            __libc_lock_lock(av->mutex);
            locked = 1;
        }
        nextchunk = chunk_at_offset(p, size);
```

##### 轻量级的检测

```c++
        /* Lightweight tests: check whether the block is already the
           top block.  */
        // 当前free的chunk不能是top chunk
        if (__glibc_unlikely(p == av->top)) {
            errstr = "double free or corruption (top)";
            goto errout;
        }
        // 当前free的chunk的下一个chunk不能超过arena的边界
        /* Or whether the next chunk is beyond the boundaries of the arena.  */
        if (__builtin_expect(contiguous(av) &&
                                 (char *) nextchunk >=
                                     ((char *) av->top + chunksize(av->top)),
                             0)) {
            errstr = "double free or corruption (out)";
            goto errout;
        }
        // 当前要free的chunk的使用标记没有被标记，double free
        /* Or whether the block is actually not marked used.  */
        if (__glibc_unlikely(!prev_inuse(nextchunk))) {
            errstr = "double free or corruption (!prev)";
            goto errout;
        }
        // 下一个chunk的大小
        nextsize = chunksize(nextchunk);
        // next chunk size valid check
        // 判断下一个chunk的大小是否不大于2*SIZE_SZ，或者
        // nextsize是否大于系统可提供的内存
        if (__builtin_expect(chunksize_nomask(nextchunk) <= 2 * SIZE_SZ, 0) ||
            __builtin_expect(nextsize >= av->system_mem, 0)) {
            errstr = "free(): invalid next size (normal)";
            goto errout;
        }
```

##### 释放填充

```c++
        //将指针的mem部分全部设置为perturb_byte 
		free_perturb(chunk2mem(p), size - 2 * SIZE_SZ);
```

##### 后向合并-合并低地址 chunk

```c++
        /* consolidate backward */
        if (!prev_inuse(p)) {
            prevsize = prev_size(p);
            size += prevsize;
            p = chunk_at_offset(p, -((long) prevsize));
            unlink(av, p, bck, fwd);
        }
```

##### 下一块不是top chunk-前向合并-合并高地址chunk

需要注意的是，如果下一块不是 top chunk 后，则合并高地址的 chunk ，并将合并后的 chunk 放入到unsorted bin中。

```c++
		// 如果下一个chunk不是top chunk
		if (nextchunk != av->top) {
            /* get and clear inuse bit */
            // 获取下一个 chunk 的使用状态
            nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
            // 如果不在使用，合并，否则清空当前chunk的使用状态。
            /* consolidate forward */
            if (!nextinuse) {
                unlink(av, nextchunk, bck, fwd);
                size += nextsize;
            } else
                clear_inuse_bit_at_offset(nextchunk, 0);

            /*
          Place the chunk in unsorted chunk list. Chunks are
          not placed into regular bins until after they have
          been given one chance to be used in malloc.
            */
            // 把 chunk 放在 unsorted chunk 链表的头部
            bck = unsorted_chunks(av);
            fwd = bck->fd;
            // 简单的检查
            if (__glibc_unlikely(fwd->bk != bck)) {
                errstr = "free(): corrupted unsorted chunks";
                goto errout;
            }
            p->fd = fwd;
            p->bk = bck;
            // 如果是 large chunk，那就设置nextsize指针字段为NULL。
            if (!in_smallbin_range(size)) {
                p->fd_nextsize = NULL;
                p->bk_nextsize = NULL;
            }
            bck->fd = p;
            fwd->bk = p;

            set_head(p, size | PREV_INUSE);
            set_foot(p, size);

            check_free_chunk(av, p);
        }
```

##### 下一块是top chunk-合并到top chunk

```c++
        /*
          If the chunk borders the current high end of memory,
          consolidate into top
        */
        // 如果要释放的chunk的下一个chunk是top chunk，那就合并到 top chunk
        else {
            size += nextsize;
            set_head(p, size | PREV_INUSE);
            av->top = p;
            check_chunk(av, p);
        }
```

##### 向系统返还内存

```c++
        /*
          If freeing a large space, consolidate possibly-surrounding
          chunks. Then, if the total unused topmost memory exceeds trim
          threshold, ask malloc_trim to reduce top.

          Unless max_fast is 0, we don't know if there are fastbins
          bordering top, so we cannot tell for sure whether threshold
          has been reached unless fastbins are consolidated.  But we
          don't want to consolidate on each free.  As a compromise,
          consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
          is reached.
        */
         // 如果合并后的 chunk 的大小大于FASTBIN_CONSOLIDATION_THRESHOLD
         // 一般合并到 top chunk 都会执行这部分代码。
         // 那就向系统返还内存
        if ((unsigned long) (size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
            // 如果有 fast chunk 就进行合并
            if (have_fastchunks(av)) malloc_consolidate(av);
            // 主分配区
            if (av == &main_arena) {
#ifndef MORECORE_CANNOT_TRIM
                // top chunk 大于当前的收缩阙值
                if ((unsigned long) (chunksize(av->top)) >=
                    (unsigned long) (mp_.trim_threshold))
                    systrim(mp_.top_pad, av);
#endif      // 非主分配区，则直接收缩heap
            } else {
                /* Always try heap_trim(), even if the top chunk is not
                   large, because the corresponding heap might go away.  */
                heap_info *heap = heap_for_ptr(top(av));

                assert(heap->ar_ptr == av);
                heap_trim(heap, mp_.top_pad);
            }
        }

        if (!have_lock) {
            assert(locked);
            __libc_lock_unlock(av->mutex);
        }
```

#### 释放mmap的chunk

```c++
    } else {
        //  If the chunk was allocated via mmap, release via munmap().
        munmap_chunk(p);
    }
```

### systrim

### heap_trim

### munmap_chunk

## 删除堆

## malloc_state 相关函数

### malloc_init_state

```c
/*
   Initialize a malloc_state struct.
   This is called only from within malloc_consolidate, which needs
   be called in the same contexts anyway.  It is never called directly
   outside of malloc_consolidate because some optimizing compilers try
   to inline it at all call points, which turns out not to be an
   optimization at all. (Inlining it in malloc_consolidate is fine though.)
 */

static void malloc_init_state(mstate av) {
    int     i;
    mbinptr bin;

    /* Establish circular links for normal bins */
    for (i = 1; i < NBINS; ++i) {
        bin     = bin_at(av, i);
        bin->fd = bin->bk = bin;
    }

#if MORECORE_CONTIGUOUS
    if (av != &main_arena)
#endif
        set_noncontiguous(av);
    if (av == &main_arena) set_max_fast(DEFAULT_MXFAST);
    // 设置 flags 标记目前没有fast chunk
    av->flags |= FASTCHUNKS_BIT;
    // 就是 unsorted bin
    av->top = initial_top(av);
}
```



### malloc_consolidate

该函数主要有两个功能

1. 若 fastbin 未初始化，即 global_max_fast 为0，那就初始化 malloc_state。
2. 如果已经初始化的话，就合并 fastbin 中的 chunk。

基本的流程如下

#### 初始

```c
static void malloc_consolidate(mstate av) {
    mfastbinptr *fb;             /* current fastbin being consolidated */
    mfastbinptr *maxfb;          /* last fastbin (for loop control) */
    mchunkptr    p;              /* current chunk being consolidated */
    mchunkptr    nextp;          /* next chunk to consolidate */
    mchunkptr    unsorted_bin;   /* bin header */
    mchunkptr    first_unsorted; /* chunk to link to */

    /* These have same use as in free() */
    mchunkptr       nextchunk;
    INTERNAL_SIZE_T size;
    INTERNAL_SIZE_T nextsize;
    INTERNAL_SIZE_T prevsize;
    int             nextinuse;
    mchunkptr       bck;
    mchunkptr       fwd;
```

#### 合并 chunk

```c
    /*
      If max_fast is 0, we know that av hasn't
      yet been initialized, in which case do so below
    */
	// 说明 fastbin 已经初始化
    if (get_max_fast() != 0) {
        // 清空 fastbin 标记
        // 因为要合并 fastbin 中的 chunk 了。
        clear_fastchunks(av);
        // 
        unsorted_bin = unsorted_chunks(av);

        /*
          Remove each chunk from fast bin and consolidate it, placing it
          then in unsorted bin. Among other reasons for doing this,
          placing in unsorted bin avoids needing to calculate actual bins
          until malloc is sure that chunks aren't immediately going to be
          reused anyway.
        */
        // 按照 fd 顺序遍历 fastbin 的每一个 bin，将 bin 中的每一个 chunk 合并掉。
        maxfb = &fastbin(av, NFASTBINS - 1);
        fb    = &fastbin(av, 0);
        do {
            p = atomic_exchange_acq(fb, NULL);
            if (p != 0) {
                do {
                    check_inuse_chunk(av, p);
                    nextp = p->fd;

                    /* Slightly streamlined version of consolidation code in
                     * free() */
                    size      = chunksize(p);
                    nextchunk = chunk_at_offset(p, size);
                    nextsize  = chunksize(nextchunk);

                    if (!prev_inuse(p)) {
                        prevsize = prev_size(p);
                        size += prevsize;
                        p = chunk_at_offset(p, -((long) prevsize));
                        unlink(av, p, bck, fwd);
                    }

                    if (nextchunk != av->top) {
                        // 判断 nextchunk 是否是空闲的。
                        nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

                        if (!nextinuse) {
                            size += nextsize;
                            unlink(av, nextchunk, bck, fwd);
                        } else
                         // 设置 nextchunk 的 prev inuse 为0，以表明可以合并当前 fast chunk。
                            clear_inuse_bit_at_offset(nextchunk, 0);

                        first_unsorted     = unsorted_bin->fd;
                        unsorted_bin->fd   = p;
                        first_unsorted->bk = p;

                        if (!in_smallbin_range(size)) {
                            p->fd_nextsize = NULL;
                            p->bk_nextsize = NULL;
                        }

                        set_head(p, size | PREV_INUSE);
                        p->bk = unsorted_bin;
                        p->fd = first_unsorted;
                        set_foot(p, size);
                    }

                    else {
                        size += nextsize;
                        set_head(p, size | PREV_INUSE);
                        av->top = p;
                    }

                } while ((p = nextp) != 0);
            }
        } while (fb++ != maxfb);
```

#### 初始化

说明 fastbin 还没有初始化。

```c
    } else {
        malloc_init_state(av);
        // 在非调试情况下没有什么用，在调试情况下，做一些检测。
        check_malloc_state(av);
    }
```



## 测试支持

下面的代码用于支持测试，默认情况下 perturb_byte 是0。

```c
static int perturb_byte;

static void alloc_perturb(char *p, size_t n) {
    if (__glibc_unlikely(perturb_byte)) memset(p, perturb_byte ^ 0xff, n);
}

static void free_perturb(char *p, size_t n) {
    if (__glibc_unlikely(perturb_byte)) memset(p, perturb_byte, n);
}
```

