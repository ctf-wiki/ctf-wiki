# 堆实现

简单想一下，对于任何堆的实现来说都离不开以下的问题

- 宏观角度
  - 创建堆并对堆进行初始化
  - 删除堆
- 微观角度
  - 申请内存块
  - 释放内存块

当然，这些都是一些比较高层面的想法，对于一些底层的实现来说，会有所不同。

# 堆初始化

# 创建堆

# 申请内存块

我们之前也说了，我们会使用malloc函数来申请内存块，可是当我们仔细看看glibc的源码实现时，其实并没有malloc函数。其实该函数真正调用的是__libc_malloc函数。为什么不直接写个malloc函数呢，因为有时候我们可能需要不同的名称，而且该函数只是用来简单封装\_int_malloc函数。\_int_malloc 才是申请内存块的核心。下面我们来仔细分析一下实现。

## __libc_malloc

1. 该函数会首先检查是否有内存分配函数的钩子函数。该函数主要用于进程在创建新线程过程中分配内存或者用户自定义的分配函数。

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

2. 接着会寻找一个arena来试图分配内存。

```c++
    arena_get(ar_ptr, bytes);
```

3. 然后调用_int_malloc函数去申请对应的内存。

```C++
    victim = _int_malloc(ar_ptr, bytes);
```

4. 如果分配失败的话，ptmalloc会尝试再去寻找一个可用的arena，并分配内存。

```c++
    /* Retry with another arena only if we were able to find a usable arena
       before.  */
    if (!victim && ar_ptr != NULL) {
        LIBC_PROBE(memory_malloc_retry, 1, bytes);
        ar_ptr = arena_get_retry(ar_ptr, bytes);
        victim = _int_malloc(ar_ptr, bytes);
    }
```

5. 如果申请到了arena，那么在离开之前还得解锁。

```c++
    if (ar_ptr != NULL) __libc_lock_unlock(ar_ptr->mutex);
```

6.  判断目前的状态是否满足以下条件，要么没有申请到内存，要么是mmap的内存，**要么申请到的内存必须在其所分配的arena中**。

```c++
    assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
           ar_ptr == arena_for_chunk(mem2chunk(victim)));
```

7. 最后返回内存。

```c++
    return victim;
}
```

## _int_malloc

### 概述

_int_malloc时内存分配的核心函数，其核心思路有以下几点

1. 它根据用户申请的内存块的大小，依次实现了不同的分配方法。
2. 它会首先检查申请的内存块是不是有相应的空闲块可以满足需求，没有的话，才会进行内存块申请。
3. 它会按照chunk 的大小由小到大依次判断。

### 初始

在进入该函数后，函数立马定义了一系列自己需要的变量，并在开始时，将用户申请的内存大小转换为其chunk大小。

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

### 判断是否有arena可用

```c++
    /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
       mmap.  */
    if (__glibc_unlikely(av == NULL)) {
        void *p = sysmalloc(nb, av);
        if (p != NULL) alloc_perturb(p, bytes);
        return p;
    }
```

### fast bin

如果申请的chunk的大小位于fastbin 范围内

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
        // 检查对应的bin内是否有空闲的chunk块，
        do {
            victim = pp;
            if (victim == NULL) break;
        } while ((pp = catomic_compare_and_exchange_val_acq(fb, victim->fd,
                                                            victim)) != victim);
        // 存在可以利用的chunk
        if (victim != 0) {
            // 检查取到的chunk是否确实在对应的fastbin中。
            if (__builtin_expect(fastbin_index(chunksize(victim)) != idx, 0)) {
                errstr = "malloc(): memory corruption (fast)";
            errout:
                malloc_printerr(check_action, errstr, chunk2mem(victim), av);
                return NULL;
            }
            // 细致的检查。。
            check_remalloced_chunk(av, victim, nb);
            // 将获取的到chunk转换为mem模式
            void *p = chunk2mem(victim);
            // 如果设置了perturb_type, 则将获取到的chunk初始化为 perturb_type ^ 0xff
            alloc_perturb(p, bytes);
            return p;
        }
    }
```

### small bin

如果获取的内存块的范围处于small bin的范围，那么执行如下流程

```c++
    /*
       If a small request, check regular bin.  Since these "smallbins"
       hold one size each, no searching within bins is necessary.
       (For a large request, we need to wait until unsorted chunks are
       processed to find best fit. But for small ones, fits are exact
       anyway, so we can check now, which is faster.)
     */

    if (in_smallbin_range(nb)) {
        // 获取small bin的索引
        idx = smallbin_index(nb);
        // 获取对应small bin中的chunk指针
        bin = bin_at(av, idx);
        // 先执行victim= last(bin)
        // 如果victim = bin，那说明该bin为空。
        // 如果不相等，那么会有两种情况
        if ((victim = last(bin)) != bin) {
            // 第一种情况，该bin还没有初始化。
            if (victim == 0) /* initialization check */
                // 执行初始化，将fast bins中的chunk进行合并
                malloc_consolidate(av);
            // 第二种情况，该bin中存在空闲的chunk
            else {
                // 获取该bin中最后一个chunk。
                bck = victim->bk;
                // 检查bck中记录的前一个chunk是不是victim，防止伪造
                if (__glibc_unlikely(bck->fd != victim)) {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                // 设置与victim对应的inuse位
                set_inuse_bit_at_offset(victim, nb);
                // 修改bin的链表情况
                bin->bk = bck;
                bck->fd = bin;
                // 如果不是主arena，设置对应的标志
                if (av != &main_arena) set_non_main_arena(victim);
                // 细致的检查
                check_malloced_chunk(av, victim, nb);
                // 将申请到的chunk转化为对应的mem状态
                void *p = chunk2mem(victim);
                // 如果设置了perturb_type, 则将获取到的chunk初始化为 perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
        }
    }
```

### large bin

large bin的处理过程如下

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
        // 如果存在fastbin的话，会先对fastbin进行合并，将其加入到unsorted bin中
        if (have_fastchunks(av)) malloc_consolidate(av);
    }

```

### 循环

#### 概述

**上面说明没有bin可以直接满足需求**。在接下来的这个循环中，主要做了以下的操作

- 尝试从unsorted bin中分配用户所需的内存
- 尝试从large bin中分配用户所需的内存
- 尝试从top  chunk中分配用户所需内存

#### 大循环

该部分是一个大循环，这是为了尝试重新分配small bin chunk，这是因为我们虽然会首先使用large bin，top chunk来尝试满足用户的请求，但是如果没有满足的话，由于我们在上面没有分配成功small bin的话，我们并没有对fast bin中的chunk进行合并，所以这里会进行fast bin chunk的合并，进而使用一个大循环来尝试再次分配small bin chunk。

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

#### unsort bin & last remainder

先考虑unsorted bin，在考虑last remainder，但是对于small bin chunk的请求会有所例外。

```c++
        // 如果unsorted bin不为空
        // First In First Out
        while ((victim = unsorted_chunks(av)->bk) != unsorted_chunks(av)) {
            // 得到 unsorted bin的最后一个chunk
            bck = victim->bk;
            // 判断得到的chunk是否满足要求，不能过小，也不能过大
            if (__builtin_expect(chunksize_nomask(victim) <= 2 * SIZE_SZ, 0) ||
                __builtin_expect(chunksize_nomask(victim) > av->system_mem, 0))
                malloc_printerr(check_action, "malloc(): memory corruption",
                                chunk2mem(victim), av);
            // 得到victim对应的chunk大小。
            size = chunksize(victim);

            /*
               If a small request, try to use last remainder if it is the
               only chunk in unsorted bin.  This helps promote locality for
               runs of consecutive small requests. This is the only
               exception to best-fit, and applies only when there is
               no exact fit for a small chunk.
             */
            // 如果用户的请求为 small bin chunk，那么我们首先考虑last remainder
            // 如果last remainder是unsorted bin中的唯一一块的话
            // 并且last remainder的大小分割够还可以作为一个chunk，为什么没有等号？
            if (in_smallbin_range(nb) && bck == unsorted_chunks(av) &&
                victim == av->last_remainder &&
                (unsigned long) (size) > (unsigned long) (nb + MINSIZE)) {
                /* split and reattach remainder */
                // 获取新的remainder的大小
                remainder_size          = size - nb;
                // 获取新的remainder的位置
                remainder               = chunk_at_offset(victim, nb);
                // 更新unsorted bin的情况
                unsorted_chunks(av)->bk = unsorted_chunks(av)->fd = remainder;
                // 更新av中记录的last_remainder
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
                // 设置remainder的头部
                set_head(remainder, remainder_size | PREV_INUSE);
                // 设置记录 remainder大小的prev_size字段，因为此时remainder处于空闲状态。
                set_foot(remainder, remainder_size);
                // 细致的检查
                check_malloced_chunk(av, victim, nb);
                // 将victim从chunk模式转化为mem模式
                void *p = chunk2mem(victim);
                // 如果设置了perturb_type, 则将获取到的chunk初始化为 perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
            //
            /* remove from unsorted list */
            unsorted_chunks(av)->bk = bck;
            bck->fd                 = unsorted_chunks(av);

            /* Take now instead of binning if exact fit */

            if (size == nb) {
                set_inuse_bit_at_offset(victim, size);
                if (av != &main_arena) set_non_main_arena(victim);
                check_malloced_chunk(av, victim, nb);
                void *p = chunk2mem(victim);
                alloc_perturb(p, bytes);
                return p;
            }

            /* place chunk in bin */

            if (in_smallbin_range(size)) {
                victim_index = smallbin_index(size);
                bck          = bin_at(av, victim_index);
                fwd          = bck->fd;
            } else {
                victim_index = largebin_index(size);
                bck          = bin_at(av, victim_index);
                fwd          = bck->fd;

                /* maintain large bins in sorted order */
                if (fwd != bck) {
                    /* Or with inuse bit to speed comparisons */
                    size |= PREV_INUSE;
                    /* if smaller than smallest, bypass loop below */
                    assert(chunk_main_arena(bck->bk));
                    if ((unsigned long) (size) <
                        (unsigned long) chunksize_nomask(bck->bk)) {
                        fwd = bck;
                        bck = bck->bk;

                        victim->fd_nextsize = fwd->fd;
                        victim->bk_nextsize = fwd->fd->bk_nextsize;
                        fwd->fd->bk_nextsize =
                            victim->bk_nextsize->fd_nextsize = victim;
                    } else {
                        assert(chunk_main_arena(fwd));
                        while ((unsigned long) size < chunksize_nomask(fwd)) {
                            fwd = fwd->fd_nextsize;
                            assert(chunk_main_arena(fwd));
                        }

                        if ((unsigned long) size ==
                            (unsigned long) chunksize_nomask(fwd))
                            /* Always insert in the second position.  */
                            fwd = fwd->fd;
                        else {
                            victim->fd_nextsize              = fwd;
                            victim->bk_nextsize              = fwd->bk_nextsize;
                            fwd->bk_nextsize                 = victim;
                            victim->bk_nextsize->fd_nextsize = victim;
                        }
                        bck = fwd->bk;
                    }
                } else
                    victim->fd_nextsize = victim->bk_nextsize = victim;
            }

            mark_bin(av, victim_index);
            victim->bk = bck;
            victim->fd = fwd;
            fwd->bk    = victim;
            bck->fd    = victim;

#define MAX_ITERS 10000
            if (++iters >= MAX_ITERS) break;
        }
```



# 释放内存块

# 删除堆

