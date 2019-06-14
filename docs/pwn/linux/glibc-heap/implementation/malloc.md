# 申请内存块

## __libc_malloc

一般我们会使用 malloc 函数来申请内存块，可是当仔细看 glibc 的源码实现时，其实并没有 malloc 函数。其实该函数真正调用的是 \_\_libc_malloc 函数。为什么不直接写个 malloc 函数呢，因为有时候我们可能需要不同的名称。此外，__libc_malloc 函数只是用来简单封装 _int_malloc 函数。\_int_malloc 才是申请内存块的核心。下面我们来仔细分析一下具体的实现。

该函数会首先检查是否有内存分配函数的钩子函数（__malloc_hook），这个主要用于用户自定义的堆分配函数，方便用户快速修改对分配函数并进行测试。这里需要注意的是，**用户申请的字节一旦进入申请内存函数中就变成了无符号整数**。

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

判断目前的状态是否满足以下条件

- 要么没有申请到内存
- 要么是 mmap 的内存
- **要么申请到的内存必须在其所分配的arena中**

```c++
    assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
           ar_ptr == arena_for_chunk(mem2chunk(victim)));
```

最后返回内存。

```c++
    return victim;
}
```

## _int_malloc

_int_malloc 是内存分配的核心函数，其核心思路有如下

1. 它根据用户申请的**内存块大小**以及**相应大小 chunk 通常使用的频度**（fastbin chunk, small chunk, large chunk），依次实现了不同的分配方法。
2. 它由小到大依次检查不同的 bin 中是否有相应的空闲块可以满足用户请求的内存。
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

### arena

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

### small bin

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

### large bin

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

### 大循环-遍历 unsortedbin

**如果程序执行到了这里，那么说明 与 chunk 大小正好一致的 bin (fast bin， small bin) 中没有 chunk可以直接满足需求 ，但是 large chunk  则是在这个大循环中处理**。

在接下来的这个循环中，主要做了以下的操作

- 按照 FIFO 的方式逐个将 unsorted bin 中的 chunk 取出来
    - 如果是 small request，则考虑是不是恰好满足，是的话，直接返回。
    - 如果不是的话，放到对应的 bin 中。
- 尝试从 large bin 中分配用户所需的内存

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

#### unsort bin 遍历

先考虑 unsorted bin，再考虑 last remainder ，但是对于 small bin chunk 的请求会有所例外。

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

##### small request

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

##### 初始取出

```c
            /* remove from unsorted list */
            unsorted_chunks(av)->bk = bck;
            bck->fd                 = unsorted_chunks(av);
```

##### exact fit

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

##### place chunk in small bin

把取出来的 chunk 放到对应的 small bin 中。

```c
            /* place chunk in bin */

            if (in_smallbin_range(size)) {
                victim_index = smallbin_index(size);
                bck          = bin_at(av, victim_index);
                fwd          = bck->fd;
```

##### place chunk in large bin

把取出来的 chunk 放到对应的 large bin 中。

```c
            } else {
                // large bin 范围
                victim_index = largebin_index(size);
                bck          = bin_at(av, victim_index); // 当前 large bin 的头部
                fwd          = bck->fd;

                /* maintain large bins in sorted order */
                /* 从这里我们可以总结出，largebin 以 fd_nextsize 递减排序。
                   同样大小的 chunk，后来的只会插入到之前同样大小的 chunk 后，
                   而不会修改之前相同大小的fd/bk_nextsize，这也很容易理解，
                   可以减低开销。此外，bin 头不参与 nextsize 链接。*/
                // 如果 large bin 链表不空
                if (fwd != bck) {
                    /* Or with inuse bit to speed comparisons */
                    // 加速比较，应该不仅仅有这个考虑，因为链表里的 chunk 都会设置该位。
                    size |= PREV_INUSE;
                    /* if smaller than smallest, bypass loop below */
                    // bck-bk 存储着相应 large bin 中最小的chunk。
                    // 如果遍历的 chunk 比当前最小的还要小，那就只需要插入到链表尾部。
                    // 判断 bck->bk 是不是在 main arena。
                    assert(chunk_main_arena(bck->bk));
                    if ((unsigned long) (size) <
                        (unsigned long) chunksize_nomask(bck->bk)) {
                        // 令 fwd 指向 large bin 头
                        fwd = bck;
                        // 令 bck 指向 largin bin 尾部 chunk
                        bck = bck->bk;
                        // victim 的 fd_nextsize 指向 largin bin 的第一个 chunk
                        victim->fd_nextsize = fwd->fd;
                        // victim 的 bk_nextsize 指向原来链表的第一个 chunk 指向的 bk_nextsize
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
                            // 那么就需要构造 nextsize 双向链表了
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

##### 最终取出

```c
            // 放到对应的 bin 中，构成 bck<-->victim<-->fwd。
            mark_bin(av, victim_index);
            victim->bk = bck;
            victim->fd = fwd;
            fwd->bk    = victim;
            bck->fd    = victim;
```

##### while 迭代次数

while 最多迭代10000次后退出。

```c
            //
##define MAX_ITERS 10000
            if (++iters >= MAX_ITERS) break;
        }
```

#### large chunk

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

#### 寻找较大 chunk

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

##### 找到一个合适的 map

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

##### 找到合适的 bin

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

##### 简单检查 chunk

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

##### 真正取出 chunk

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

### 使用 top chunk

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

```

### 堆内存不够

如果堆内存不够，我们就需要使用 `sysmalloc` 来申请内存了。

```c
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



## _libc_calloc

calloc 也是 libc 中的一种申请内存块的函数。在 `libc`中的封装为 `_libc_calloc`，具体介绍如下

```c
/*
  calloc(size_t n_elements, size_t element_size);
  Returns a pointer to n_elements * element_size bytes, with all locations
  set to zero.
*/
void*  __libc_calloc(size_t, size_t);
```

## sysmalloc

正如该函数头的注释所言，该函数用于当前堆内存不足时，需要向系统申请更多的内存。

```c
/*
   sysmalloc handles malloc cases requiring more memory from the system.
   On entry, it is assumed that av->top does not have enough
   space to service request for nb bytes, thus requiring that av->top
   be extended or replaced.
 */
```

### 基本定义

```c
static void *sysmalloc(INTERNAL_SIZE_T nb, mstate av) {
  mchunkptr old_top;        /* incoming value of av->top */
  INTERNAL_SIZE_T old_size; /* its size */
  char *old_end;            /* its end address */

  long size; /* arg to first MORECORE or mmap call */
  char *brk; /* return value from MORECORE */

  long correction; /* arg to 2nd MORECORE call */
  char *snd_brk;   /* 2nd return val */

  INTERNAL_SIZE_T front_misalign; /* unusable bytes at front of new space */
  INTERNAL_SIZE_T end_misalign;   /* partial page left at end of new space */
  char *aligned_brk;              /* aligned offset into brk */

  mchunkptr p;                  /* the allocated/returned chunk */
  mchunkptr remainder;          /* remainder frOm allocation */
  unsigned long remainder_size; /* its size */

  size_t pagesize = GLRO(dl_pagesize);
  bool tried_mmap = false;
```

我们可以主要关注一下 `pagesize`，其

```c
#ifndef EXEC_PAGESIZE
#define EXEC_PAGESIZE	4096
#endif
# define GLRO(name) _##name
size_t _dl_pagesize = EXEC_PAGESIZE;
```

所以，`pagesize=4096=0x1000`。

### 考虑 mmap

正如开头注释所言如果满足如下任何一种条件

1. 没有分配堆。
2. 申请的内存大于 `mp_.mmap_threshold`，并且mmap 的数量小于最大值，就可以尝试使用 mmap。

默认情况下，临界值为

```c
static struct malloc_par mp_ = {
    .top_pad = DEFAULT_TOP_PAD,
    .n_mmaps_max = DEFAULT_MMAP_MAX,
    .mmap_threshold = DEFAULT_MMAP_THRESHOLD,
    .trim_threshold = DEFAULT_TRIM_THRESHOLD,
#define NARENAS_FROM_NCORES(n) ((n) * (sizeof(long) == 4 ? 2 : 8))
    .arena_test = NARENAS_FROM_NCORES(1)
#if USE_TCACHE
        ,
    .tcache_count = TCACHE_FILL_COUNT,
    .tcache_bins = TCACHE_MAX_BINS,
    .tcache_max_bytes = tidx2usize(TCACHE_MAX_BINS - 1),
    .tcache_unsorted_limit = 0 /* No limit.  */
#endif
};
```

`DEFAULT_MMAP_THRESHOLD` 为 128*1024 字节，即 128 K。

```c
#ifndef DEFAULT_MMAP_THRESHOLD
#define DEFAULT_MMAP_THRESHOLD DEFAULT_MMAP_THRESHOLD_MIN
#endif
/*
  MMAP_THRESHOLD_MAX and _MIN are the bounds on the dynamically
  adjusted MMAP_THRESHOLD.
*/

#ifndef DEFAULT_MMAP_THRESHOLD_MIN
#define DEFAULT_MMAP_THRESHOLD_MIN (128 * 1024)
#endif

#ifndef DEFAULT_MMAP_THRESHOLD_MAX
/* For 32-bit platforms we cannot increase the maximum mmap
   threshold much because it is also the minimum value for the
   maximum heap size and its alignment.  Going above 512k (i.e., 1M
   for new heaps) wastes too much address space.  */
#if __WORDSIZE == 32
#define DEFAULT_MMAP_THRESHOLD_MAX (512 * 1024)
#else
#define DEFAULT_MMAP_THRESHOLD_MAX (4 * 1024 * 1024 * sizeof(long))
#endif
#endif
```

下面为这部分代码，目前不是我们关心的重点，可以暂时跳过。

```c
  /*
     If have mmap, and the request size meets the mmap threshold, and
     the system supports mmap, and there are few enough currently
     allocated mmapped regions, try to directly map this request
     rather than expanding top.
   */

  if (av == NULL ||
      ((unsigned long)(nb) >= (unsigned long)(mp_.mmap_threshold) &&
       (mp_.n_mmaps < mp_.n_mmaps_max))) {
    char *mm; /* return value from mmap call*/

  try_mmap:
    /*
       Round up size to nearest page.  For mmapped chunks, the overhead
       is one SIZE_SZ unit larger than for normal chunks, because there
       is no following chunk whose prev_size field could be used.

       See the front_misalign handling below, for glibc there is no
       need for further alignments unless we have have high alignment.
     */
    if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
      size = ALIGN_UP(nb + SIZE_SZ, pagesize);
    else
      size = ALIGN_UP(nb + SIZE_SZ + MALLOC_ALIGN_MASK, pagesize);
    tried_mmap = true;

    /* Don't try if size wraps around 0 */
    if ((unsigned long)(size) > (unsigned long)(nb)) {
      mm = (char *)(MMAP(0, size, PROT_READ | PROT_WRITE, 0));

      if (mm != MAP_FAILED) {
        /*
           The offset to the start of the mmapped region is stored
           in the prev_size field of the chunk. This allows us to adjust
           returned start address to meet alignment requirements here
           and in memalign(), and still be able to compute proper
           address argument for later munmap in free() and realloc().
         */

        if (MALLOC_ALIGNMENT == 2 * SIZE_SZ) {
          /* For glibc, chunk2mem increases the address by 2*SIZE_SZ and
             MALLOC_ALIGN_MASK is 2*SIZE_SZ-1.  Each mmap'ed area is page
             aligned and therefore definitely MALLOC_ALIGN_MASK-aligned.  */
          assert(((INTERNAL_SIZE_T)chunk2mem(mm) & MALLOC_ALIGN_MASK) == 0);
          front_misalign = 0;
        } else
          front_misalign = (INTERNAL_SIZE_T)chunk2mem(mm) & MALLOC_ALIGN_MASK;
        if (front_misalign > 0) {
          correction = MALLOC_ALIGNMENT - front_misalign;
          p = (mchunkptr)(mm + correction);
          set_prev_size(p, correction);
          set_head(p, (size - correction) | IS_MMAPPED);
        } else {
          p = (mchunkptr)mm;
          set_prev_size(p, 0);
          set_head(p, size | IS_MMAPPED);
        }

        /* update statistics */

        int new = atomic_exchange_and_add(&mp_.n_mmaps, 1) + 1;
        atomic_max(&mp_.max_n_mmaps, new);

        unsigned long sum;
        sum = atomic_exchange_and_add(&mp_.mmapped_mem, size) + size;
        atomic_max(&mp_.max_mmapped_mem, sum);

        check_chunk(av, p);

        return chunk2mem(p);
      }
    }
  }
```

### mmap 失败或者未分配堆

```c
  /* There are no usable arenas and mmap also failed.  */
  if (av == NULL)
    return 0;
```

如果是这两种情况中的任何一种，其实就可以退出了。。

### 记录旧堆信息

```c
  /* Record incoming configuration of top */

  old_top = av->top;
  old_size = chunksize(old_top);
  old_end = (char *)(chunk_at_offset(old_top, old_size));

  brk = snd_brk = (char *)(MORECORE_FAILURE);
```

### 检查旧堆信息1

```c
  /*
     If not the first time through, we require old_size to be
     at least MINSIZE and to have prev_inuse set.
   */

  assert((old_top == initial_top(av) && old_size == 0) ||
         ((unsigned long)(old_size) >= MINSIZE && prev_inuse(old_top) &&
          ((unsigned long)old_end & (pagesize - 1)) == 0));
```

这个检查要求满足任何其中一个条件

1. `old_top == initial_top(av) && old_size == 0`，即如果是第一次的话，堆的大小需要是 0。
2. 新的堆，那么
    1. `(unsigned long)(old_size) >= MINSIZE && prev_inuse(old_top)`，堆的大小应该不小于 `MINSIZE`，并且前一个堆块应该处于使用中。
    2. `((unsigned long)old_end & (pagesize - 1)) == 0)`，堆的结束地址应该是页对齐的，由于页对齐的大小默认是0x1000，所以低 12 个比特需要为 0。

### 检查旧堆信息2

```c
  /* Precondition: not enough current space to satisfy nb request */
  assert((unsigned long)(old_size) < (unsigned long)(nb + MINSIZE));
```

根据 malloc 中的定义

```c
static void *_int_malloc(mstate av, size_t bytes) {
    INTERNAL_SIZE_T nb;  /* normalized request size */
```

`nb` 应该是已经加上 chunk 头部的字节，为什么还要加上 `MINSIZE `呢？这是因为 top chunk 的大小应该至少预留 MINSIZE 空间，以便于合并。

### 非 main_arena

这里暂时不是关心的重点，暂且不分析。

```c
  if (av != &main_arena) {
    heap_info *old_heap, *heap;
    size_t old_heap_size;

    /* First try to extend the current heap. */
    old_heap = heap_for_ptr(old_top);
    old_heap_size = old_heap->size;
    if ((long)(MINSIZE + nb - old_size) > 0 &&
        grow_heap(old_heap, MINSIZE + nb - old_size) == 0) {
      av->system_mem += old_heap->size - old_heap_size;
      set_head(old_top,
               (((char *)old_heap + old_heap->size) - (char *)old_top) |
                   PREV_INUSE);
    } else if ((heap = new_heap(nb + (MINSIZE + sizeof(*heap)), mp_.top_pad))) {
      /* Use a newly allocated heap.  */
      heap->ar_ptr = av;
      heap->prev = old_heap;
      av->system_mem += heap->size;
      /* Set up the new top.  */
      top(av) = chunk_at_offset(heap, sizeof(*heap));
      set_head(top(av), (heap->size - sizeof(*heap)) | PREV_INUSE);

      /* Setup fencepost and free the old top chunk with a multiple of
         MALLOC_ALIGNMENT in size. */
      /* The fencepost takes at least MINSIZE bytes, because it might
         become the top chunk again later.  Note that a footer is set
         up, too, although the chunk is marked in use. */
      old_size = (old_size - MINSIZE) & ~MALLOC_ALIGN_MASK;
      set_head(chunk_at_offset(old_top, old_size + 2 * SIZE_SZ),
               0 | PREV_INUSE);
      if (old_size >= MINSIZE) {
        set_head(chunk_at_offset(old_top, old_size),
                 (2 * SIZE_SZ) | PREV_INUSE);
        set_foot(chunk_at_offset(old_top, old_size), (2 * SIZE_SZ));
        set_head(old_top, old_size | PREV_INUSE | NON_MAIN_ARENA);
        _int_free(av, old_top, 1);
      } else {
        set_head(old_top, (old_size + 2 * SIZE_SZ) | PREV_INUSE);
        set_foot(old_top, (old_size + 2 * SIZE_SZ));
      }
    } else if (!tried_mmap)
      /* We can at least try to use to mmap memory.  */
      goto try_mmap;
  }
```

### Main_arena 处理

#### 计算内存

计算可以满足请求的内存大小。

```c
else { /* av == main_arena */

    /* Request enough space for nb + pad + overhead */
    size = nb + mp_.top_pad + MINSIZE;
```

默认情况下 `top_pad`定义为

```c
#ifndef DEFAULT_TOP_PAD
# define DEFAULT_TOP_PAD 131072
#endif
```

即 131072 字节，0x20000 字节。

#### 是否连续

如果我们希望堆的空间连续的话，那么其实可以复用之前的内存。

```c
    /*
       If contiguous, we can subtract out existing space that we hope to
       combine with new space. We add it back later only if
       we don't actually get contiguous space.
     */

    if (contiguous(av))
      size -= old_size;
```

#### 对齐页大小

```c
    /*
       Round to a multiple of page size.
       If MORECORE is not contiguous, this ensures that we only call it
       with whole-page arguments.  And if MORECORE is contiguous and
       this is not first time through, this preserves page-alignment of
       previous calls. Otherwise, we correct to page-align below.
     */

    size = ALIGN_UP(size, pagesize);
```

#### 申请内存

```c
    /*
       Don't try to call MORECORE if argument is so big as to appear
       negative. Note that since mmap takes size_t arg, it may succeed
       below even if we cannot call MORECORE.
     */

    if (size > 0) {
      brk = (char *)(MORECORE(size));
      LIBC_PROBE(memory_sbrk_more, 2, brk, size);
    }
```

##### 可能成功

```c
    if (brk != (char *)(MORECORE_FAILURE)) {
      /* Call the `morecore' hook if necessary.  */
      void (*hook)(void) = atomic_forced_read(__after_morecore_hook);
      if (__builtin_expect(hook != NULL, 0))
        (*hook)();
    }
```

这里竟然调用了一个 hook，有点意思。

##### 失败

失败，考虑 mmap。

```c
else {
      /*
         If have mmap, try using it as a backup when MORECORE fails or
         cannot be used. This is worth doing on systems that have "holes" in
         address space, so sbrk cannot extend to give contiguous space, but
         space is available elsewhere.  Note that we ignore mmap max count
         and threshold limits, since the space will not be used as a
         segregated mmap region.
       */

      /* Cannot merge with old top, so add its size back in */
      if (contiguous(av))
        size = ALIGN_UP(size + old_size, pagesize);

      /* If we are relying on mmap as backup, then use larger units */
      if ((unsigned long)(size) < (unsigned long)(MMAP_AS_MORECORE_SIZE))
        size = MMAP_AS_MORECORE_SIZE;

      /* Don't try if size wraps around 0 */
      if ((unsigned long)(size) > (unsigned long)(nb)) {
        char *mbrk = (char *)(MMAP(0, size, PROT_READ | PROT_WRITE, 0));

        if (mbrk != MAP_FAILED) {
          /* We do not need, and cannot use, another sbrk call to find end */
          brk = mbrk;
          snd_brk = brk + size;

          /*
             Record that we no longer have a contiguous sbrk region.
             After the first time mmap is used as backup, we do not
             ever rely on contiguous space since this could incorrectly
             bridge regions.
           */
          set_noncontiguous(av);
        }
      }
    }
```

#### 内存可能申请成功

```c
    if (brk != (char *)(MORECORE_FAILURE)) {
      if (mp_.sbrk_base == 0)
        mp_.sbrk_base = brk;
      av->system_mem += size;
```

##### 情况 1

```c
      /*
         If MORECORE extends previous space, we can likewise extend top size.
       */

      if (brk == old_end && snd_brk == (char *)(MORECORE_FAILURE))
        set_head(old_top, (size + old_size) | PREV_INUSE);
```

##### 情况 2 - 意外内存耗尽

```c
      else if (contiguous(av) && old_size && brk < old_end)
        /* Oops!  Someone else killed our space..  Can't touch anything.  */
        malloc_printerr("break adjusted to free malloc space");
```

##### 处理其他意外情况

```c
      /*
         Otherwise, make adjustments:

       * If the first time through or noncontiguous, we need to call sbrk
          just to find out where the end of memory lies.

       * We need to ensure that all returned chunks from malloc will meet
          MALLOC_ALIGNMENT

       * If there was an intervening foreign sbrk, we need to adjust sbrk
          request size to account for fact that we will not be able to
          combine new space with existing space in old_top.

       * Almost all systems internally allocate whole pages at a time, in
          which case we might as well use the whole last page of request.
          So we allocate enough more memory to hit a page boundary now,
          which in turn causes future contiguous calls to page-align.
       */

      else {
        front_misalign = 0;
        end_misalign = 0;
        correction = 0;
        aligned_brk = brk;
```

###### 处理连续内存

```c
        /* handle contiguous cases */
        if (contiguous(av)) {
          /* Count foreign sbrk as system_mem.  */
          if (old_size)
            av->system_mem += brk - old_end;

          /* Guarantee alignment of first new chunk made from this space */

          front_misalign = (INTERNAL_SIZE_T)chunk2mem(brk) & MALLOC_ALIGN_MASK;
          if (front_misalign > 0) {
            /*
               Skip over some bytes to arrive at an aligned position.
               We don't need to specially mark these wasted front bytes.
               They will never be accessed anyway because
               prev_inuse of av->top (and any chunk created from its start)
               is always true after initialization.
             */

            correction = MALLOC_ALIGNMENT - front_misalign;
            aligned_brk += correction;
          }

          /*
             If this isn't adjacent to existing space, then we will not
             be able to merge with old_top space, so must add to 2nd request.
           */

          correction += old_size;

          /* Extend the end address to hit a page boundary */
          end_misalign = (INTERNAL_SIZE_T)(brk + size + correction);
          correction += (ALIGN_UP(end_misalign, pagesize)) - end_misalign;

          assert(correction >= 0);
          snd_brk = (char *)(MORECORE(correction));

          /*
             If can't allocate correction, try to at least find out current
             brk.  It might be enough to proceed without failing.

             Note that if second sbrk did NOT fail, we assume that space
             is contiguous with first sbrk. This is a safe assumption unless
             program is multithreaded but doesn't use locks and a foreign sbrk
             occurred between our first and second calls.
           */

          if (snd_brk == (char *)(MORECORE_FAILURE)) {
            correction = 0;
            snd_brk = (char *)(MORECORE(0));
          } else {
            /* Call the `morecore' hook if necessary.  */
            void (*hook)(void) = atomic_forced_read(__after_morecore_hook);
            if (__builtin_expect(hook != NULL, 0))
              (*hook)();
          }
        }
```

###### 处理不连续内存

```c
        /* handle non-contiguous cases */
        else {
          if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
            /* MORECORE/mmap must correctly align */
            assert(((unsigned long)chunk2mem(brk) & MALLOC_ALIGN_MASK) == 0);
          else {
            front_misalign =
                (INTERNAL_SIZE_T)chunk2mem(brk) & MALLOC_ALIGN_MASK;
            if (front_misalign > 0) {
              /*
                 Skip over some bytes to arrive at an aligned position.
                 We don't need to specially mark these wasted front bytes.
                 They will never be accessed anyway because
                 prev_inuse of av->top (and any chunk created from its start)
                 is always true after initialization.
               */

              aligned_brk += MALLOC_ALIGNMENT - front_misalign;
            }
          }

          /* Find out current end of memory */
          if (snd_brk == (char *)(MORECORE_FAILURE)) {
            snd_brk = (char *)(MORECORE(0));
          }
        }
```

###### 调整

```c
        /* Adjust top based on results of second sbrk */
        if (snd_brk != (char *)(MORECORE_FAILURE)) {
          av->top = (mchunkptr)aligned_brk;
          set_head(av->top, (snd_brk - aligned_brk + correction) | PREV_INUSE);
          av->system_mem += correction;

          /*
             If not the first time through, we either have a
             gap due to foreign sbrk or a non-contiguous region.  Insert a
             double fencepost at old_top to prevent consolidation with space
             we don't own. These fenceposts are artificial chunks that are
             marked as inuse and are in any case too small to use.  We need
             two to make sizes and alignments work out.
           */

          if (old_size != 0) {
            /*
               Shrink old_top to insert fenceposts, keeping size a
               multiple of MALLOC_ALIGNMENT. We know there is at least
               enough space in old_top to do this.
             */
            old_size = (old_size - 4 * SIZE_SZ) & ~MALLOC_ALIGN_MASK;
            set_head(old_top, old_size | PREV_INUSE);

            /*
               Note that the following assignments completely overwrite
               old_top when old_size was previously MINSIZE.  This is
               intentional. We need the fencepost, even if old_top otherwise
               gets lost.
             */
            set_head(chunk_at_offset(old_top, old_size),
                     (2 * SIZE_SZ) | PREV_INUSE);
            set_head(chunk_at_offset(old_top, old_size + 2 * SIZE_SZ),
                     (2 * SIZE_SZ) | PREV_INUSE);

            /* If possible, release the rest. */
            if (old_size >= MINSIZE) {
              _int_free(av, old_top, 1);
            }
          }
        }
      }
```

需要注意的是，在这里程序将旧的 top chunk 进行了释放，那么其会根据大小进入不同的 bin 或 tcache 中。

#### 更新最大内存

```c
  if ((unsigned long)av->system_mem > (unsigned long)(av->max_system_mem))
    av->max_system_mem = av->system_mem;
  check_malloc_state(av);
```

#### 分配内存块

##### 获取大小

```c
  /* finally, do the allocation */
  p = av->top;
  size = chunksize(p);
```

##### 切分 top

```c
  /* check that one of the above allocation paths succeeded */
  if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE)) {
    remainder_size = size - nb;
    remainder = chunk_at_offset(p, nb);
    av->top = remainder;
    set_head(p, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head(remainder, remainder_size | PREV_INUSE);
    check_malloced_chunk(av, p, nb);
    return chunk2mem(p);
  }
```

#### 捕捉所有错误

```c
  /* catch all failure paths */
  __set_errno(ENOMEM);
  return 0;
```

