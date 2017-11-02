# 深入理解堆的实现

简单想一下，对于任何堆的实现来说都离不开以下的问题

- 宏观角度
  - 创建堆并对堆进行初始化
  - 删除堆
- 微观角度
  - 申请内存块
  - 释放内存块

当然，这些都是一些比较高层面的想法，对于一些底层的实现来说，会有所不同。

## 堆初始化

## 创建堆

## 申请内存块

我们之前也说了，我们会使用malloc函数来申请内存块，可是当我们仔细看看glibc的源码实现时，其实并没有malloc函数。其实该函数真正调用的是__libc_malloc函数。为什么不直接写个malloc函数呢，因为有时候我们可能需要不同的名称，而且该函数只是用来简单封装\_int_malloc函数。\_int_malloc 才是申请内存块的核心。下面我们来仔细分析一下实现。

### __libc_malloc

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

### _int_malloc

#### 概述

_int_malloc时内存分配的核心函数，其核心思路有以下几点

1. 它根据用户申请的内存块的大小，依次实现了不同的分配方法。
2. 它会首先检查申请的内存块是不是有相应的空闲块可以满足需求，没有的话，才会进行内存块申请。
3. 它会按照chunk 的大小由小到大依次判断。

#### 初始

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

#### 判断是否有arena可用

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

#### small bin

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

#### large bin

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

#### 循环

##### 概述

**上面说明没有bin可以直接满足需求**。在接下来的这个循环中，主要做了以下的操作

- 尝试从unsorted bin中分配用户所需的内存
- 尝试从large bin中分配用户所需的内存
- 尝试从top  chunk中分配用户所需内存

##### 大循环

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

##### unsort bin & last remainder

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
            // 如果unsorted bin中的chunk大小正好合适，就直接使用
            if (size == nb) {
                set_inuse_bit_at_offset(victim, size);
                if (av != &main_arena) set_non_main_arena(victim);
                check_malloced_chunk(av, victim, nb);
                void *p = chunk2mem(victim);
                alloc_perturb(p, bytes);
                return p;
            }

            /* place chunk in bin */
            // 把chunk放到对应的bin中
            // small bin范围
            if (in_smallbin_range(size)) {
                victim_index = smallbin_index(size);
                bck          = bin_at(av, victim_index);
                fwd          = bck->fd;
            } else {
                // large bin范围
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
            // 放到对应的bin中
            mark_bin(av, victim_index);
            victim->bk = bck;
            victim->fd = fwd;
            fwd->bk    = victim;
            bck->fd    = victim;
            // 最多迭代10000次
##define MAX_ITERS 10000
            if (++iters >= MAX_ITERS) break;
        }
```

##### large chunk



```c++
        /*
           If a large request, scan through the chunks of current bin in
           sorted order to find smallest that fits.  Use the skip list for this.
         */
        // 如果请求的chunk在large chunk范围内，就在对应的bin中从小到大进行扫描，找到第一个合适的
        if (!in_smallbin_range(nb)) {
            bin = bin_at(av, idx);

            /* skip scan if empty or largest chunk is too small */
            // 如果 对应的bin为空或者其中的chunk最大的也很小，那就跳过
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
                    if (__glibc_unlikely(fwd->bk != bck)) {
                        errstr = "malloc(): corrupted unsorted chunks";
                        goto errout;
                    }
                    remainder->bk = bck;
                    remainder->fd = fwd;
                    bck->fd       = remainder;
                    fwd->bk       = remainder;
                    // 如果处于small bin范围内，就设置对应的字段
                    if (!in_smallbin_range(remainder_size)) {
                        remainder->fd_nextsize = NULL;
                        remainder->bk_nextsize = NULL;
                    }
                    // 设置分配的chunk的标记
                    set_head(victim,
                             nb | PREV_INUSE |
                                 (av != &main_arena ? NON_MAIN_ARENA : 0));
                  
                    // 设置remainder的使用状态，其余的不用管，直接从上面继承下来了
                    // 为什么这里也设置了inuse？
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

##### 暂时转换

如果走到了这里，那说明对于用户所需的chunk，不能直接从其对应的合适的bin中获取chunk，所以我们需要来查找比当前bin更大的fast bin，small bin或者large bin。

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
```



##### 小循环



```c++
        for (;;) {
            /* Skip rest of block if there are no more set bits in this block.
             */
            // 如果bit>map，则表示该map中没有比当前所需要chunk大的空闲块
            // 如果bit为0，那么说明，上面idx2bit带入的参数为0。
            if (bit > map || bit == 0) {
                do {
                    // 寻找下一个block，直到其对应的map不为0。
                    // 如果已经不存在的话，那就只能使用top chunk了
                    if (++block >= BINMAPSIZE) /* out of bins */
                        goto use_top;
                } while ((map = av->binmap[ block ]) == 0);
                // 获取其对应的bin，因为该map中的chunk大小都比所需的chunk大，而且
                // map本身不为0，所以必然存在瞒住需求的chunk。
                bin = bin_at(av, (block << BINMAPSHIFT));
                bit = 1;
            }

            /* Advance to bin with set bit. There must be one. */
            // 从当前map的最小的bin一直找，直到找到合适的bin。
            // 这里是一定存在的
            while ((bit & map) == 0) {
                bin = next_bin(bin);
                bit <<= 1;
                assert(bit != 0);
            }

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

            else {
                //获取对应victim的大小
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
        }
```

##### 使用top chunk

如果所有的bin中的chunk都没有办法直接满足要求（即不合并），或者说都没有空闲的chunk。那么我们就只能使用top chunk了。

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
        // 如果在分割之后，其大小仍然满足chunk的最小大小，那么就可以直接进行分割。
        if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) {
            remainder_size = size - nb;
            remainder      = chunk_at_offset(victim, nb);
            av->top        = remainder;
            set_head(victim, nb | PREV_INUSE |
                                 (av != &main_arena ? NON_MAIN_ARENA : 0));
            set_head(remainder, remainder_size | PREV_INUSE);

            check_malloced_chunk(av, victim, nb);
            void *p = chunk2mem(victim);
            alloc_perturb(p, bytes);
            return p;
        }
        // 否则，判断是否有fast chunk
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



### sysmalloc

有时间的时候再分析。

### malloc_consolidate

有时间的时候再分析。

## 释放内存块

### __libc_free

类似于malloc，free函数也有一层封装，命名格式与malloc基本类似。代码如下

```c++
void __libc_free(void *mem) {
    mstate    ar_ptr;
    mchunkptr p; /* chunk corresponding to mem */
    // 判断是否有钩子函数
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

#### 概述

#### 初始化

进行函数后，立马定义了一系列的变量，并且得到了用户想要释放的chunk的大小

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
    // 指针不能指向非法的地址
    // 指针必须得对齐，这个对齐得仔细想想
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
    // 检查该chunk是否处于使用状态，如果
    check_inuse_chunk(av, p);
```

#### fast bin

如果上述检查都合格的话，判断当前的bin是不是在fast bin范围内，在的话，就插入到fastbin中

```c++
    /*
      If eligible, place chunk on a fastbin so it can be found
      and used quickly in malloc.
    */

    if ((unsigned long) (size) <= (unsigned long) (get_max_fast())

##if TRIM_FASTBINS
        /*
      If TRIM_FASTBINS set, don't place chunks
      bordering top into fastbins
        */
       // 如果当前chunk是fast chunk，并且下一个chunk是top chunk，则不能插入
        && (chunk_at_offset(p, size) != av->top)
##endif
            ) {
        // 下一个chunk的大小不能小于两倍的SIZE_SZ,并且
        // 下一个chunk的大小不能大于系统可提供的内存
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
            // 防止对fast bin double free
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

#### 合并非mmap的空闲chunk

首先，我们先说一下为什么会合并chunk，这是为了避免heap中有太多的零零碎碎的内存块，合并之后可以用来应对更大的内存块请求。

合并的主要顺序为

- 先考虑低地址空闲块
- 后考虑高地址空闲块

**合并后的chunk指向所有合并的chunk的低地址。**

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
        //将 指针的mem部分全部设置为perturb_byte 
		free_perturb(chunk2mem(p), size - 2 * SIZE_SZ);
```

##### 后向合并-合并低地址chunk

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

需要注意的是，如果下一块不是top chunk后，合并后的chunk会被放入到unsorted bin中。

```c++
		// 如果下一个chunk不是top chunk
		if (nextchunk != av->top) {
            /* get and clear inuse bit */
            // 获取下一个chunk的使用状态
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
            // 把chunk放在unsorted chunk链表的尾部
            bck = unsorted_chunks(av);
            fwd = bck->fd;
            // 简单的检查
            if (__glibc_unlikely(fwd->bk != bck)) {
                errstr = "free(): corrupted unsorted chunks";
                goto errout;
            }
            p->fd = fwd;
            p->bk = bck;
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
         // 如果合并后的chunk的大小大于FASTBIN_CONSOLIDATION_THRESHOLD
         // 那就向系统返还内存
        if ((unsigned long) (size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
            // 如果有fast chunk 就进行合并
            if (have_fastchunks(av)) malloc_consolidate(av);
            // 主分配区
            if (av == &main_arena) {
##ifndef MORECORE_CANNOT_TRIM
                // top chunk 大于当前的收缩阙值
                if ((unsigned long) (chunksize(av->top)) >=
                    (unsigned long) (mp_.trim_threshold))
                    systrim(mp_.top_pad, av);
##endif      // 非主分配区，则直接收缩heap
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

### unlink

unlink函数主要是将chunk P从bin中取出来，如下

```c
/* Take a chunk off a bin list */
##define unlink(AV, P, BK, FD) {                                            \
    FD = P->fd;                                                                      \
    BK = P->bk;                                                                      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {                                                                      \
        FD->bk = BK;                                                              \
        BK->fd = FD;                                                              \
        if (!in_smallbin_range (chunksize_nomask (P))                              \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {                      \
            if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)              \
                || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
              malloc_printerr (check_action,                                      \
                               "corrupted double-linked list (not small)",    \
                               P, AV);                                              \
            if (FD->fd_nextsize == NULL) {                                      \
                if (P->fd_nextsize == P)                                      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;                      \
                else {                                                              \
                    FD->fd_nextsize = P->fd_nextsize;                              \
                    FD->bk_nextsize = P->bk_nextsize;                              \
                    P->fd_nextsize->bk_nextsize = FD;                              \
                    P->bk_nextsize->fd_nextsize = FD;                              \
                  }                                                              \
              } else {                                                              \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;                      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;                      \
              }                                                                      \
          }                                                                      \
      }                                                                              \
}
```

可以看到首先是分别获取P的forward chunk和backward chunk。

```
FD = P->fd;                                                                      \
BK = P->bk;                                                                      \
```

接下来有这样的一个判断

```
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
  malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
```

看起来似乎很正常，P的forward chunk的bk很自然是P，同样P的backward chunk的fd也很自然是P。然而，这里真正的目的在于进行双向链表的冲突检测。

考虑加入没有的情况，如果我们将该chunk 的fd为某个got表项-12(32位)的地址，同时修改bk为shellcode代码，这样当执行完下面的代码后，该got表项的地址其实就是shellcode的地址。如果我们调用了该got表项对应的函数，那么实际上执行的就是shellcode。所以这里的检查是必要的。

然后就是直接修改相应的指针，去掉P。

接下来判断chunk P是否属于large chunk，如果属于就需要进行进一步的处理。

**注意：堆的第一个chunk的话所记录的prev_inuse位默认为1。**

1. **给出图片说明**
2. **说明unlink的判断**

### systrim

### heap_trim

### munmap_chunk



## 删除堆

