[EN](./free.md) | [ZH](./free-zh.md)
# 释放内存块

## __libc_free

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

## _int_free

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

### 简单的检查

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



### fast bin

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

### 合并非 mmap 的空闲 chunk

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

#### 轻量级的检测

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

#### 释放填充

```c++
        //将指针的mem部分全部设置为perturb_byte
		free_perturb(chunk2mem(p), size - 2 * SIZE_SZ);
```

#### 后向合并-合并低地址 chunk

```c++
        /* consolidate backward */
        if (!prev_inuse(p)) {
            prevsize = prev_size(p);
            size += prevsize;
            p = chunk_at_offset(p, -((long) prevsize));
            unlink(av, p, bck, fwd);
        }
```

#### 下一块不是top chunk-前向合并-合并高地址chunk

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

#### 下一块是 top chunk-合并到 top chunk

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

#### 向系统返还内存

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

### 释放 mmap 的chunk

```c++
    } else {
        //  If the chunk was allocated via mmap, release via munmap().
        munmap_chunk(p);
    }
```

## systrim

## heap_trim

## munmap_chunk