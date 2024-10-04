# 釋放內存塊

## __libc_free

類似於 malloc，free 函數也有一層封裝，命名格式與 malloc 基本類似。代碼如下

```c++
void __libc_free(void *mem) {
    mstate    ar_ptr;
    mchunkptr p; /* chunk corresponding to mem */
    // 判斷是否有鉤子函數 __free_hook
    void (*hook)(void *, const void *) = atomic_forced_read(__free_hook);
    if (__builtin_expect(hook != NULL, 0)) {
        (*hook)(mem, RETURN_ADDRESS(0));
        return;
    }
    // free NULL沒有作用
    if (mem == 0) /* free(0) has no effect */
        return;
    // 將mem轉換爲chunk狀態
    p = mem2chunk(mem);
    // 如果該塊內存是mmap得到的
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
    // 根據chunk獲得分配區的指針
    ar_ptr = arena_for_chunk(p);
    // 執行釋放
    _int_free(ar_ptr, p, 0);
}
```

## _int_free

函數初始時刻定義了一系列的變量，並且得到了用戶想要釋放的 chunk 的大小

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

### 簡單的檢查

```c++
    /* Little security check which won't hurt performance: the
       allocator never wrapps around at the end of the address space.
       Therefore we can exclude some size values which might appear
       here by accident or by "design" from some intruder.  */
    // 指針不能指向非法的地址, 必須小於等於-size，爲什麼？？？
    // 指針必須得對齊，2*SIZE_SZ 這個對齊得仔細想想
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
    // 大小沒有最小的chunk大，或者說，大小不是MALLOC_ALIGNMENT的整數倍
    if (__glibc_unlikely(size < MINSIZE || !aligned_OK(size))) {
        errstr = "free(): invalid size";
        goto errout;
    }
    // 檢查該chunk是否處於使用狀態，非調試狀態下沒有作用
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

如果上述檢查都合格的話，判斷當前的 bin 是不是在 fast bin 範圍內，在的話就插入到 **fastbin 頭部**，即成爲對應 fastbin 鏈表的**第一個 free chunk**。

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
       //默認 #define TRIM_FASTBINS 0，因此默認情況下下面的語句不會執行
       // 如果當前chunk是fast chunk，並且下一個chunk是top chunk，則不能插入
        && (chunk_at_offset(p, size) != av->top)
#endif
            ) {
        // 下一個chunk的大小不能小於兩倍的SIZE_SZ,並且
        // 下一個chunk的大小不能大於system_mem， 一般爲132k
        // 如果出現這樣的情況，就報錯。
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
        // 將chunk的mem部分全部設置爲perturb_byte
        free_perturb(chunk2mem(p), size - 2 * SIZE_SZ);
        // 設置fast chunk的標記位
        set_fastchunks(av);
        // 根據大小獲取fast bin的索引
        unsigned int idx = fastbin_index(size);
        // 獲取對應fastbin的頭指針，被初始化後爲NULL。
        fb               = &fastbin(av, idx);

        /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
        // 使用原子操作將P插入到鏈表中
        mchunkptr    old     = *fb, old2;
        unsigned int old_idx = ~0u;
        do {
            /* Check that the top of the bin is not the record we are going to
               add
               (i.e., double free).  */
            // so we can not double free one fastbin chunk
            // 防止對 fast bin double free
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
        // 確保fast bin的加入前與加入後相同
        if (have_lock && old != NULL && __builtin_expect(old_idx != idx, 0)) {
            errstr = "invalid fastbin entry (free)";
            goto errout;
        }
    }
```

### 合併非 mmap 的空閒 chunk

**只有不是 fast bin 的情況下才會觸發unlink**

首先我們先說一下爲什麼會合並chunk，這是爲了避免heap中有太多零零碎碎的內存塊，合併之後可以用來應對更大的內存塊請求。合併的主要順序爲

- 先考慮物理低地址空閒塊
- 後考慮物理高地址空閒塊

**合併後的 chunk 指向合併的 chunk 的低地址。**

在沒有鎖的情況下，先獲得鎖。

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

#### 輕量級的檢測

```c++
        /* Lightweight tests: check whether the block is already the
           top block.  */
        // 當前free的chunk不能是top chunk
        if (__glibc_unlikely(p == av->top)) {
            errstr = "double free or corruption (top)";
            goto errout;
        }
        // 當前free的chunk的下一個chunk不能超過arena的邊界
        /* Or whether the next chunk is beyond the boundaries of the arena.  */
        if (__builtin_expect(contiguous(av) &&
                                 (char *) nextchunk >=
                                     ((char *) av->top + chunksize(av->top)),
                             0)) {
            errstr = "double free or corruption (out)";
            goto errout;
        }
        // 當前要free的chunk的使用標記沒有被標記，double free
        /* Or whether the block is actually not marked used.  */
        if (__glibc_unlikely(!prev_inuse(nextchunk))) {
            errstr = "double free or corruption (!prev)";
            goto errout;
        }
        // 下一個chunk的大小
        nextsize = chunksize(nextchunk);
        // next chunk size valid check
        // 判斷下一個chunk的大小是否不大於2*SIZE_SZ，或者
        // nextsize是否大於系統可提供的內存
        if (__builtin_expect(chunksize_nomask(nextchunk) <= 2 * SIZE_SZ, 0) ||
            __builtin_expect(nextsize >= av->system_mem, 0)) {
            errstr = "free(): invalid next size (normal)";
            goto errout;
        }
```

#### 釋放填充

```c++
        //將指針的mem部分全部設置爲perturb_byte
		free_perturb(chunk2mem(p), size - 2 * SIZE_SZ);
```

#### 後向合併-合併低地址 chunk

```c++
        /* consolidate backward */
        if (!prev_inuse(p)) {
            prevsize = prev_size(p);
            size += prevsize;
            p = chunk_at_offset(p, -((long) prevsize));
            unlink(av, p, bck, fwd);
        }
```

#### 下一塊不是top chunk-前向合併-合併高地址chunk

需要注意的是，如果下一塊不是 top chunk ，則合併高地址的 chunk ，並將合併後的 chunk 放入到unsorted bin中。

```c++
		// 如果下一個chunk不是top chunk
		if (nextchunk != av->top) {
            /* get and clear inuse bit */
            // 獲取下一個 chunk 的使用狀態
            nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
            // 如果不在使用，合併，否則清空當前chunk的使用狀態。
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
            // 把 chunk 放在 unsorted chunk 鏈表的頭部
            bck = unsorted_chunks(av);
            fwd = bck->fd;
            // 簡單的檢查
            if (__glibc_unlikely(fwd->bk != bck)) {
                errstr = "free(): corrupted unsorted chunks";
                goto errout;
            }
            p->fd = fwd;
            p->bk = bck;
            // 如果是 large chunk，那就設置nextsize指針字段爲NULL。
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

#### 下一塊是 top chunk-合併到 top chunk

```c++
        /*
          If the chunk borders the current high end of memory,
          consolidate into top
        */
        // 如果要釋放的chunk的下一個chunk是top chunk，那就合併到 top chunk
        else {
            size += nextsize;
            set_head(p, size | PREV_INUSE);
            av->top = p;
            check_chunk(av, p);
        }
```

#### 向系統返還內存

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
         // 如果合併後的 chunk 的大小大於FASTBIN_CONSOLIDATION_THRESHOLD
         // 一般合併到 top chunk 都會執行這部分代碼。
         // 那就向系統返還內存
        if ((unsigned long) (size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
            // 如果有 fast chunk 就進行合併
            if (have_fastchunks(av)) malloc_consolidate(av);
            // 主分配區
            if (av == &main_arena) {
#ifndef MORECORE_CANNOT_TRIM
                // top chunk 大於當前的收縮闕值
                if ((unsigned long) (chunksize(av->top)) >=
                    (unsigned long) (mp_.trim_threshold))
                    systrim(mp_.top_pad, av);
#endif      // 非主分配區，則直接收縮heap
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

### 釋放 mmap 的chunk

```c++
    } else {
        //  If the chunk was allocated via mmap, release via munmap().
        munmap_chunk(p);
    }
```

## systrim

## heap_trim

## munmap_chunk