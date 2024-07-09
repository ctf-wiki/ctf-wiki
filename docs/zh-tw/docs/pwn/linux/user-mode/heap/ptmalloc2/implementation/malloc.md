# 申請內存塊

## __libc_malloc

一般我們會使用 malloc 函數來申請內存塊，可是當仔細看 glibc 的源碼實現時，其實並沒有 malloc 函數。其實該函數真正調用的是 \_\_libc_malloc 函數。爲什麼不直接寫個 malloc 函數呢，因爲有時候我們可能需要不同的名稱。此外，__libc_malloc 函數只是用來簡單封裝 _int_malloc 函數。\_int_malloc 纔是申請內存塊的核心。下面我們來仔細分析一下具體的實現。

該函數會首先檢查是否有內存分配函數的鉤子函數（__malloc_hook），這個主要用於用戶自定義的堆分配函數，方便用戶快速修改堆分配函數並進行測試。這裏需要注意的是，**用戶申請的字節一旦進入申請內存函數中就變成了無符號整數**。

```c++
// wapper for int_malloc
void *__libc_malloc(size_t bytes) {
    mstate ar_ptr;
    void * victim;
    // 檢查是否有內存分配鉤子，如果有，調用鉤子並返回.
    void *(*hook)(size_t, const void *) = atomic_forced_read(__malloc_hook);
    if (__builtin_expect(hook != NULL, 0))
        return (*hook)(bytes, RETURN_ADDRESS(0));

```

接着會尋找一個 arena 來試圖分配內存。

```c++
    arena_get(ar_ptr, bytes);
```

然後調用 _int_malloc 函數去申請對應的內存。

```c++
    victim = _int_malloc(ar_ptr, bytes);
```

如果分配失敗的話，ptmalloc 會嘗試再去尋找一個可用的 arena，並分配內存。

```c++
    /* Retry with another arena only if we were able to find a usable arena
       before.  */
    if (!victim && ar_ptr != NULL) {
        LIBC_PROBE(memory_malloc_retry, 1, bytes);
        ar_ptr = arena_get_retry(ar_ptr, bytes);
        victim = _int_malloc(ar_ptr, bytes);
    }
```

如果申請到了 arena，那麼在退出之前還得解鎖。

```c++
    if (ar_ptr != NULL) __libc_lock_unlock(ar_ptr->mutex);
```

判斷目前的狀態是否滿足以下條件

- 要麼沒有申請到內存
- 要麼是 mmap 的內存
- **要麼申請到的內存必須在其所分配的arena中**

```c++
    assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
           ar_ptr == arena_for_chunk(mem2chunk(victim)));
```

最後返回內存。

```c++
    return victim;
}
```

## _int_malloc

_int_malloc 是內存分配的核心函數，其核心思路有如下

1. 它根據用戶申請的**內存塊大小**以及**相應大小 chunk 通常使用的頻度**（fastbin chunk, small chunk, large chunk），依次實現了不同的分配方法。
2. 它由小到大依次檢查不同的 bin 中是否有相應的空閒塊可以滿足用戶請求的內存。
3. 當所有的空閒 chunk 都無法滿足時，它會考慮 top chunk。
4. 當 top chunk 也無法滿足時，堆分配器纔會進行內存塊申請。

在進入該函數後，函數立馬定義了一系列自己需要的變量，並將用戶申請的內存大小轉換爲內部的chunk大小。

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

如果申請的 chunk 的大小位於 fastbin 範圍內，**需要注意的是這裏比較的是無符號整數**。**此外，是從 fastbin 的頭結點開始取 chunk**。

```c++
    /*
       If the size qualifies as a fastbin, first check corresponding bin.
       This code is safe to execute even if av is not yet initialized, so we
       can try it without checking, which saves some time on this fast path.
     */

    if ((unsigned long) (nb) <= (unsigned long) (get_max_fast())) {
        // 得到對應的fastbin的下標
        idx             = fastbin_index(nb);
        // 得到對應的fastbin的頭指針
        mfastbinptr *fb = &fastbin(av, idx);
        mchunkptr    pp = *fb;
        // 利用fd遍歷對應的bin內是否有空閒的chunk塊，
        do {
            victim = pp;
            if (victim == NULL) break;
        } while ((pp = catomic_compare_and_exchange_val_acq(fb, victim->fd,
                                                            victim)) != victim);
        // 存在可以利用的chunk
        if (victim != 0) {
            // 檢查取到的 chunk 大小是否與相應的 fastbin 索引一致。
            // 根據取得的 victim ，利用 chunksize 計算其大小。
            // 利用fastbin_index 計算 chunk 的索引。
            if (__builtin_expect(fastbin_index(chunksize(victim)) != idx, 0)) {
                errstr = "malloc(): memory corruption (fast)";
            errout:
                malloc_printerr(check_action, errstr, chunk2mem(victim), av);
                return NULL;
            }
            // 細緻的檢查。。只有在 DEBUG 的時候有用
            check_remalloced_chunk(av, victim, nb);
            // 將獲取的到chunk轉換爲mem模式
            void *p = chunk2mem(victim);
            // 如果設置了perturb_type, 則將獲取到的chunk初始化爲 perturb_type ^ 0xff
            alloc_perturb(p, bytes);
            return p;
        }
    }
```

### small bin

如果獲取的內存塊的範圍處於 small bin 的範圍，那麼執行如下流程

```c++
    /*
       If a small request, check regular bin.  Since these "smallbins"
       hold one size each, no searching within bins is necessary.
       (For a large request, we need to wait until unsorted chunks are
       processed to find best fit. But for small ones, fits are exact
       anyway, so we can check now, which is faster.)
     */

    if (in_smallbin_range(nb)) {
        // 獲取 small bin 的索引
        idx = smallbin_index(nb);
        // 獲取對應 small bin 中的 chunk 指針
        bin = bin_at(av, idx);
        // 先執行 victim = last(bin)，獲取 small bin 的最後一個 chunk
        // 如果 victim = bin ，那說明該 bin 爲空。
        // 如果不相等，那麼會有兩種情況
        if ((victim = last(bin)) != bin) {
            // 第一種情況，small bin 還沒有初始化。
            if (victim == 0) /* initialization check */
                // 執行初始化，將 fast bins 中的 chunk 進行合併
                malloc_consolidate(av);
            // 第二種情況，small bin 中存在空閒的 chunk
            else {
                // 獲取 small bin 中倒數第二個 chunk 。
                bck = victim->bk;
                // 檢查 bck->fd 是不是 victim，防止僞造
                if (__glibc_unlikely(bck->fd != victim)) {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                // 設置 victim 對應的 inuse 位
                set_inuse_bit_at_offset(victim, nb);
                // 修改 small bin 鏈表，將 small bin 的最後一個 chunk 取出來
                bin->bk = bck;
                bck->fd = bin;
                // 如果不是 main_arena，設置對應的標誌
                if (av != &main_arena) set_non_main_arena(victim);
                // 細緻的檢查，非調試狀態沒有作用
                check_malloced_chunk(av, victim, nb);
                // 將申請到的 chunk 轉化爲對應的 mem 狀態
                void *p = chunk2mem(victim);
                // 如果設置了 perturb_type , 則將獲取到的chunk初始化爲 perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
        }
    }
```

### large bin

當 fast bin、small bin 中的 chunk 都不能滿足用戶請求 chunk 大小時，就會考慮是不是 large bin。但是，其實在 large bin 中並沒有直接去掃描對應 bin 中的chunk，而是先利用 malloc_consolidate（參見malloc_state相關函數） 函數處理 fast bin 中的chunk，將有可能能夠合併的 chunk 先進行合併後放到 unsorted bin 中，不能夠合併的就直接放到 unsorted bin 中，然後再在下面的大循環中進行相應的處理。**爲什麼不直接從相應的 bin 中取出 large chunk 呢？這是ptmalloc 的機制，它會在分配 large chunk 之前對堆中碎片 chunk 進行合併，以便減少堆中的碎片。**

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
        // 獲取large bin的下標。
        idx = largebin_index(nb);
        // 如果存在fastbin的話，會處理 fastbin
        if (have_fastchunks(av)) malloc_consolidate(av);
    }

```

### 大循環-遍歷 unsorted bin

**如果程序執行到了這裏，那麼說明 與 chunk 大小正好一致的 bin (fast bin， small bin) 中沒有 chunk可以直接滿足需求 ，但是 large chunk  則是在這個大循環中處理**。

在接下來的這個循環中，主要做了以下的操作

- 按照 FIFO 的方式逐個將 unsorted bin 中的 chunk 取出來
    - 如果是 small request，則考慮是不是恰好滿足，是的話，直接返回。
    - 如果不是的話，放到對應的 bin 中。
- 嘗試從 large bin 中分配用戶所需的內存

該部分是一個大循環，這是爲了嘗試重新分配 small bin chunk，這是因爲我們雖然會首先使用 large bin，top chunk 來嘗試滿足用戶的請求，但是如果沒有滿足的話，由於我們在上面沒有分配成功 small bin，我們並沒有對fast bin 中的 chunk 進行合併，所以這裏會進行 fast bin chunk 的合併，進而使用一個大循環來嘗試再次分配small bin chunk。

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

#### unsorted bin 遍歷

先考慮 unsorted bin，再考慮 last remainder ，但是對於 small bin chunk 的請求會有所例外。

**注意 unsorted bin 的遍歷順序爲 bk。**

```c++
        // 如果 unsorted bin 不爲空
        // First In First Out
        while ((victim = unsorted_chunks(av)->bk) != unsorted_chunks(av)) {
            // victim 爲 unsorted bin 的最後一個 chunk
            // bck 爲 unsorted bin 的倒數第二個 chunk
            bck = victim->bk;
            // 判斷得到的 chunk 是否滿足要求，不能過小，也不能過大
            // 一般 system_mem 的大小爲132K
            if (__builtin_expect(chunksize_nomask(victim) <= 2 * SIZE_SZ, 0) ||
                __builtin_expect(chunksize_nomask(victim) > av->system_mem, 0))
                malloc_printerr(check_action, "malloc(): memory corruption",
                                chunk2mem(victim), av);
            // 得到victim對應的chunk大小。
            size = chunksize(victim);
```

##### small request

如果用戶的請求爲 small bin chunk，那麼我們首先考慮 last remainder，如果 last remainder 是 unsorted bin 中的唯一一塊的話， 並且 last remainder 的大小分割後還可以作爲一個 chunk ，**爲什麼沒有等號**？

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
                // 獲取新的 remainder 的大小
                remainder_size          = size - nb;
                // 獲取新的 remainder 的位置
                remainder               = chunk_at_offset(victim, nb);
                // 更新 unsorted bin 的情況
                unsorted_chunks(av)->bk = unsorted_chunks(av)->fd = remainder;
                // 更新 av 中記錄的 last_remainder
                av->last_remainder                                = remainder;
                // 更新last remainder的指針
                remainder->bk = remainder->fd = unsorted_chunks(av);
                if (!in_smallbin_range(remainder_size)) {
                    remainder->fd_nextsize = NULL;
                    remainder->bk_nextsize = NULL;
                }
                // 設置victim的頭部，
                set_head(victim, nb | PREV_INUSE |
                                     (av != &main_arena ? NON_MAIN_ARENA : 0));
                // 設置 remainder 的頭部
                set_head(remainder, remainder_size | PREV_INUSE);
                // 設置記錄 remainder 大小的 prev_size 字段，因爲此時 remainder 處於空閒狀態。
                set_foot(remainder, remainder_size);
                // 細緻的檢查，非調試狀態下沒有作用
                check_malloced_chunk(av, victim, nb);
                // 將 victim 從 chunk 模式轉化爲mem模式
                void *p = chunk2mem(victim);
                // 如果設置了perturb_type, 則將獲取到的chunk初始化爲 perturb_type ^ 0xff
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

如果從 unsorted bin 中取出來的 chunk 大小正好合適，就直接使用。這裏應該已經把合併後恰好合適的 chunk 給分配出去了。

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

把取出來的 chunk 放到對應的 small bin 中。

```c
            /* place chunk in bin */

            if (in_smallbin_range(size)) {
                victim_index = smallbin_index(size);
                bck          = bin_at(av, victim_index);
                fwd          = bck->fd;
```

##### place chunk in large bin

把取出來的 chunk 放到對應的 large bin 中。

```c
            } else {
                // large bin 範圍
                victim_index = largebin_index(size);
                bck          = bin_at(av, victim_index); // 當前 large bin 的頭部
                fwd          = bck->fd;

                /* maintain large bins in sorted order */
                /* 從這裏我們可以總結出，largebin 以 fd_nextsize 遞減排序。
                   同樣大小的 chunk，後來的只會插入到之前同樣大小的 chunk 後，
                   而不會修改之前相同大小的fd/bk_nextsize，這也很容易理解，
                   可以減低開銷。此外，bin 頭不參與 nextsize 鏈接。*/
                // 如果 large bin 鏈表不空
                if (fwd != bck) {
                    /* Or with inuse bit to speed comparisons */
                    // 加速比較，應該不僅僅有這個考慮，因爲鏈表裏的 chunk 都會設置該位。
                    size |= PREV_INUSE;
                    /* if smaller than smallest, bypass loop below */
                    // bck->bk 存儲着相應 large bin 中最小的chunk。
                    // 如果遍歷的 chunk 比當前最小的還要小，那就只需要插入到鏈表尾部。
                    // 判斷 bck->bk 是不是在 main arena。
                    assert(chunk_main_arena(bck->bk));
                    if ((unsigned long) (size) <
                        (unsigned long) chunksize_nomask(bck->bk)) {
                        // 令 fwd 指向 large bin 頭
                        fwd = bck;
                        // 令 bck 指向 largin bin 尾部 chunk
                        bck = bck->bk;
                        // victim 的 fd_nextsize 指向 largin bin 的第一個 chunk
                        victim->fd_nextsize = fwd->fd;
                        // victim 的 bk_nextsize 指向原來鏈表的第一個 chunk 指向的 bk_nextsize
                        victim->bk_nextsize = fwd->fd->bk_nextsize;
                        // 原來鏈表的第一個 chunk 的 bk_nextsize 指向 victim
                        // 原來指向鏈表第一個 chunk 的 fd_nextsize 指向 victim
                        fwd->fd->bk_nextsize =
                            victim->bk_nextsize->fd_nextsize = victim;
                    } else {
                        // 當前要插入的 victim 的大小大於最小的 chunk
                        // 判斷 fwd 是否在 main arena
                        assert(chunk_main_arena(fwd));
                        // 從鏈表頭部開始找到不比 victim 大的 chunk
                        while ((unsigned long) size < chunksize_nomask(fwd)) {
                            fwd = fwd->fd_nextsize;
                            assert(chunk_main_arena(fwd));
                        }
                        // 如果找到了一個和 victim 一樣大的 chunk，
                        // 那就直接將 chunk 插入到該chunk的後面，並不修改 nextsize 指針。
                        if ((unsigned long) size ==
                            (unsigned long) chunksize_nomask(fwd))
                            /* Always insert in the second position.  */
                            fwd = fwd->fd;
                        else {
                            // 如果找到的chunk和當前victim大小不一樣
                            // 那麼就需要構造 nextsize 雙向鏈表了
                            victim->fd_nextsize              = fwd;
                            victim->bk_nextsize              = fwd->bk_nextsize;
                            fwd->bk_nextsize                 = victim;
                            victim->bk_nextsize->fd_nextsize = victim;
                        }
                        bck = fwd->bk;
                    }
                } else
                    // 如果空的話，直接簡單使得 fd_nextsize 與 bk_nextsize 構成一個雙向鏈表即可。
                    victim->fd_nextsize = victim->bk_nextsize = victim;
            }
```

##### 最終取出

```c
            // 放到對應的 bin 中，構成 bck<-->victim<-->fwd。
            mark_bin(av, victim_index);
            victim->bk = bck;
            victim->fd = fwd;
            fwd->bk    = victim;
            bck->fd    = victim;
```

##### while 迭代次數

while 最多迭代10000次後退出。

```c
            // #define MAX_ITERS 10000
            if (++iters >= MAX_ITERS) break;
        }
```

#### large chunk

**注： 或許會很奇怪，爲什麼這裏沒有先去看 small chunk 是否滿足新需求了呢？這是因爲small bin 在循環之前已經判斷過了，這裏如果有的話，就是合併後的纔出現chunk。但是在大循環外，large chunk 只是單純地找到其索引，所以覺得在這裏直接先判斷是合理的，而且也爲了下面可以再去找較大的chunk。**

如果請求的 chunk 在 large chunk 範圍內，就在對應的 bin 中從小到大進行掃描，找到第一個合適的。

```c++
        /*
           If a large request, scan through the chunks of current bin in
           sorted order to find smallest that fits.  Use the skip list for this.
         */
        if (!in_smallbin_range(nb)) {
            bin = bin_at(av, idx);
            /* skip scan if empty or largest chunk is too small */
            // 如果對應的 bin 爲空或者其中的chunk最大的也很小，那就跳過
            // first(bin)=bin->fd 表示當前鏈表中最大的chunk
            if ((victim = first(bin)) != bin &&
                (unsigned long) chunksize_nomask(victim) >=
                    (unsigned long) (nb)) {
                // 反向遍歷鏈表，直到找到第一個不小於所需chunk大小的chunk
                victim = victim->bk_nextsize;
                while (((unsigned long) (size = chunksize(victim)) <
                        (unsigned long) (nb)))
                    victim = victim->bk_nextsize;

                /* Avoid removing the first entry for a size so that the skip
                   list does not have to be rerouted.  */
                // 如果最終取到的chunk不是該bin中的最後一個chunk，並且該chunk與其前面的chunk
                // 的大小相同，那麼我們就取其前面的chunk，這樣可以避免調整bk_nextsize,fd_nextsize
                //  鏈表。因爲大小相同的chunk只有一個會被串在nextsize鏈上。
                if (victim != last(bin) &&
                    chunksize_nomask(victim) == chunksize_nomask(victim->fd))
                    victim = victim->fd;
                // 計算分配後剩餘的大小
                remainder_size = size - nb;
                // 進行unlink
                unlink(av, victim, bck, fwd);

                /* Exhaust */
                // 剩下的大小不足以當做一個塊
                // 很好奇接下來會怎麼辦？
                if (remainder_size < MINSIZE) {
                    set_inuse_bit_at_offset(victim, size);
                    if (av != &main_arena) set_non_main_arena(victim);
                }
                /* Split */
                //  剩下的大小還可以作爲一個chunk，進行分割。
                else {
                    // 獲取剩下那部分chunk的指針，稱爲remainder
                    remainder = chunk_at_offset(victim, nb);
                    /* We cannot assume the unsorted list is empty and therefore
                       have to perform a complete insert here.  */
                    // 插入unsorted bin中
                    bck = unsorted_chunks(av);
                    fwd = bck->fd;
                    // 判斷 unsorted bin 是否被破壞。
                    if (__glibc_unlikely(fwd->bk != bck)) {
                        errstr = "malloc(): corrupted unsorted chunks";
                        goto errout;
                    }
                    remainder->bk = bck;
                    remainder->fd = fwd;
                    bck->fd       = remainder;
                    fwd->bk       = remainder;
                    // 如果不處於small bin範圍內，就設置對應的字段
                    if (!in_smallbin_range(remainder_size)) {
                        remainder->fd_nextsize = NULL;
                        remainder->bk_nextsize = NULL;
                    }
                    // 設置分配的chunk的標記
                    set_head(victim,
                             nb | PREV_INUSE |
                                 (av != &main_arena ? NON_MAIN_ARENA : 0));

                    // 設置remainder的上一個chunk，即分配出去的chunk的使用狀態
                    // 其餘的不用管，直接從上面繼承下來了
                    set_head(remainder, remainder_size | PREV_INUSE);
                    // 設置remainder的大小
                    set_foot(remainder, remainder_size);
                }
                // 檢查
                check_malloced_chunk(av, victim, nb);
                // 轉換爲mem狀態
                void *p = chunk2mem(victim);
                // 如果設置了perturb_type, 則將獲取到的chunk初始化爲 perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
        }
```

#### 尋找較大 chunk

如果走到了這裏，那說明對於用戶所需的chunk，不能直接從其對應的合適的bin中獲取chunk，所以我們需要來查找比當前 bin 更大的 fast bin ， small bin 或者 large bin。

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
        // 獲取對應的bin
        bin   = bin_at(av, idx);
        // 獲取當前索引在binmap中的block索引
        // #define idx2block(i) ((i) >> BINMAPSHIFT)  ,BINMAPSHIFT=5
        // Binmap按block管理，每個block爲一個int，共32個bit，可以表示32個bin中是否有空閒chunk存在
        // 所以這裏是右移5
        block = idx2block(idx);
        // 獲取當前塊大小對應的映射，這裏可以得知相應的bin中是否有空閒塊
        map   = av->binmap[ block ];
        // #define idx2bit(i) ((1U << ((i) & ((1U << BINMAPSHIFT) - 1))))
        // 將idx對應的比特位設置爲1，其它位爲0
        bit   = idx2bit(idx);
        for (;;) {
```

##### 找到一個合適的 map

```c++
            /* Skip rest of block if there are no more set bits in this block.
             */
            // 如果bit>map，則表示該 map 中沒有比當前所需要chunk大的空閒塊
            // 如果bit爲0，那麼說明，上面idx2bit帶入的參數爲0。
            if (bit > map || bit == 0) {
                do {
                    // 尋找下一個block，直到其對應的map不爲0。
                    // 如果已經不存在的話，那就只能使用top chunk了
                    if (++block >= BINMAPSIZE) /* out of bins */
                        goto use_top;
                } while ((map = av->binmap[ block ]) == 0);
                // 獲取其對應的bin，因爲該map中的chunk大小都比所需的chunk大，而且
                // map本身不爲0，所以必然存在滿足需求的chunk。
                bin = bin_at(av, (block << BINMAPSHIFT));
                bit = 1;
            }
```

##### 找到合適的 bin

```c
            /* Advance to bin with set bit. There must be one. */
            // 從當前map的最小的bin一直找，直到找到合適的bin。
            // 這裏是一定存在的
            while ((bit & map) == 0) {
                bin = next_bin(bin);
                bit <<= 1;
                assert(bit != 0);
            }
```

##### 簡單檢查 chunk

```c
            /* Inspect the bin. It is likely to be non-empty */
            // 獲取對應的bin
            victim = last(bin);

            /*  If a false alarm (empty bin), clear the bit. */
            // 如果victim=bin，那麼我們就將map對應的位清0，然後獲取下一個bin
            // 這種情況發生的概率應該很小。
            if (victim == bin) {
                av->binmap[ block ] = map &= ~bit; /* Write through */
                bin                 = next_bin(bin);
                bit <<= 1;
            }
```

##### 真正取出 chunk

```c
            else {
                // 獲取對應victim的大小
                size = chunksize(victim);

                /*  We know the first chunk in this bin is big enough to use. */
                assert((unsigned long) (size) >= (unsigned long) (nb));
                // 計算分割後剩餘的大小
                remainder_size = size - nb;

                /* unlink */
                unlink(av, victim, bck, fwd);

                /* Exhaust */
                // 如果分割後不夠一個chunk怎麼辦？
                if (remainder_size < MINSIZE) {
                    set_inuse_bit_at_offset(victim, size);
                    if (av != &main_arena) set_non_main_arena(victim);
                }

                /* Split */
                // 如果夠，儘管分割
                else {
                    // 計算剩餘的chunk的偏移
                    remainder = chunk_at_offset(victim, nb);

                    /* We cannot assume the unsorted list is empty and therefore
                       have to perform a complete insert here.  */
                    // 將剩餘的chunk插入到unsorted bin中
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
                    // 如果在small bin範圍內，就將其標記爲remainder
                    if (in_smallbin_range(nb)) av->last_remainder = remainder;
                    if (!in_smallbin_range(remainder_size)) {
                        remainder->fd_nextsize = NULL;
                        remainder->bk_nextsize = NULL;
                    }
                    // 設置victim的使用狀態
                    set_head(victim,
                             nb | PREV_INUSE |
                                 (av != &main_arena ? NON_MAIN_ARENA : 0));
                    // 設置remainder的使用狀態，這裏是爲什麼呢？
                    set_head(remainder, remainder_size | PREV_INUSE);
                    // 設置remainder的大小
                    set_foot(remainder, remainder_size);
                }
                // 檢查
                check_malloced_chunk(av, victim, nb);
                // chunk狀態轉換到mem狀態
                void *p = chunk2mem(victim);
                // 如果設置了perturb_type, 則將獲取到的chunk初始化爲 perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
```

### 使用 top chunk

如果所有的 bin 中的 chunk 都沒有辦法直接滿足要求（即不合並），或者說都沒有空閒的 chunk。那麼我們就只能使用 top chunk 了。

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
        // 獲取當前的top chunk，並計算其對應的大小
        victim = av->top;
        size   = chunksize(victim);
        // 如果分割之後，top chunk 大小仍然滿足 chunk 的最小大小，那麼就可以直接進行分割。
        if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) {
            remainder_size = size - nb;
            remainder      = chunk_at_offset(victim, nb);
            av->top        = remainder;
            // 這裏設置 PREV_INUSE 是因爲 top chunk 前面的 chunk 如果不是 fastbin，就必然會和
            // top chunk 合併，所以這裏設置了 PREV_INUSE。
            set_head(victim, nb | PREV_INUSE |
                                 (av != &main_arena ? NON_MAIN_ARENA : 0));
            set_head(remainder, remainder_size | PREV_INUSE);

            check_malloced_chunk(av, victim, nb);
            void *p = chunk2mem(victim);
            alloc_perturb(p, bytes);
            return p;
        }
        // 否則，判斷是否有 fast chunk
        /* When we are using atomic ops to free fast chunks we can get
           here for all block sizes.  */
        else if (have_fastchunks(av)) {
            // 先執行一次fast bin的合併
            malloc_consolidate(av);
            /* restore original bin index */
            // 判斷需要的chunk是在small bin範圍內還是large bin範圍內
            // 並計算對應的索引
            // 等待下次再看看是否可以
            if (in_smallbin_range(nb))
                idx = smallbin_index(nb);
            else
                idx = largebin_index(nb);
        }

```

### 堆內存不夠

如果堆內存不夠，我們就需要使用 `sysmalloc` 來申請內存了。

```c
        /*
           Otherwise, relay to handle system-dependent cases
         */
        // 否則的話，我們就只能從系統中再次申請一點內存了。
        else {
            void *p = sysmalloc(nb, av);
            if (p != NULL) alloc_perturb(p, bytes);
            return p;
        }
```



## _libc_calloc

calloc 也是 libc 中的一種申請內存塊的函數。在 `libc`中的封裝爲 `_libc_calloc`，具體介紹如下

```c
/*
  calloc(size_t n_elements, size_t element_size);
  Returns a pointer to n_elements * element_size bytes, with all locations
  set to zero.
*/
void*  __libc_calloc(size_t, size_t);
```

## sysmalloc

正如該函數頭的註釋所言，該函數用於當前堆內存不足時，需要向系統申請更多的內存。

```c
/*
   sysmalloc handles malloc cases requiring more memory from the system.
   On entry, it is assumed that av->top does not have enough
   space to service request for nb bytes, thus requiring that av->top
   be extended or replaced.
 */
```

### 基本定義

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

我們可以主要關注一下 `pagesize`，其

```c
#ifndef EXEC_PAGESIZE
#define EXEC_PAGESIZE	4096
#endif
# define GLRO(name) _##name
size_t _dl_pagesize = EXEC_PAGESIZE;
```

所以，`pagesize=4096=0x1000`。

### 考慮 mmap

正如開頭註釋所言如果滿足如下任何一種條件

1. 沒有分配堆。
2. 申請的內存大於 `mp_.mmap_threshold`，並且mmap 的數量小於最大值，就可以嘗試使用 mmap。

默認情況下，臨界值爲

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

`DEFAULT_MMAP_THRESHOLD` 爲 128*1024 字節，即 128 K。

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

下面爲這部分代碼，目前不是我們關心的重點，可以暫時跳過。

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

### mmap 失敗或者未分配堆

```c
  /* There are no usable arenas and mmap also failed.  */
  if (av == NULL)
    return 0;
```

如果是這兩種情況中的任何一種，其實就可以退出了。。

### 記錄舊堆信息

```c
  /* Record incoming configuration of top */

  old_top = av->top;
  old_size = chunksize(old_top);
  old_end = (char *)(chunk_at_offset(old_top, old_size));

  brk = snd_brk = (char *)(MORECORE_FAILURE);
```

### 檢查舊堆信息1

```c
  /*
     If not the first time through, we require old_size to be
     at least MINSIZE and to have prev_inuse set.
   */

  assert((old_top == initial_top(av) && old_size == 0) ||
         ((unsigned long)(old_size) >= MINSIZE && prev_inuse(old_top) &&
          ((unsigned long)old_end & (pagesize - 1)) == 0));
```

這個檢查要求滿足其中任何一個條件

1. `old_top == initial_top(av) && old_size == 0`，即如果是第一次的話，堆的大小需要是 0。
2. 新的堆，那麼
    1. `(unsigned long)(old_size) >= MINSIZE && prev_inuse(old_top)`，堆的大小應該不小於 `MINSIZE`，並且前一個堆塊應該處於使用中。
    2. `((unsigned long)old_end & (pagesize - 1)) == 0)`，堆的結束地址應該是頁對齊的，由於頁對齊的大小默認是0x1000，所以低 12 個比特需要爲 0。

### 檢查舊堆信息2

```c
  /* Precondition: not enough current space to satisfy nb request */
  assert((unsigned long)(old_size) < (unsigned long)(nb + MINSIZE));
```

根據 malloc 中的定義

```c
static void *_int_malloc(mstate av, size_t bytes) {
    INTERNAL_SIZE_T nb;  /* normalized request size */
```

`nb` 應該是已經加上 chunk 頭部的字節，爲什麼還要加上 `MINSIZE `呢？這是因爲 top chunk 的大小應該至少預留 MINSIZE 空間，以便於合併。

### 非 main_arena

這裏暫時不是關心的重點，暫且不分析。

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

### Main_arena 處理

#### 計算內存

計算可以滿足請求的內存大小。

```c
else { /* av == main_arena */

    /* Request enough space for nb + pad + overhead */
    size = nb + mp_.top_pad + MINSIZE;
```

默認情況下 `top_pad`定義爲

```c
#ifndef DEFAULT_TOP_PAD
# define DEFAULT_TOP_PAD 131072
#endif
```

即 131072 字節，0x20000 字節。

#### 是否連續

如果我們希望堆的空間連續的話，那麼其實可以複用之前的內存。

```c
    /*
       If contiguous, we can subtract out existing space that we hope to
       combine with new space. We add it back later only if
       we don't actually get contiguous space.
     */

    if (contiguous(av))
      size -= old_size;
```

#### 對齊頁大小

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

#### 申請內存

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

這裏竟然調用了一個 hook，有點意思。

##### 失敗

失敗，考慮 mmap。

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

#### 內存可能申請成功

```c
    if (brk != (char *)(MORECORE_FAILURE)) {
      if (mp_.sbrk_base == 0)
        mp_.sbrk_base = brk;
      av->system_mem += size;
```

##### 情況 1

```c
      /*
         If MORECORE extends previous space, we can likewise extend top size.
       */

      if (brk == old_end && snd_brk == (char *)(MORECORE_FAILURE))
        set_head(old_top, (size + old_size) | PREV_INUSE);
```

##### 情況 2 - 意外內存耗盡

```c
      else if (contiguous(av) && old_size && brk < old_end)
        /* Oops!  Someone else killed our space..  Can't touch anything.  */
        malloc_printerr("break adjusted to free malloc space");
```

##### 處理其他意外情況

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

###### 處理連續內存

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

###### 處理不連續內存

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

###### 調整

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

需要注意的是，在這裏程序將舊的 top chunk 進行了釋放，那麼其會根據大小進入不同的 bin 或 tcache 中。

#### 更新最大內存

```c
  if ((unsigned long)av->system_mem > (unsigned long)(av->max_system_mem))
    av->max_system_mem = av->system_mem;
  check_malloc_state(av);
```

#### 分配內存塊

##### 獲取大小

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

#### 捕捉所有錯誤

```c
  /* catch all failure paths */
  __set_errno(ENOMEM);
  return 0;
```

