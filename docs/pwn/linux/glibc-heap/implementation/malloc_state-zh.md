[EN](./malloc_state.md) | [ZH](./malloc_state-zh.md)
# malloc_state 相关函数

## malloc_init_state

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



## malloc_consolidate

该函数主要有两个功能

1. 若 fastbin 未初始化，即 global_max_fast 为0，那就初始化 malloc_state。
2. 如果已经初始化的话，就合并 fastbin 中的 chunk。

基本的流程如下

### 初始

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

### 合并 chunk

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

### 初始化

说明 fastbin 还没有初始化。

```c
    } else {
        malloc_init_state(av);
        // 在非调试情况下没有什么用，在调试情况下，做一些检测。
        check_malloc_state(av);
    }
```