[EN](./malloc.md) | [ZH](./malloc-zh.md)
# Apply for a memory block


## __libc_malloc



In general, we will use the malloc function to apply for a block of memory, but when we look closely at the source implementation of glibc, there is actually no malloc function. In fact, the function actually calls the \_\_libc_malloc function. Why not just write a malloc function directly, because sometimes we may need different names. In addition, the __libc_malloc function is simply used to simply wrap the _int_malloc function. \_int_malloc is the core of the application memory block. Let's take a closer look at the specific implementation.


This function first checks if there is a hook function (__malloc_hook) for the memory allocation function. This is mainly used for user-defined heap allocation functions, which is convenient for users to quickly modify and evaluate the allocation function. It should be noted here that the ** user-applied byte becomes an unsigned integer** once it enters the application memory function.


```c++

// wapper for int_malloc

void *__libc_malloc(size_t bytes) {
    mstate ar_ptr;
    void * victim;

    // Check if there is a memory allocation hook, if so, call the hook and return.
    void *(*hook)(size_t, const void *) = atomic_forced_read(__malloc_hook);

    if (__builtin_expect(hook != NULL, 0))
        return (*hook)(bytes, RETURN_ADDRESS(0));



```



Then I will look for an arena to try to allocate memory.


```c++

    arena_get(ar_ptr, bytes);

```



Then call the _int_malloc function to request the corresponding memory.


```c++

    victim = _int_malloc(ar_ptr, bytes);

```



If the allocation fails, ptmalloc will try to find another available arena and allocate memory.


```c++

    /* Retry with another arena only if we were able to find a usable arena
       before.  */
    if (!victim && ar_ptr != NULL) {
        LIBC_PROBE(memory_malloc_retry, 1, bytes);
        ar_ptr = arena_get_retry(ar_ptr, bytes);
        victim = _int_malloc(ar_ptr, bytes);
    }
```



If you apply for arena, you have to unlock it before you quit.


```c++
    if (ar_ptr != NULL) __libc_lock_unlock(ar_ptr->mutex);

```



Determine if the current status meets the following conditions


- Either didn't apply to memory
- either mmap memory
- **Either the requested memory must be in its assigned arena**


```c++
    assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
           ar_ptr == arena_for_chunk(mem2chunk(victim)));

```



Finally return to memory.


```c++
    return victim;
}
```



## _int_malloc



_int_malloc is the core function of memory allocation, and its core ideas are as follows


1. It implements different allocation methods in turn according to the **memory block size** and **frequency of use** of fastbin chunk, small chunk, large chunk of the user's application.
2. It checks from small to large whether there are corresponding free blocks in different bins to satisfy the memory requested by the user.
3. When all free chunks are not met, it considers the top chunk.
4. The heap allocator will only request the memory block when the top chunk is not satisfied.


After entering the function, the function immediately defines a series of variables that you need, and converts the memory size requested by the user to the internal chunk size.


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
        void * p = sysmalloc(nb, av);
        if (p != NULL) alloc_perturb(p, bytes);
        return p;
    }
```



### fast bin

If the size of the requested chunk is in the fastbin range, ** note that the comparison here is an unsigned integer**. ** In addition, chunk** is taken from the head node of fastbin.


```c++
    /*
       If the size qualifies as a fastbin, first check corresponding bin.
       This code is safe to execute even if av is not yet initialized, so we
       can try it without checking, which saves some time on this fast path.
     */
    if ((unsigned long) (nb) <= (unsigned long) (get_max_fast())) {
        // Get the corresponding subscript of fastbin
        idx             = fastbin_index(nb);
        // Get the corresponding pointer to the fastbin
        mfastbinptr * fb = &fastbin(av, idx);
        mchunkptr    pp = *fb;
        // Use fd to traverse the corresponding bin whether there are free chunks,
        do {
            victim = pp;
            if (victim == NULL) break;
        } while ((pp = catomic_compare_and_exchange_val_acq(fb, victim->fd,
                                                            victim)) != victim);
        // There are chunks that can be used
        if (victim != 0) {
            // Check if the chunk size retrieved is consistent with the corresponding fastbin index.
            // Calculate its size using chunksize based on the obtained victim.
            // Calculate the index of the chunk using fastbin_index.
            if (__builtin_expect(fastbin_index(chunksize(victim)) != idx, 0)) {
                errstr = "malloc(): memory corruption (fast)";

            errout:
                malloc_printerr(check_action, errstr, chunk2mem(victim), av);
                return NULL;
            }
            // Careful inspection. . Useful only when DEBUG
            check_remalloced_chunk(av, victim, nb);
            // Convert the obtained chunk to mem mode
            void *p = chunk2mem(victim);
            // If perturb_type is set, the obtained chunk is initialized to perturb_type ^ 0xff
            alloc_perturb(p, bytes);
            return p;
        }
    }
```



### small bin



If the range of the obtained memory block is in the range of the small bin, then the following process is performed.


```c++
    /*
       If a small request, check regular bin.  Since these "smallbins"
       hold one size each, no searching within bins is necessary.
       (For a large request, we need to wait until unsorted chunks are
       processed to find best fit. But for small ones, fits are exact
       anyway, so we can check now, which is faster.)
     */

    if (in_smallbin_range(nb)) {
        // Get the index of the small bin
        idx = smallbin_index(nb);
        // Get the corresponding chunk pointer in the small bin
        bin = bin_at(av, idx);
        // first execute victim = last(bin) to get the last chunk of the small bin
        // If victim = bin , then the bin is empty.
        // If they are not equal, then there will be two cases
        if ((victim = last(bin)) != bin) {
            // In the first case, the small bin has not yet been initialized.
            if (victim == 0) /* initialization check */
                // Perform initialization to merge chunks in fast bins
                malloc_consolidate(av);
            // In the second case, there is a free chunk in the small bin
            else {
                // Get the second-to-last chunk in the small bin.
                bck = victim->bk;
                // Check if bck->fd is victim, prevent forgery
                if (__glibc_unlikely(bck->fd != victim)) {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                // Set the corresponding inuse bit of victim
                set_inuse_bit_at_offset(victim, nb);
                // Modify the small bin list, take the last chunk of the small bin
                bin->bk = bck;
                bck->fd = bin;
                // If it is not main_arena, set the corresponding flag
                if (av != &main_arena) set_non_main_arena(victim);
                // Detailed inspection, non-debug status has no effect
                check_malloced_chunk(av, victim, nb);
                // Convert the requested chunk to the corresponding mem state
                void *p = chunk2mem(victim);
                // If perturb_type is set, the obtained chunk is initialized to perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
        }
    }
```



### large bin



When the chunks in the fast bin and small bin cannot satisfy the user request chunk hour, it will consider whether it is a large bin. However, in the large bin, there is no direct scan of the chunk in the corresponding bin. Instead, the malloc_consolidate(see malloc_state related function) function is used to process the chunk in the fast bin, and the chunks that may be merged are merged and then placed. In the unsorted bin, if you can't merge, put it directly into the unsorted bin, and then process it in the big loop below. ** Why not just take the large chunk directly from the corresponding bin? This is the mechanism of ptmalloc, which merges fragment chunks in the heap before allocating large chunks to reduce fragmentation in the heap. **


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
        // Get the subscript of the large bin.
        idx = largebin_index(nb);
        // If there is fastbin, it will handle fastbin
      if (have_fastchunks(av)) malloc_consolidate(av);
    }
```



### Big loop - traversing unsorted bin


**If the program is executed here, it means that there is no chunk in the bin (fast bin, small bin) that is exactly the same as the chunk size, which can directly satisfy the demand, but the large chunk is processed in this big loop.


In the next cycle, the main operations are as follows

- Take the chunks in the unsorted bin one by one in the FIFO mode
- If it is a small request, consider whether it is just satisfied, if it is, return directly.
- If not, put it in the corresponding bin.
- Try to allocate the memory required by the user from the large bin


This part is a big loop, this is to try to redistribute the small bin chunk, because we will first use the large bin, top chunk to try to satisfy the user's request, but if it is not satisfied, because we did not assign it successfully Small bin, we didn't merge the chunks in the fast bin, so we'll merge the fast bin chunks and use a big loop to try to allocate the small bin chunk again.


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



#### unsorted bin Traversing


Consider the unsorted bin first, then consider the last remainder, but there are exceptions to the request for the small bin chunk.


** Note that the traversal order of unsorted bin is bk. **


```c++
        // If the unsorted bin is not empty
        // First In First Out
        while ((victim = unsorted_chunks(av)->bk)! = unsorted_chunks(av)) {
            // victim is the last chunk of unsorted bin
            // bck is the penultimate chunk of unsorted bin
            bck = victim->bk;

            // Determine whether the obtained chunk meets the requirements, can not be too small, can not be too large
            // The size of the general system_mem is 132K
            if (__builtin_expect(chunksize_nomask(victim) <= 2 * SIZE_SZ, 0) ||
                __builtin_expect(chunksize_nomask(victim) > av->system_mem, 0))
                malloc_printerr(check_action, "malloc(): memory corruption",
                                chunk2mem(victim), av);
            // Get the chunk size corresponding to the victim.
            size = chunksize(victim);
```



##### small request



If the user's request is a small bin chunk, then we first consider the last remainder. If the last remainder is the only one in the unsorted bin, and the size of the last remainder is enough to be a chunk, why is there no equal sign**?


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
                // Get the size of the new retriever
                remainder_size          = size - nb;
                // Get the location of the new retriever
                remainder               = chunk_at_offset(victim, nb);
                // update the unsorted bin
                unsorted_chunks(av)->bk = unsorted_chunks(av)->fd = remainder;
                // update the last_remainder recorded in av
                av->last_remainder = remainder;
                // Update the pointer of the last remainder
                remainder->bk = remainder->fd = unsorted_chunks(av);
                if (!in_smallbin_range(remainder_size)) {
                    remainder->fd_nextsize = NULL;
                    remainder->bk_nextsize = NULL;
                }
                // Set the victim's head,
                set_head(victim, nb | PREV_INUSE |
                                    (av! = &main_arena? NON_MAIN_ARENA: 0));
                // Set the head of the remainder
                set_head(remainder, remainder_size | PREV_INUSE);
                // Set the prev_size field of the record remainder size because the retriever is idle at this time.
                set_foot(remainder, remainder_size);
                // Detailed inspection, no effect in non-debug mode
                check_malloced_chunk(av, victim, nb);
                // Convert victim from chunk mode to mem mode
                void *p = chunk2mem(victim);
                // If perturb_type is set, the obtained chunk is initialized to perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
```



##### Initial take out


```c
            /* remove from unsorted list */
            unsorted_chunks(av)->bk = bck;
            bck->fd = unsorted_chunks(av);
```



##### exact fit



If the chunk size taken from the unsorted bin is just right, use it directly. Here we should have allocated the appropriate chunks after the merger.


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



Put the extracted chunk into the corresponding small bin.


```c
            /* place chunk in bin */
            if (in_smallbin_range(size)) {
                victim_index = smallbin_index(size);
                bck = bin_at(av, victim_index);
                fwd          = bck->fd;
```



##### place chunk in large bin



Put the fetched chunks into the corresponding large bin.


```c
            } else {
                // large bin range
                victim_index = largebin_index(size);
                bck = bin_at(av, victim_index); // the head of the current large bin
                fwd          = bck->fd;

                /* maintain large bins in sorted order */
                /* From here we can conclude that largebin is sorted in descending order by fd_nextsize.
                The same size chunk, later will only be inserted into the same size chunk before.
                It is easy to understand without modifying the same size fd/bk_nextsize.
                Can reduce overhead. In addition, the bin header does not participate in the nextsize link. */
                // If the large bin list is not empty
                if (fwd != bck) {
                    /* Or with inuse bit to speed comparisons */
                    // Accelerate comparisons, not only should this be considered, because the chunks in the list will set this bit.
                    size |= PREV_INUSE;
                    /* if smaller than smallest, bypass loop below */
                    // bck->bk stores the smallest chunk in the corresponding large bin.
                    // If the traversed chunk is smaller than the current minimum, then it only needs to be inserted at the end of the list.
                    // Determine if bck->bk is in main arena.
                    assert(chunk_main_arena(bck->bk));
                    if ((unsigned long) (size) <
                        (unsigned long) chunksize_nomask(bck->bk)) {
                        // Let fwd point to the big bin header
                        fwd = bck;
                        // Let bck point to the largin bin tail chunk
                        bck = bck->bk;
                        // victim's fd_nextsize points to the first chunk of largin bin
                        victim->fd_nextsize = fwd->fd;
                        // victim's bk_nextsize points to the bk_nextsize pointed to by the first chunk of the original list.
                        victim->bk_nextsize = fwd->fd->bk_nextsize;
                        // The bk_nextsize of the first chunk of the original list points to the victim
                        // The original fd_nextsize pointing to the first chunk of the list points to victim
                        fwd->fd->bk_nextsize =
                            victim->bk_nextsize->fd_nextsize = victim;
                    } else {
                        // The size of the victim currently being inserted is larger than the smallest chunk
                        // Determine if fwd is in main arena
                        assert(chunk_main_arena(fwd));
                        // Start from the head of the list to find a chunk that is no bigger than the victim.
                        while ((unsigned long) size < chunksize_nomask(fwd)) {
                            fwd = fwd->fd_nextsize;
                            assert(chunk_main_arena(fwd));
                        }
                        // If you find a chunk that is as big as the victim,
                        // Then insert the chunk directly after the chunk and don't modify the nextsize pointer.
                        if ((unsigned long) size ==
                            (unsigned long) chunksize_nomask(fwd))
                            /* Always insert in the second position.  */
                            fwd = fwd->fd;
                        else {
                            // If the chunk found is not the same size as the current victim
                            // Then you need to construct a nextsize doubly linked list.
                            victim->fd_nextsize              = fwd;
                            victim->bk_nextsize              = fwd->bk_nextsize;
                            fwd->bk_nextsize                 = victim;
                            victim->bk_nextsize->fd_nextsize = victim;
                        }
                        bck = fwd->bk;
                    }
                } else
                    // If it is empty, simply make fd_nextsize and bk_nextsize form a doubly linked list.
                    victim->fd_nextsize = victim->bk_nextsize = victim;

            }
```



##### Final take out


```c
            // Put it in the corresponding bin to form bck<-->victim<-->fwd.
            mark_bin(av, victim_index);
            victim->bk = bck;
            victim->fd = fwd;
            fwd->bk    = victim;
            bck->fd    = victim;
```



##### while Iterations


While exits up to 10,000 iterations and exits.


```c
            // # define MAX_ITERS 10000
            if (++iters >= MAX_ITERS) break;
                    }
```



#### large chunk



**Note: It may be very strange, why not go to see if the small chunk meets the new requirements first? This is because the small bin has already been judged before the loop. If there is one, the chunk will appear after the merge. But outside the big loop, the large chunk simply finds its index, so it feels reasonable to judge directly here, and also to find larger chunks for the following. **


If the requested chunk is in the large chunk range, it is scanned from small to large in the corresponding bin to find the first one.


```c++
        /*
           If a large request, scan through the chunks of current bin in
           sorted order to find smallest that fits.  Use the skip list for this.
         */

        if (!in_smallbin_range(nb)) {
            bin = bin_at(av, idx);
            /* skip scan if empty or largest chunk is too small */
            // If the corresponding bin is empty or the chunks in it are the smallest, skip it
            // first(bin)=bin->fd means the largest chunk in the current list.
            if ((victim = first(bin)) != bin &&
                (unsigned long) chunksize_nomask(victim) >=
                    (unsigned long) (nb)) {
                // Reverse traversing the list until the first chunk is found that is not less than the desired chunk size
                victim = victim->bk_nextsize;
                while (((unsigned long) (size = chunksize(victim)) <
                        (unsigned long) (nb)))
                    victim = victim->bk_nextsize;

                /* Avoid removing the first entry for a size so that the skip
                   list does not have to be rerouted.  */
                // If the final chunk is not the last chunk in the bin, and the chunk is in front of the chunk
                // The size is the same, then we take the chunk in front of it, so we can avoid adjusting bk_nextsize, fd_nextsize
                // linked list. Because only one chunk of the same size will be chained to the nextsize chain.
                if (victim != last(bin) &&
                    chunksize_nomask(victim) == chunksize_nomask(victim->fd))
                    victim = victim->fd;
                // Calculate the remaining size after the allocation
                remainder_size = size - nb;
                // unlink
                unlink(av, victim, bck, fwd);
                /* Exhaust */
                // The remaining size is not enough to be a block
                // Very curious what will happen next?
                if (remainder_size < MINSIZE) {
                    set_inuse_bit_at_offset(victim, size);
                    if (av != &main_arena) set_non_main_arena(victim);
                }
                /* Split */
                // The remaining size can also be split as a chunk.
                else {
                    // Get the pointer to the remaining chunk, called the reducer
                    remainder = chunk_at_offset(victim, nb);
                    /* We cannot assume the unsorted list is empty and therefore
                       have to perform a complete insert here.  */
                    // Insert in unsorted bin
                    bck = unsorted_chunks(av);
                    fwd = bck->fd;

                    // Determine if the unsorted bin is destroyed.
                    if (__glibc_unlikely(fwd->bk != bck)) {
                        errstr = "malloc(): corrupted unsorted chunks";
                        goto errout;
                    }
                    remainder->bk = bck;
                    remainder->fd = fwd;
                    bck->fd       = remainder;
                    fwd->bk       = remainder;
                    // If it is not in the range of small bin, set the corresponding field
                    if (!in_smallbin_range(remainder_size)) {
                        remainder->fd_nextsize = NULL;
                        remainder->bk_nextsize = NULL;
                    }

                    // Set the flag of the assigned chunk
                    set_head(victim,
                             nb | PREV_INUSE |
                                (av! = &main_arena? NON_MAIN_ARENA: 0));
                    // Set the last chunk of the remainder, that is, the usage status of the allocated chunk
                    // The rest of the rules are inherited directly from above.
                    set_head(remainder, remainder_size | PREV_INUSE);
                    // Set the size of the remainder
                    set_foot(remainder, remainder_size);
                }
                // an examination
                check_malloced_chunk(av, victim, nb);
                // Convert to mem state
                void *p = chunk2mem(victim);
                // If perturb_type is set, the obtained chunk is initialized to perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
        }
```



#### Looking for a larger chunk


If you get here, it means that for the chunks that the user needs, you can't get the chunk directly from the corresponding bin, so we need to find the faster bin, small bin or large bin larger than the current bin.


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
        // Get the corresponding bin
        bin = bin_at(av, idx);
        // Get the current index in the binmap block index
        // #define idx2block(i) ((i) >> BINMAPSHIFT)  ,BINMAPSHIFT=5
        // Binmap is managed by block. Each block is an int with a total of 32 bits. It can indicate whether there are free chunks in 32 bins.
        // So here is the right shift 5
        block = idx2block(idx);
        // Get the mapping corresponding to the current block size, here you can know whether there is a free block in the corresponding bin
        map = av->binmap [block];
        // #define idx2bit(i) ((1U << ((i) & ((1U << BINMAPSHIFT) - 1))))
        // Set the bit corresponding to idx to 1, and the other bits to 0.
        bit   = idx2bit(idx);
        for (;;) {
```



##### Find a suitable map


```c++
            /* Skip rest of block if there are no more set bits in this block.
             */

            // If bit>map, it means that there is no free block in the map that is larger than the current required chunk.
            // If the bit is 0, then the parameter brought by idx2bit above is 0.
            if (bit > map || bit == 0) {
                do {
                    // Find the next block until its corresponding map is not 0.
                    // If it doesn't exist, you can only use the top chunk.
                    if (++block >= BINMAPSIZE) /* out of bins */
                        goto use_top;
                } while ((map = av->binmap[ block ]) == 0);
                // Get its corresponding bin, because the chunk size in the map is larger than the required chunk, and
                // map itself is not 0, so there must be a chunk that meets the requirements.
                bin = bin_at(av, (block << BINMAPSHIFT));
                bit = 1;
            }
```



##### Find the right bin


```c
            /* Advance to bin with set bit. There must be one. */

            // Find from the smallest bin of the current map until you find the appropriate bin.
            // This is definitely there.
            while ((bit & map) == 0) {
                bin = next_bin(bin);
                bit <<= 1;
                assert(bit != 0);
            }
```



##### Simple check chunk


```c
            /* Inspect the bin. It is likely to be non-empty */

            // Get the corresponding bin
            victim = last(bin);

            /*  If a false alarm(empty bin), clear the bit. */
            // If victim=bin, then we clear the bit corresponding to the map to 0 and then get the next bin.
            // The probability of this happening should be small.
            if (victim == bin) {
                av->binmap[ block ] = map &= ~bit; /* Write through */
                bin                 = next_bin(bin);
                bit <<= 1;
            }
```



##### Really take out chunk


```c
            else {
                // Get the size of the corresponding victim
                size = chunksize(victim);

                /*  We know the first chunk in this bin is big enough to use. */
                assert((unsigned long) (size) >= (unsigned long) (nb));
                // Calculate the remaining size after splitting
                remainder_size = size - nb;

                /* unlink */
                unlink(av, victim, bck, fwd);

                /* Exhaust */
                // What if there is not enough chunk after splitting?
                if (remainder_size < MINSIZE) {
                    set_inuse_bit_at_offset(victim, size);
                    if (av != &main_arena) set_non_main_arena(victim);
                }

                /* Split */
                // If enough, despite the segmentation
                else {
                    // Calculate the offset of the remaining chunk
                    remainder = chunk_at_offset(victim, nb);

                    /* We cannot assume the unsorted list is empty and therefore
                       have to perform a complete insert here.  */

                    // Insert the remaining chunks into the unsorted bin
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
                    // If it is in the range of small bin, mark it as a remainder
                    if (in_smallbin_range(nb)) av->last_remainder = remainder;
                    if (!in_smallbin_range(remainder_size)) {
                        remainder->fd_nextsize = NULL;
                        remainder->bk_nextsize = NULL;
                    }
                    // Set the use status of the victim
                    set_head(victim,
                             nb | PREV_INUSE |
                                (av! = &main_arena? NON_MAIN_ARENA: 0));
                    // Set the usage status of the remainder. Why is this?
                    set_head(remainder, remainder_size | PREV_INUSE);
                    // Set the size of the remainder
                    set_foot(remainder, remainder_size);
                }
                // an examination
                check_malloced_chunk(av, victim, nb);
                // The chunk state is converted to the mem state.
                void *p = chunk2mem(victim);
                // If perturb_type is set, the obtained chunk is initialized to perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
```



### Using top chunk


If all the chunks in the bin have no way to directly meet the requirements (that is, not merged), or there are no free chunks. Then we can only use the top chunk.


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

        // Get the current top chunk and calculate its corresponding size
        victim = av->top;
        size   = chunksize(victim);
        // If the top chunk size still satisfies the minimum size of chunk after splitting, then you can split directly.
        if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) {
            remainder_size = size - nb;
            remainder      = chunk_at_offset(victim, nb);
            av->top = remainder;
            // Here, set PREV_INUSE because if the previous chunk of the top chunk is bound to be fastbin,
            // The top chunk will merged, so PREV_INUSE is set here.
            set_head(victim, nb | PREV_INUSE |
                                (av! = &main_arena? NON_MAIN_ARENA: 0));
            set_head(remainder, remainder_size | PREV_INUSE);
            check_malloced_chunk(av, victim, nb);
            void *p = chunk2mem(victim);
            alloc_perturb(p, bytes);
            return p;
        }
        // Otherwise, determine if there is a fast chunk
        /* When we are using atomic ops to free fast chunks we can get
           here for all block sizes.  */
        else if (have_fastchunks(av)) {
            // Perform a fast bin merge first
            malloc_consolidate(av);
            /* restore original bin index */
            // Determine whether the required chunk is in the range of small bin or large bin
            // and calculate the corresponding index
            // Wait for the next time to see if you can
            if (in_smallbin_range(nb))
                idx = smallbin_index(nb);
            else
                idx = largebin_index(nb);
        }
```



### Heap memory is not enough


If the heap memory is not enough, we need to use `sysmalloc` to apply for memory.


```c
        /*
           Otherwise, relay to handle system-dependent cases
         */

        // Otherwise, we can only apply for a bit of memory from the system again.
        else {
            void * p = sysmalloc(nb, av);
            if (p != NULL) alloc_perturb(p, bytes);
            return p;
        }
```







## _libc_calloc



Calloc is also a function in libc that requests memory blocks. The package in `libc` is `_libc_calloc`, which is described below.


```c
/*
  calloc(size_t n_elements, size_t element_size);
  Returns a pointer to n_elements * element_size bytes, with all locations
  set to zero.
*/
void*  __libc_calloc(size_t, size_t);

```



## sysmalloc



As the comment in the function header says, this function is used to request more memory from the system when the current heap is out of memory.


```c
/*
   sysmalloc handles malloc cases requiring more memory from the system.
   On entry, it is assumed that av->top does not have enough
   space to service request for nb bytes, thus requiring that av->top
   be extended or replaced.
 */
```



### Basic definition


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

We can mainly focus on `pagesize`, which

```c
#ifndef EXEC_PAGESIZE
#define EXEC_PAGESIZE	4096
#endif
# define GLRO(name) _##name
size_t _dl_pagesize = EXEC_PAGESIZE;
```

So, `pagesize=4096=0x1000`.


### Consider mmap


As stated in the opening comment, if any of the following conditions are met


1. There is no heap allocated.
2. If the requested memory is larger than `mp_.mmap_threshold` and the number of mmap is less than the maximum value, you can try to use mmap.


By default, the threshold is


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

`DEFAULT_MMAP_THRESHOLD` is 128*1024 bytes, or 128 K.

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



The following is part of the code, which is not the focus of our concern at present, and can be skipped temporarily.


```c
  /*
     If have mmap, and the request size meets the mmap threshold, and
     the system supports mmap, and there are few enough currently
     allocated mmapped regions, try to directly map this request
     rather than expanding top.
   */

if (av == NULL ||
      ((unsigned long)(nb) >= (unsigned long)(mp_.mmap_threshold) &&
      (mp_.n_mmaps <mp_.n_mmaps_max)) {
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



### mmap failed or unallocated heap


```c
  /* There are no usable arenas and mmap also failed.  */
  if (av == NULL)
    return 0;
```



If it is any of these two situations, you can actually quit. .


### Recording old heap information


```c
  /* Record incoming configuration of top */
  old_top = av->top;
  old_size = chunksize(old_top);
  old_end = (char *)(chunk_at_offset(old_top, old_size));

  brk = snd_brk = (char *)(MORECORE_FAILURE);
```



### Check old heap information 1


```c
  /*
     If not the first time through, we require old_size to be
     at least MINSIZE and to have prev_inuse set.
   */

  assert((old_top == initial_top(av) && old_size == 0) ||
         ((unsigned long)(old_size) >= MINSIZE && prev_inuse(old_top) &&
          ((unsigned long)old_end & (pagesize - 1)) == 0));
```



This check requires that any one of the conditions be met


1. `old_top == initial_top(av) && old_size == 0`, ie if it is the first time, the heap size needs to be 0.
2. The new heap, then
1. `(unsigned long)(old_size) >= MINSIZE && prev_inuse(old_top)`, the heap size should be no smaller than `MINSIZE`, and the previous heap block should be in use.
2. `((unsigned long)old_end &(pagesize - 1)) == 0)`, the end address of the heap should be page-aligned. Since the page alignment size defaults to 0x1000, the lower 12 bits need to be 0.


### Check old heap information 2


```c
  /* Precondition: not enough current space to satisfy nb request */
  assert((unsigned long)(old_size) < (unsigned long)(nb + MINSIZE));
```



According to the definition in malloc


```c
static void *_int_malloc(mstate av, size_t bytes) {
    INTERNAL_SIZE_T nb;  /* normalized request size */
```



`nb` should be the byte that has been added to the chunk header. Why add `MINSIZE `? This is because the size of the top chunk should at least reserve the MINSIZE space for easy merging.


### Non main_arena


This is not the focus of care for the time being, and it will not be analyzed for the time being.


```c
  if (av! = &main_arena) {
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
      av->system_mem + = heap->size;
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



### Main_arena Processing


#### Calculating memory


The calculation can satisfy the requested memory size.


```c
else {/ * by == main_arena * /

    /* Request enough space for nb + pad + overhead */
    size = nb + mp_.top_pad + MINSIZE;
```



By default `top_pad` is defined as


```c
#ifndef DEFAULT_TOP_PAD
# define DEFAULT_TOP_PAD 131072
#endif
```



That is, 131072 bytes, 0x20000 bytes.


#### Whether it is continuous


If we want the heap space to be continuous, then we can actually reuse the previous memory.


```c
    /*
       If contiguous, we can subtract out existing space that we hope to
       combine with new space. We add it back later only if
       we don't actually get contiguous space.
     */

    if (contiguous(av))
      size -= old_size;
```


#### Align page size


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



#### Applying for memory


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



##### May succeed


```c
    if (brk != (char *)(MORECORE_FAILURE)) {
      /* Call the `morecore' hook if necessary.  */
      void (*hook)(void) = atomic_forced_read(__after_morecore_hook);
      if (__builtin_expect(hook != NULL, 0))
        (*hook)();
    }
```



It is a bit of a meaning to call a hook here.


##### Failed


Failure, consider mmap.


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



#### Memory may be applied successfully


```c
    if (brk != (char *)(MORECORE_FAILURE)) {
      if (mp_.sbrk_base == 0)
        mp_srk_base = brk;
        av->system_mem + = size;
```



##### Situation 1


```c
      /*
         If MORECORE extends previous space, we can likewise extend top size.
       */

      if (brk == old_end && snd_brk == (char *)(MORECORE_FAILURE))
        set_head(old_top, (size + old_size) | PREV_INUSE);
```



##### Case 2 - Unexpected memory exhaustion


```c
      else if (contiguous(av) && old_size && brk < old_end)
        /* Oops!  Someone else killed our space..  Can't touch anything.  */
        malloc_printerr("break adjusted to free malloc space");
```



##### Handling other unexpected situations


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



###### Processing contiguous memory


```c
        /* handle contiguous cases */
        if (contiguous(av)) {
          /* Count foreign sbrk as system_mem.  */
          if (old_size)
            av->system_mem + = brk - old_end;

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
            snd_brk = (char *) (MORECORE(0));
          } else {
            /* Call the `morecore' hook if necessary.  */
            void (*hook)(void) = atomic_forced_read(__after_morecore_hook);
            if (__builtin_expect(hook != NULL, 0))
              (*hook)();
          }
        }
```



###### Handling discontinuous memory


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
            snd_brk = (char *) (MORECORE(0));
          }
        }
```



###### Adjustment


```c
        /* Adjust top based on results of second sbrk */
        if (snd_brk != (char *)(MORECORE_FAILURE)) {
          av->top = (mchunkptr) aligned_brk;
          set_head(av->top, (snd_brk - aligned_brk + correction) | PREV_INUSE);
          av->system_mem + = correction;

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



It should be noted that here the program releases the old top chunk, and it will enter different bins or tcaches depending on the size.


#### Update maximum memory


```c
  if ((unsigned long) av->system_mem > (unsigned long) (av->max_system_mem))
    av->max_system_mem = av->system_mem;
  check_malloc_state(av);
```



#### Allocating memory blocks


##### Get the size


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



#### Capture all errors


```c
  /* catch all failure paths */
  __set_errno(ENOMEM);
  return 0;
```