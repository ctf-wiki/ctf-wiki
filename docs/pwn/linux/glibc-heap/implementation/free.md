[EN](./free.md) | [ZH](./free-zh.md)
#release memory block


## __libc_free



Similar to malloc, the free function also has a wrapper, and the naming format is basically similar to malloc. code show as below


```c++

void __libc_free(void *mem) {

mstate ar_ptr;
    mchunkptr p; /* chunk corresponding to mem */

/ / Determine whether there is a hook function __free_hook
    void (*hook)(void *, const void *) = atomic_forced_read(__free_hook);

    if (__builtin_expect(hook != NULL, 0)) {

        (*hook)(mem, RETURN_ADDRESS(0));

        return;

    }

// free NULL has no effect
    if (mem == 0) /* free(0) has no effect */

        return;

/ / Convert mem to chunk state
    p = mem2chunk(mem);

// If the block memory is obtained by mmap
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

// Get a pointer to the allocation area according to the chunk
    ar_ptr = arena_for_chunk(p);

// execute release
    _int_free(ar_ptr, p, 0);

}

```



## _int_free



The initial time of the function defines a series of variables and gets the size of the chunk the user wants to release.


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



### Simple check


```c++

    /* Little security check which won't hurt performance: the

       allocator never wrapps around at the end of the address space.

       Therefore we can exclude some size values which might appear

       here by accident or by "design" from some intruder.  */

// The pointer cannot point to an illegal address, it must be less than or equal to -size, why? ? ?
// The pointer must be aligned, 2*SIZE_SZ This alignment is carefully thought about
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

// The size is not the smallest chunk, or the size is not an integer multiple of MALLOC_ALIGNMENT
    if (__glibc_unlikely(size < MINSIZE || !aligned_OK(size))) {

        errstr = "free(): invalid size";

        goto errout;

    }

/ / Check if the chunk is in use, no effect in the non-debug state
    check_inuse_chunk(av, p);

```



among them


```c

/* Check if m has acceptable alignment */



#define aligned_OK(m) (((unsigned long) (m) &MALLOC_ALIGN_MASK) == 0)



#define misaligned_chunk(p)                                                    \

    ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem(p)) &       \

     MALLOC_ALIGN_MASK)

```







I am almost


If the above checks are all qualified, it is judged whether the current bin is in the fast bin range, and if it is inserted into the **fastbin header**, it becomes the first free chunk** corresponding to the fastbin list.


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

//Default #define TRIM_FASTBINS 0, so the following statement will not execute by default
// If the current chunk is a fast chunk and the next chunk is a top chunk, it cannot be inserted
        && (chunk_at_offset(p, size) != av->top)
#endif
            ) {

// The size of the next chunk cannot be less than twice the SIZE_SZ, and
// The size of the next chunk cannot be greater than system_mem, which is generally 132k
// If this happens, an error is reported.
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

__libc_lock_lock (de-&gt; mutex);
                    locked = 1;

                    chunksize_nomask(chunk_at_offset(p, size)) <= 2 * SIZE_SZ ||

                        chunksize(chunk_at_offset(p, size)) >= av->system_mem;

                })) {

                errstr = "free(): invalid next size (fast)";

                goto errout;

            }

            if (!have_lock) {

__libc_lock_unlock (de-&gt; mutex);
                locked = 0;

            }

        }

// Set the mem part of the chunk to perturb_byte
        free_perturb(chunk2mem(p), size - 2 * SIZE_SZ);

/ / Set the flag bit of the fast chunk
set_fastchunks (of);
/ / Get the index of the fast bin according to the size
        unsigned int idx = fastbin_index(size);

// Get the head pointer corresponding to fastbin, which is NULL after being initialized.
fb = &amp; fastbin (av, idx);


        /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */

// Insert P into the linked list using atomic operations
        mchunkptr    old     = *fb, old2;

        unsigned int old_idx = ~0u;

        do {

            /* Check that the top of the bin is not the record we are going to

               add

               (i.e., double free).  */

            // so we can not double free one fastbin chunk

// prevent against fast bin double free
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

// Make sure the fast bin is added before and after joining
        if (have_lock && old != NULL && __builtin_expect(old_idx != idx, 0)) {

            errstr = "invalid fastbin entry (free)";

            goto errout;

        }

    }

```



### Merging non-mmap free chunks


**Unlink** will only be triggered if it is not a fast bin


First, let&#39;s talk about why the chunks are merged. This is to avoid too many fragmented memory blocks in the heap. After the merge, it can be used to handle larger memory block requests. The main order of the merge is


- Consider the physical low address free block first
- After considering the physical high address free block


**The merged chunk points to the lower address of the merged chunk. **


In the absence of a lock, the lock is first obtained.


```c++

    /*

      Consolidate other non-mmapped chunks as they arrive.

    */



    else if (!chunk_is_mmapped(p)) {

        if (!have_lock) {

__libc_lock_lock (de-&gt; mutex);
            locked = 1;

        }

        nextchunk = chunk_at_offset(p, size);

```



#### Lightweight inspection


```c++

        /* Lightweight tests: check whether the block is already the

           top block.  */

// The current free chunk cannot be the top chunk
        if (__glibc_unlikely(p == av->top)) {

            errstr = "double free or corruption (top)";

            goto errout;

        }

// The next chunk of the current free chunk cannot exceed the bound of arena
        /* Or whether the next chunk is beyond the boundaries of the arena.  */

        if (__builtin_expect(contiguous(av) &&

                                 (char *) nextchunk >=

((char *) off-&gt; top + chunksize (off-&gt; top)),
                             0)) {

            errstr = "double free or corruption (out)";

            goto errout;

        }

// The currently used chunk&#39;s usage tag is not marked, double free
        /* Or whether the block is actually not marked used.  */

        if (__glibc_unlikely(!prev_inuse(nextchunk))) {

            errstr = "double free or corruption (!prev)";

            goto errout;

        }

// the size of the next chunk
        nextsize = chunksize(nextchunk);

        // next chunk size valid check

/ / Determine whether the size of the next chunk is not greater than 2 * SIZE_SZ, or
// Whether nextsize is greater than the memory available in the system
        if (__builtin_expect(chunksize_nomask(nextchunk) <= 2 * SIZE_SZ, 0) ||

            __builtin_expect(nextsize >= av->system_mem, 0)) {

            errstr = "free(): invalid next size (normal)";
            goto errout;

        }

```



#### Release padding


```c++

/ / Set the mem part of the pointer to perturb_byte
		free_perturb(chunk2mem(p), size - 2 * SIZE_SZ);

```



#### Backward merge-merge low address chunk


```c++

        /* consolidate backward */

        if (!prev_inuse(p)) {

            prevsize = prev_size(p);

            size += prevsize;

            p = chunk_at_offset(p, -((long) prevsize));

unlink (off, p, bck, fwd);
        }

```



#### The next block is not a top chunk - forward merge - merge high address chunk


It should be noted that if the next block is not the top chunk, merge the chunks with the high address and put the merged chunk into the unsorted bin.


```c++

// If the next chunk is not the top chunk
		if (nextchunk != av->top) {

            /* get and clear inuse bit */

/ / Get the use status of the next chunk
            nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

// If not used, merge, otherwise clear the current chunk usage status.
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

// put the chunk in the head of the unsorted chunk list
bck = unsorted_chunks (off);
            fwd = bck->fd;

// Simple check
            if (__glibc_unlikely(fwd->bk != bck)) {

                errstr = "free(): corrupted unsorted chunks";

                goto errout;

            }

            p->fd = fwd;

            p->bk = bck;

// If it is a large chunk, set the nextsize pointer field to NULL.
            if (!in_smallbin_range(size)) {

                p->fd_nextsize = NULL;

                p->bk_nextsize = NULL;

            }

            bck->fd = p;

            fwd->bk = p;



            set_head(p, size | PREV_INUSE);

            set_foot(p, size);



check_free_chunk (av, p);
        }

```



#### The next block is the top chunk- merged into the top chunk


```c++

        /*

          If the chunk borders the current high end of memory,

          consolidate into top

        */

// If the next chunk of the chunk to be released is the top chunk, merge it into the top chunk
        else {

            size += nextsize;

            set_head(p, size | PREV_INUSE);

of -&gt; top = p;
check_chunk (av, p);
        }

```



#### Returning memory to the system


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

// If the size of the merged chunk is greater than FASTBIN_CONSOLIDATION_THRESHOLD
// Normally merged into the top chunk will execute this part of the code.
// Then return the memory to the system
        if ((unsigned long) (size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {

// merge if there is a fast chunk
if (have_fastchunks (off)) malloc_consolidate (off);
// main allocation area
if (by == &amp; main_arena) {
#ifndef MORECORE_CANNOT_TRIM

// top chunk is greater than the current contraction threshold
                if ((unsigned long) (chunksize(av->top)) >=

                    (unsigned long) (mp_.trim_threshold))

systrim (mp_.top_pad, off);
#endif // Non-primary allocation area, directly shrinking heap
            } else {

                /* Always try heap_trim(), even if the top chunk is not

                   large, because the corresponding heap might go away.  */

heap_info * heap = heap_for_ptr (top (off));


assert (heap-&gt; ar_ptr == off);
                heap_trim(heap, mp_.top_pad);

            }

        }



        if (!have_lock) {
            assert(locked);

__libc_lock_unlock (de-&gt; mutex);
        }

```



### Release the chunk of mmap


```c++

    } else {

        //  If the chunk was allocated via mmap, release via munmap().

        munmap_chunk(p);

    }

```



## systrim



## heap_trim



## munmap_chunk