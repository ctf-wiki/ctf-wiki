[EN](./malloc_state.md) | [ZH](./malloc_state-zh.md)
# malloc_state Related Functions


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

bin = bin_at (av, i);
bin-&gt; fd = bin-&gt; bk = bin;
    }



#if MORECORE_CONTIGUOUS

if (by! = &amp; main_arena)
#endif
set_noncontiguous (of);
    if (av == &main_arena) set_max_fast(DEFAULT_MXFAST);

/ / Set the flags flag does not currently have fast chunk
off-&gt; flags | = FASTCHUNKS_BIT;
// is unsorted bin
off-&gt; top = initial_top (off);
}

```







## malloc_consolidate



This function has two main functions.


1. If fastbin is not initialized, ie global_max_fast is 0, initialize malloc_state.
2. If it has already been initialized, merge the chunks in fastbin.


The basic process is as follows


### Initial


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

int nextinuse;
    mchunkptr       bck;

    mchunkptr       fwd;

```



### Merge chunk


```c

    /*

      If max_fast is 0, we know that av hasn't

      yet been initialized, in which case do so below

    */

// Description fastbin has been initialized
    if (get_max_fast() != 0) {

// empty the fastbin tag
// Because I want to merge the chunks in fastbin.
clear_fastchunks (of);
        //

unsorted_bin = unsorted_chunks (off);


        /*

          Remove each chunk from fast bin and consolidate it, placing it

          then in unsorted bin. Among other reasons for doing this,

          placing in unsorted bin avoids needing to calculate actual bins

          until malloc is sure that chunks aren't immediately going to be

          reused anyway.

        */

// Traverse each bin of fastbin in fd order, merging each chunk in the bin.
maxfb = &amp; fastbin (off, NFASTBINS - 1);
fb = &amp; fastbin (av, 0);
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

unlink (off, p, bck, fwd);
                    }



                    if (nextchunk != av->top) {

// Determine if nextchunk is free.
                        nextinuse = inuse_bit_at_offset(nextchunk, nextsize);



                        if (!nextinuse) {

                            size += nextsize;

                            unlink(av, nextchunk, bck, fwd);

                        } else

// Set the prev inuse of nextchunk to 0 to indicate that the current fast chunk can be merged.
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

of -&gt; top = p;
                    }



                } while ((p = nextp) != 0);

            }

        } while (fb++ != maxfb);

```



### Initialization


Note that fastbin has not been initialized yet.


```c

    } else {

malloc_init_state (of);
// It&#39;s useless in non-debug situations. In the case of debugging, do some testing.
check_malloc_state (of);
    }

```