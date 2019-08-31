[EN](./tcache.md) | [ZH](./tcache-zh.md)
# tcache



Tcache is a technique introduced after glibc 2.26 (ubuntu 17.10) (see [commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc)), the purpose is to improve The performance of heap management. But while improving performance, it has abandoned a lot of security checks, so there are many new ways to use it.


&gt; Mainly refer to the glibc source code, angelboy&#39;s slide and tukan.farm, the links are all at the end.


## Related Structure


Tcache introduces two new structures, `tcache_entry` and `tcache_perthread_struct`.


This is actually very similar to fastbin, but it is different.


### tcache_entry



[source code](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#tcache_entry)



```C

/* We overlay this structure on the user-data portion of a chunk when

   the chunk is stored in the per-thread cache.  */

typedef struct tcache_entry

{

  struct tcache_entry *next;

} tcache_entry;

```



`tcache_entry` is used to link free chunk structures, where the `next` pointer points to the next chunk of the same size.


Note that the next here points to the user data of the chunk, and the fd of the fastbin points to the address at the beginning of the chunk.


Moreover, tcache_entry multiplexes the user data portion of the free chunk.


### tcache_perthread_struct



[source code](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#tcache_perthread_struct)

```C

/* There is one of these for each thread, which contains the

   per-thread cache (hence "tcache_perthread_struct").  Keeping

   overall size low is mildly important.  Note that COUNTS and ENTRIES

   are redundant (we could have just counted the linked list each

   time), this is for performance reasons.  */

typedef struct tcache_perthread_struct

{

  char counts[TCACHE_MAX_BINS];

  tcache_entry *entries[TCACHE_MAX_BINS];

} tcache_perthread_struct;



# define TCACHE_MAX_BINS                64



static __thread tcache_perthread_struct *tcache = NULL;

```



Each thread maintains a `tcache_prethread_struct`, which is the management structure of the entire tcache. There are a total of `TCACHE_MAX_BINS` counters and a `TCACHE_MAX_BINS` entry tcache_entry.


- `tcache_entry` links the same size of free (after free) chunks in a singly linked list, much like fastbin.
- `counts` records the number of free chunks in the `tcache_entry` chain, with up to 7 chunks per chain.


The diagram is probably:


![](http://ww1.sinaimg.cn/large/006AWYXBly1fw87zlnrhtj30nh0ciglz.jpg)





## Basic working methods
- The first malloc will first malloc a block of memory for `tcache_prethread_struct`.
- free memory, and size is less than small bin size
- tcache will be placed in fastbin or unsorted bin before
- after tcache:
- Put it in the corresponding tcache until tcache is filled (the default is 7)
- After tcache is filled, the free memory is placed in fastbin or unsorted bin as before.
- chunks in tcache are not merged (do not cancel inuse bit)
- malloc memory, and size is in the tcache range
- First take chunk from tcache until tcache is empty
- After tcache is empty, look for it from bin
- When tcache is empty, if there is a chunk with size matching in `fastbin/smallbin/unsorted bin`, the chunk in `fastbin/smallbin/unsorted bin` will be put into tcache first until it is full. Then take it from tcache; therefore the order of chunks in bin and tcache will be reversed.


## Source Analysis


Next, analyze tcache from the perspective of source code.


### __libc_malloc

The first time malloc will enter `MAYBE_INIT_TCACHE ()`


[source code](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3010)

```C

void *

__libc_malloc (size_t bytes)

{

    ......

    ......

#if USE_TCACHE

  /* int_free also calls request2size, be careful to not pad twice.  */

  size_t tbytes;

/ / Calculate the actual size of the chunk according to the parameters passed in malloc, and calculate the subscript corresponding to tcache
  checked_request2size (bytes, tbytes);

  size_t tc_idx = csize2tidx (tbytes);



/ / Initialize tcache
  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;

If (tc_idx &lt; mp_.tcache_bins // The idx obtained from size is within the legal range
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */

      && tcache

      && tcache->entries[tc_idx] != NULL) // tcache->entries[tc_idx] 有 chunk

    {

      return tcache_get (tc_idx);

    }

  DIAG_POP_NEEDS_COMMENT;

#endif
    ......

    ......

}

```



### __tcache_init ()
Where `MAYBE_INIT_TCACHE ()` calls `tcache_init()` when tcache is empty (that is, the first malloc), and directly looks at `tcache_init()`


[source code](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#tcache_init)



```C

tcache_init(void)

{

mstate ar_ptr;
  void *victim = 0;

  const size_t bytes = sizeof (tcache_perthread_struct);

  if (tcache_shutting_down)

    return;

Arena_get (ar_ptr, bytes); // find available arena
Victim = _int_malloc (ar_ptr, bytes); // Request a chunk of sizeof(tcache_prethread_struct) size  if (!victim && ar_ptr != NULL)

    {

      ar_ptr = arena_get_retry (ar_ptr, bytes);

      victim = _int_malloc (ar_ptr, bytes);

    }

  if (ar_ptr != NULL)

    __libc_lock_unlock (ar_ptr->mutex);

  /* In a low memory situation, we may not be able to allocate memory

     - in which case, we just keep trying later.  However, we

     typically do this very early, so either there is sufficient

     memory, or there isn't enough memory to do non-trivial

     allocations anyway.  */

If (victim) // initialize tcache
    {

      tcache = (tcache_perthread_struct *) victim;

      memset (tcache, 0, sizeof (tcache_perthread_struct));

    }

}

```



`tcache_init()` After successful return, `tcache_prethread_struct` was successfully created.


### Applying for memory
Next, you will enter the steps to apply for memory.
```C

// Get memory from tcache list
If (tc_idx &lt; mp_.tcache_bins // idx calculated by size is within legal range
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */

      && tcache

&amp;&amp; tcache-&gt;entries[tc_idx] != NULL) // The tcache chain is not empty
    {

      return tcache_get (tc_idx);

    }

  DIAG_POP_NEEDS_COMMENT;

#endif
// Enter a process similar to when there is no tcache
  if (SINGLE_THREAD_P)

    {

      victim = _int_malloc (&main_arena, bytes);

      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||

              &main_arena == arena_for_chunk (mem2chunk (victim)));

      return victim;

    }



```

When `tcache-&gt;entries` is not empty, it will enter the process of `tcache_get()` to get the chunk. Otherwise, it is similar to the process before the tcache mechanism. Here, the first type of `tcache_get()` is analyzed. It can also be seen here that tcache has a high priority and is higher than fastbin (the application of fastbin is not in the process of entering tcache).


### tcache_get()

Take a look at `tcache_get()`


[source code](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#tcache_get)

```C

/* Caller must ensure that we know tc_idx is valid and there's

   available chunks to remove.  */

static __always_inline void *

tcache_get (size_t tc_idx)

{

  tcache_entry *e = tcache->entries[tc_idx];

  assert (tc_idx < TCACHE_MAX_BINS);

  assert (tcache->entries[tc_idx] > 0);

  tcache->entries[tc_idx] = e->next;

--(tcache-&gt;counts[tc_idx]); // Get a chunk, counts one less
  return (void *) e;

}

```

`tcache_get()` is the process of getting the chunk. It can be seen that this process is still very simple. Get the first chunk from `tcache-&gt;entries[tc_idx]`, decrement one by `tcache-&gt;counts`, and there is almost no protection.


### __libc_free()

After reading the application, look at the release when there is tcache


[source code](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3068)

```C

void

__libc_free (void *mem)

{

  ......

  ......

  MAYBE_INIT_TCACHE ();

  ar_ptr = arena_for_chunk (p);

  _int_free (ar_ptr, p, 0);

}

```

`__libc_free()` doesn&#39;t change much, `MAYBE_INIT_TCACHE ()` has no effect on tcache not empty.


### _int_free()

Follow up `_int_free()`


[source code](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#4123)

```C

static void

_int_free (mstate av, mchunkptr p, int have_lock)

{

  ......

  ......

#if USE_TCACHE

  {

    size_t tc_idx = csize2tidx (size);

    if (tcache

        && tc_idx < mp_.tcache_bins // 64

        && tcache->counts[tc_idx] < mp_.tcache_count) // 7

      {

        tcache_put (p, tc_idx);

        return;

      }

  }

#endif
  ......

  ......

```

When judging `tc_idx` is legal, `tcache-&gt;counts[tc_idx]` is within 7, it enters `tcache_put()`, the two parameters passed are the chunk to be released and the size corresponding to the chunk in tcache. Standard.




### tcache_put()



[source code](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#2907)



```C

/* Caller must ensure that we know tc_idx is valid and there's room

   for more chunks.  */

static __always_inline void

tcache_put (mchunkptr chunk, size_t tc_idx)

{

  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  assert (tc_idx < TCACHE_MAX_BINS);

  e->next = tcache->entries[tc_idx];

  tcache->entries[tc_idx] = e;

  ++(tcache->counts[tc_idx]);
}

```

`tcache_puts()` completes the operation of inserting the released chunk into the `tcache-&gt;entries[tc_idx]` list header with almost no protection. And ** did not set the p position to zero**.






## Reference


- http://tukan.farm/2017/07/08/tcache/

- https://github.com/bash-c/slides/blob/master/pwn_heap/tcache_exploitation.pdf

- https://www.secpulse.com/archives/71958.html