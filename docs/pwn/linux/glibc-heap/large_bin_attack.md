[EN](./large_bin_attack.md) | [ZH](./large_bin_attack-zh.md)
# Large Bin Attack



## Introduction


Large Bin Attack can be used to modify the value of any address. For example, to modify global_max_fast and then do the next fast bin attack.






```c

while ((victim = unsorted_chunks (off) -&gt; bk)! = unsorted_chunks (off))
{

    bck = victim->bk;

    if (__builtin_expect (chunksize_nomask (victim) <= 2 * SIZE_SZ, 0)

        || __builtin_expect (chunksize_nomask (victim)

&gt; off-&gt; system_mem, 0))
            malloc_printerr (check_action, "malloc(): memory corruption",

chunk2mem (victim), off);
    size = chunksize (victim);

 

    /*

      If a small request, try to use last remainder if it is the

      only chunk in unsorted bin.  This helps promote locality for

      runs of consecutive small requests. This is the only

      exception to best-fit, and applies only when there is

      no exact fit for a small chunk.

    */

 

    if (in_smallbin_range (nb) &&

bck == unsorted_chunks (off) &amp;&amp;
victim == off-&gt; last_remainder &amp;&amp;
        (unsigned long) (size) > (unsigned long) (nb + MINSIZE))

    {

        /* split and reattach remainder */

        remainder_size = size - nb;

        remainder = chunk_at_offset (victim, nb);

unsorted_chunks (off) -&gt; bk = unsorted_chunks (off) -&gt; fd = remainder;
av-&gt; last_remainder = remainder;
        remainder->bk = remainder->fd = unsorted_chunks (av);

        if (!in_smallbin_range (remainder_size))

        {

            remainder->fd_nextsize = NULL;

            remainder->bk_nextsize = NULL;

        }

 

        set_head (victim, nb | PREV_INUSE |

(av! = &amp; main_arena? NON_MAIN_ARENA: 0));
        set_head (remainder, remainder_size | PREV_INUSE);

        set_foot (remainder, remainder_size);

 

check_malloced_chunk (off, victim, nb);
        void *p = chunk2mem (victim);

        alloc_perturb (p, bytes);

        return p;

    }

 

    /* remove from unsorted list */

unsorted_chunks (off) -&gt; bk = bck;
bck-&gt; fd = unsorted_chunks (off);
 

    /* Take now instead of binning if exact fit */

 

    if (size == nb)

    {

         set_inuse_bit_at_offset (victim, size);

if (by! = &amp; main_arena)
             set_non_main_arena (victim);

check_malloced_chunk (off, victim, nb);
         void *p = chunk2mem (victim);

         alloc_perturb (p, bytes);

         return p;

    }

 

    /* place chunk in bin */

    if (in_smallbin_range (size))

    {

        victim_index = smallbin_index (size);

bck = bin_at (off, victim_index);
        fwd = bck->fd;

    }

    else

    {

        victim_index = largebin_index (size);

bck = bin_at (off, victim_index);
        fwd = bck->fd;

 

        /* maintain large bins in sorted order */

        if (fwd != bck)

        {

             /* Or with inuse bit to speed comparisons */

             size |= PREV_INUSE;

             /* if smaller than smallest, bypass loop below */

             assert (chunk_main_arena (bck->bk));

             if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk))

             {

                 fwd = bck;

                 bck = bck->bk;

                 victim->fd_nextsize = fwd->fd;

                 victim->bk_nextsize = fwd->fd->bk_nextsize;

                 fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;

              }

              else

              {

                  assert (chunk_main_arena (fwd));

                  while ((unsigned long) size < chunksize_nomask (fwd))

                  {

                      fwd = fwd->fd_nextsize;

                      assert (chunk_main_arena (fwd));

                  }

 

                  if ((unsigned long) size == (unsigned long) chunksize_nomask (fwd))

                        /* Always insert in the second position.  */

                        fwd = fwd->fd;

                  else

                  {

                      victim->fd_nextsize = fwd;

                      victim->bk_nextsize = fwd->bk_nextsize;

                      fwd->bk_nextsize = victim;

                      victim->bk_nextsize->fd_nextsize = victim;

                  }

                  bck = fwd->bk;

              }

          }

          else

              victim->fd_nextsize = victim->bk_nextsize = victim;

    }

 

 
 

mark_bin (off, victim_index);
    victim->bk = bck;

    victim->fd = fwd;

    fwd->bk = victim;

    bck->fd = victim;

 

#define MAX_ITERS 10000
if (++ iters&gt; = MAX_ITERS)
        break;

}



```



The code associated with largebin is as above, the main core code we are using is the following branch:


When the `if ((unsigned long) size == (unsigned long) chunksize_nomask (fwd))` condition is not satisfied


```c

                  if ((unsigned long) size == (unsigned long) chunksize_nomask (fwd))

                        /* Always insert in the second position.  */

                        fwd = fwd->fd;

                  else

                  {

                      victim->fd_nextsize = fwd;

                      victim->bk_nextsize = fwd->bk_nextsize;

                      fwd->bk_nextsize = victim;

                      victim->bk_nextsize->fd_nextsize = victim;

                  }



```







## example


### 0x1 how2heap：large_bin_attack



We constructed the following scenario:


```bash

PwnLife> parseheap

addr                prev                size                 status              fd                bk

0x603000            0x0                 0xa0                 Used                None              None

0x6030a0            0x0                 0x290                Freed     0x7ffff7dd1b58          0x6037a0

0x603330            0x290               0x30                 Used                None              None

0x603360            0x0                 0x410                Freed     0x7ffff7dd1f48    0x7ffff7dd1f48

0x603770            0x410               0x30                 Used                None              None

0x6037a0            0x0                 0x410                Freed           0x6030a0    0x7ffff7dd1b58

0x603bb0            0x410               0x30                 Used                None              None

```



The chunk scenario is as follows:


```bash

                  top: 0x603be0 (size : 0x20420)

       last_remainder: 0x6030a0 (size : 0x290)

            unsortbin: 0x6037a0 (size : 0x410) <--> 0x6030a0 (size : 0x290)

         largebin[ 0]: 0x603360 (size : 0x410)

```



unsortbin :



```bash

+----------------------------------------+

|                                        |

|                                        |

|               +-------------+          |

| | | v
| P3 v | P1
|         +-----+------+      |     +------------+

|         |            |      |     |            |

|         |            |      |     |            |

|         +------------+      |     +------------+

|         |            |      |     |            |

|         | size:0x410 |      |     | size:0x290 |

|         +------------+      |     +------------+

|         |            |      |     |            |

+ ----------- + fd | | | |
          +------------+      |     +------------+

          |            |      |     |            |

          |            |      +---------+ bk     |

          +------------+            +------------+

```



Then we modify the chunk of P2 through some kind of vulnerability:


```c

    p2[-1] = 0x3f1;

    p2[0] = 0;

    p2[2] = 0;

    p2[1] = (unsigned long)(&stack_var1 - 2);

    p2[3] = (unsigned long)(&stack_var2 - 4);

```



Then we malloc a new chunk. At this time, because the fastbin is empty, the program traverses the unsorte bin. At that time, when the chunk in the unsorte bin is large bin, first determine whether the current chunk size is smaller than bck-&gt;bk. The size, which is the smallest chunk in the large bin, if it is, is added directly to the end. If not, it traverses the large bin until it finds that the size of a chunk is less than or equal to the current chunk size (the chunks of the large bin are aligned from large to small). Then insert the current chunk into the two linked lists of the large bin.


The `fd_nextsize` in the large bin chunk points to the first chunk in the list that is smaller than itself, and `bk_nextsize` points to the first chunk larger than itself.






At this time, we have only one chunk in the largebin, and the current chunk size is 0x290 is smaller than the chunk size in the largebin. First, the chunk in the unsorted bin is placed in the large bin, and then the large bin is traversed. At this time, the fwd chunk does not match the if. ((unsigned long) size == (unsigned long) chunksize_nomask (fwd))` When this condition:


```c

    [...]



              else

              {

                  victim->fd_nextsize = fwd;

                  victim->bk_nextsize = fwd->bk_nextsize;

                  fwd->bk_nextsize = victim;

                  victim->bk_nextsize->fd_nextsize = victim;

              }

              bck = fwd->bk;



    [...]



mark_bin (off, victim_index);
    victim->bk = bck;

    victim->fd = fwd;

    fwd->bk = victim;

    bck->fd = victim;

```



Fwd is now P2, victim is P3, and the two variables on the stack can be modified to `victim`.

