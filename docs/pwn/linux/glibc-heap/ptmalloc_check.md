[EN](./ptmalloc_check.md) | [ZH](./ptmalloc_check-zh.md)
#堆 in the heap


## _int_malloc



## Initial inspection


| Check Objectives | Check Conditions | Information |
| :---: | :--------------------------------------: | :-----------------: |

| 申请的大小 | REQUEST_OUT_OF_RANGE(req) ：((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE)) | __set_errno(ENOMEM) |



### fastbin



| Check Target | Check Condition | Error Message |
| -------- | :-------------------------------------: | :--------------------------------: |

| chunk 大小 | fastbin_index(chunksize(victim)) != idx | malloc(): memory corruption (fast) |



### Unsorted bin



| Check Target | Check Condition | Error Message |
| :-------------------: | :--------------------------------------: | :-------------------------: |

| unsorted bin chunk 大小 | chunksize_nomask (victim) <= 2 * SIZE_SZ \|\| chunksize_nomask (victim)  av->system_mem | malloc(): memory corruption |







### top chunk



| Check Objectives | Check Conditions | Information |
| :------------: | :--------------------------------------: | :--: |

| top chunk size | (unsigned long) (size) >= (unsigned long) (nb + MINSIZE) | 方可进入 |







## __libc_free



### mmap block


| Check Objectives | Check Conditions | Information |
| :------------: | :------------------: | :--: |

| chunk size tag bit | chunk_is_mmapped (p) | to enter |


### Non-mmap block


## __int_free



### Initial inspection


| Check Target | Check Condition | Error Message |
| :--------: | :--------------------------------------: | :---------------------: |

Release the chunk position | (uintptr_t) p &gt; (uintptr_t) -size \|\| misaligned_chunk(p) | free(): invalid pointer |
| 释放chunk的大小 |  size < MINSIZE \|\| !aligned_OK(size)   |  free(): invalid size   |



### fastbin



| Check Target | Check Condition | Error Message |
| :-------------------: | :--------------------------------------: | :---------------------------------: |

| Release the next chunk size of the chunk | chunksize_nomask(chunk_at_offset(p, size)) &lt;= 2 * SIZE_SZ, chunksize(chunk_at_offset(p, size)) &gt;= av-&gt;system_mem | free(): invalid next size (fast) |
| Release the first chunk of the chunk corresponding to the linked list | fb = &amp;fastbin(av, idx), old= *fb, old == p | double free or corruption (fasttop) |
|       fastbin索引       |      old != NULL && old_idx != idx       |    invalid fastbin entry (free)     |



### non-mmapped block check


| Check Target | Check Condition | Error Message |
| :-----------: | :--------------------------------------: | :--------------------------------: |

| Free chunk location | p == av-&gt;top | double free or corruption (top) |
| next chunk 位置 | contiguous (av) && (char *) nextchunk  >= ((char *) av->top + chunksize(av->top)) |  double free or corruption (out)   |

| next chunk 大小 | chunksize_nomask (nextchunk) <= 2 * SIZE_SZ \|\|  nextsize >= av->system_mem | free(): invalid next size (normal) |



## unlink



| Check Target | Check Condition | Error Message |
| :-------------------: | :--------------------------------------: | :--------------------------------------: |

| size **vs** prev_size | chunksize(P) != prev_size (next_chunk(P)) |       corrupted size vs. prev_size       |

| Fd, bk doubly linked list check | FD-&gt;bk != P \|\| BK-&gt;fd != P | corrupted double-linked list |
|     nextsize 双向链表     | P->fd_nextsize->bk_nextsize != P \|\| P->bk_nextsize->fd_nextsize != P | corrupted double-linked list (not small) |


