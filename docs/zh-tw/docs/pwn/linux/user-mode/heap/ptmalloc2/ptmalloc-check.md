# 堆中的檢查

## _int_malloc

## 初始檢查

| 檢查目標  |                   檢查條件                   |         信息          |
| :---: | :--------------------------------------: | :-----------------: |
| 申請的大小 | REQUEST_OUT_OF_RANGE(req) ：((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE)) | __set_errno(ENOMEM) |

### fastbin

| 檢查目標     |                  檢查條件                   |                報錯信息                |
| -------- | :-------------------------------------: | :--------------------------------: |
| chunk 大小 | fastbin_index(chunksize(victim)) != idx | malloc(): memory corruption (fast) |

### Unsorted bin

|         檢查目標          |                   檢查條件                   |            報錯信息             |
| :-------------------: | :--------------------------------------: | :-------------------------: |
| unsorted bin chunk 大小 | chunksize_nomask (victim) <= 2 * SIZE_SZ \|\| chunksize_nomask (victim)  av->system_mem | malloc(): memory corruption |



### top chunk

|      檢查目標      |                   檢查條件                   |  信息  |
| :------------: | :--------------------------------------: | :--: |
| top chunk size | (unsigned long) (size) >= (unsigned long) (nb + MINSIZE) | 方可進入 |



## __libc_free

### mmap 塊

|      檢查目標      |         檢查條件         |  信息  |
| :------------: | :------------------: | :--: |
| chunk size 標記位 | chunk_is_mmapped (p) | 方可進入 |

### 非mmap 塊

## __int_free

### 初始檢查

|    檢查目標    |                   檢查條件                   |          報錯信息           |
| :--------: | :--------------------------------------: | :---------------------: |
| 釋放chunk位置  | (uintptr_t) p > (uintptr_t) -size \|\| misaligned_chunk(p) | free(): invalid pointer |
| 釋放chunk的大小 |  size < MINSIZE \|\| !aligned_OK(size)   |  free(): invalid size   |

### fastbin

|         檢查目標          |                   檢查條件                   |                報錯信息                 |
| :-------------------: | :--------------------------------------: | :---------------------------------: |
|  釋放chunk的下一個chunk大小   | chunksize_nomask(chunk_at_offset(p, size)) <= 2 * SIZE_SZ， chunksize(chunk_at_offset(p, size)) >= av->system_mem |  free(): invalid next size (fast)   |
| 釋放 chunk對應鏈表的第一個chunk | fb = &fastbin(av, idx)，old= *fb， old == p | double free or corruption (fasttop) |
|       fastbin索引       |      old != NULL && old_idx != idx       |    invalid fastbin entry (free)     |

### non-mmapped 塊檢查

|     檢查目標      |                   檢查條件                   |                報錯信息                |
| :-----------: | :--------------------------------------: | :--------------------------------: |
|   釋放chunk位置   |               p == av->top               |  double free or corruption (top)   |
| next chunk 位置 | contiguous (av) && (char *) nextchunk  >= ((char *) av->top + chunksize(av->top)) |  double free or corruption (out)   |
| next chunk 大小 | chunksize_nomask (nextchunk) <= 2 * SIZE_SZ \|\|  nextsize >= av->system_mem | free(): invalid next size (normal) |

## unlink

|         檢查目標          |                   檢查條件                   |                   報錯信息                   |
| :-------------------: | :--------------------------------------: | :--------------------------------------: |
| size **vs** prev_size | chunksize(P) != prev_size (next_chunk(P)) |       corrupted size vs. prev_size       |
|     Fd, bk 雙向鏈表檢查     |       FD->bk != P \|\| BK->fd != P       |       corrupted double-linked list       |
|     nextsize 雙向鏈表     | P->fd_nextsize->bk_nextsize != P \|\| P->bk_nextsize->fd_nextsize != P | corrupted double-linked list (not small) |

