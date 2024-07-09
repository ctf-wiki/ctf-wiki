# tcache

tcache 是 glibc 2.26 (ubuntu 17.10) 之後引入的一種技術（see [commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc)），目的是提升堆管理的性能。但提升性能的同時捨棄了很多安全檢查，也因此有了很多新的利用方式。

> 主要參考了 glibc 源碼，angelboy 的 slide 以及 tukan.farm，鏈接都放在最後了。

## 相關結構體

tcache 引入了兩個新的結構體，`tcache_entry` 和 `tcache_perthread_struct`。

這其實和 fastbin 很像，但又不一樣。

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

`tcache_entry` 用於鏈接空閒的 chunk 結構體，其中的 `next` 指針指向下一個大小相同的 chunk。

需要注意的是這裏的 next 指向 chunk 的 user data，而 fastbin 的 fd 指向 chunk 開頭的地址。

而且，tcache_entry 會複用空閒 chunk 的 user data 部分。

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

每個 thread 都會維護一個 `tcache_perthread_struct`，它是整個 tcache 的管理結構，一共有 `TCACHE_MAX_BINS` 個計數器和 `TCACHE_MAX_BINS`項 tcache_entry，其中

- `tcache_entry` 用單向鏈表的方式鏈接了相同大小的處於空閒狀態（free 後）的 chunk，這一點上和 fastbin 很像。
- `counts` 記錄了 `tcache_entry` 鏈上空閒 chunk 的數目，每條鏈上最多可以有 7 個 chunk。

用圖表示大概是：

![](https://i0.wp.com/tvax1.sinaimg.cn/large/006AWYXBly1fw87zlnrhtj30nh0ciglz.jpg)


## 基本工作方式
- 第一次 malloc 時，會先 malloc 一塊內存用來存放 `tcache_perthread_struct` 。
- free 內存，且 size 小於 small bin size 時
  - tcache 之前會放到 fastbin 或者 unsorted bin 中
  - tcache 後：
    - 先放到對應的 tcache 中，直到 tcache 被填滿（默認是 7 個）
    - tcache 被填滿之後，再次 free 的內存和之前一樣被放到 fastbin 或者 unsorted bin 中
    - tcache 中的 chunk 不會合並（不取消 inuse bit）
- malloc 內存，且 size 在 tcache 範圍內
  - 先從 tcache 取 chunk，直到 tcache 爲空
  - tcache 爲空後，從 bin 中找
  - tcache 爲空時，如果 `fastbin/smallbin/unsorted bin` 中有 size 符合的 chunk，會先把 `fastbin/smallbin/unsorted bin` 中的 chunk 放到 tcache 中，直到填滿。之後再從 tcache 中取；因此 chunk 在 bin 中和 tcache 中的順序會反過來

## 源碼分析

接下來從源碼的角度分析一下 tcache。

### __libc_malloc
第一次 malloc 時，會進入到 `MAYBE_INIT_TCACHE ()`

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
  // 根據 malloc 傳入的參數計算 chunk 實際大小，並計算 tcache 對應的下標
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);

  // 初始化 tcache
  MAYBE_INIT_TCACHE ();
  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins  // 根據 size 得到的 idx 在合法的範圍內
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

### __tcache_init()
其中 `MAYBE_INIT_TCACHE ()` 在 tcache 爲空（即第一次 malloc）時調用了 `tcache_init()`，直接查看 `tcache_init()`

[source code](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#tcache_init)

```C
tcache_init(void)
{
  mstate ar_ptr;
  void *victim = 0;
  const size_t bytes = sizeof (tcache_perthread_struct);
  if (tcache_shutting_down)
    return;
  arena_get (ar_ptr, bytes); // 找到可用的 arena
  victim = _int_malloc (ar_ptr, bytes); // 申請一個 sizeof(tcache_perthread_struct) 大小的 chunk
  if (!victim && ar_ptr != NULL)
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
  if (victim) // 初始化 tcache
    {
      tcache = (tcache_perthread_struct *) victim;
      memset (tcache, 0, sizeof (tcache_perthread_struct));
    }
}
```

`tcache_init()` 成功返回後，`tcache_perthread_struct` 就被成功建立了。

### 申請內存
接下來將進入申請內存的步驟
```C
  // 從 tcache list 中獲取內存
  if (tc_idx < mp_.tcache_bins // 由 size 計算的 idx 在合法範圍內
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache
      && tcache->entries[tc_idx] != NULL) // 該條 tcache 鏈不爲空
    {
      return tcache_get (tc_idx);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif
  // 進入與無 tcache 時類似的流程
  if (SINGLE_THREAD_P)
    {
      victim = _int_malloc (&main_arena, bytes);
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
              &main_arena == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }

```
在 `tcache->entries` 不爲空時，將進入 `tcache_get()` 的流程獲取 chunk，否則與 tcache 機制前的流程類似，這裏主要分析第一種 `tcache_get()`。這裏也可以看出 tcache 的優先級很高，比 fastbin 還要高（ fastbin 的申請在沒進入 tcache 的流程中）。

### tcache_get()
看一下 `tcache_get()`

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
  --(tcache->counts[tc_idx]); // 獲得一個 chunk，counts 減一
  return (void *) e;
}
```
`tcache_get()` 就是獲得 chunk 的過程了。可以看出這個過程還是很簡單的，從 `tcache->entries[tc_idx]` 中獲得第一個 chunk，`tcache->counts` 減一，幾乎沒有任何保護。

### __libc_free()
看完申請，再看看有 tcache 時的釋放

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
`__libc_free()` 沒有太多變化，`MAYBE_INIT_TCACHE ()` 在 tcache 不爲空失去了作用。

### _int_free()
跟進 `_int_free()`

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
判斷 `tc_idx` 合法，`tcache->counts[tc_idx]` 在 7 個以內時，就進入 `tcache_put()`，傳遞的兩個參數是要釋放的 chunk 和該 chunk 對應的 size 在 tcache 中的下標。


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
`tcache_puts()` 完成了把釋放的 chunk 插入到 `tcache->entries[tc_idx]` 鏈表頭部的操作，也幾乎沒有任何保護。並且 **沒有把 p 位置零**。



## 參考

- http://tukan.farm/2017/07/08/tcache/
- https://github.com/bash-c/slides/blob/master/pwn_heap/tcache_exploitation.pdf
- https://www.secpulse.com/archives/71958.html
