# tcache

tcache 是 glibc 2.26(ubuntu 17.10) 之后引入的一种技术（see [commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc)），目的是提升堆管理的性能。但提升性能的同时舍弃了很多安全检查，也因此有了很多新的利用方式。

> 主要参考了 glibc 源码，angelboy 的 slide 以及 tukan.farm，链接都放在最后了。

## New Structure

tcache 引入了两个新的结构体，`tcache_entry` 和 `tcache_perthread_struct`。

**tcache_entry**

[source code](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#tcache_entry)
```C
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;
```

**tcache_perthread_struct**

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

----
先给一个宏观印象：

- `tcache_prethread_struct` 是整个 tcache 的管理结构，其中有 64 项 entries。每个 entries 管理了若干个大小相同的 chunk，用单向链表 (`tcache_entry`) 的方式连接，这一点上和 fastbin 很像
- 每个 thread 都会维护一个 `tcache_prethread_struct`
- `tcache_prethread_struct` 中的 `counts` 记录 `entries` 中每一条链上 chunk 的数目，每条链上最多可以有 7 个 chunk
- `tcache_entry` 用于链接 chunk 结构体，其中的 `next` 指针指向下一个大小相同的 chunk
	- 这里与 fastbin 不同的是 fastbin 的 fd 指向 chunk 开头的地址，而 tcache 的 next 指向 user data 的地方，即 chunk header 之后

用图表示大概是：

![](http://ww1.sinaimg.cn/large/006AWYXBly1fw87zlnrhtj30nh0ciglz.jpg)


## 相关函数
同样先给一个宏观的印象：

- 第一次 malloc 时，会先 malloc 一块内存用来存放 `tcache_prethread_struct`
- 之后 size 在 small chunk 范围内的 malloc 都会先以存放在 tcache 中的为主，方式类似 fastbin
- free 内存，且 size 小于 small bin size 时
	- tcache 之前会放到 fastbin 或者 unsorted bin 中
	- tcache 后：
		- 先放到对应的 tcache 中，直到 tcache 被填满（默认是 7 个）
		- tcache 被填满之后，再次 free 的内存和之前一样被放到 fastbin 或者 unsorted bin 中


### source code
接下来从源码的角度分析一下 tcache。

#### __libc_malloc
第一次 malloc 时，会进入到 `MAYBE_INIT_TCACHE ()`

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
  // 根据 malloc 传入的参数计算 chunk 实际大小，并计算 tcache 对应的下标
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);

  // 初始化 tcache
  MAYBE_INIT_TCACHE ();
  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins  // 根据 size 得到的 idx 在合法的范围内
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

#### __tcache_init()
其中 `MAYBE_INIT_TCACHE ()` 在 tcache 为空（即第一次 malloc）时调用了 `tcache_init()`，直接查看 `tcache_init()`

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
  victim = _int_malloc (ar_ptr, bytes); // 申请一个 sizeof(tcache_prethread_struct) 大小的 chunk
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
  if (victim)
    {
      tcache = (tcache_perthread_struct *) victim; // 更新 tcache
      memset (tcache, 0, sizeof (tcache_perthread_struct));
    }
}
```

`tcache_init()` 成功返回后，`tcache_prethread_struct` 就被成功建立了

#### 申请内存
接下来将进入申请内存的步骤
```C
  // 从 tcache list 中获取内存
  if (tc_idx < mp_.tcache_bins // 由 size 计算的 idx 在合法范围内
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache
      && tcache->entries[tc_idx] != NULL) // 该条 tcache 链不为空
    {
      return tcache_get (tc_idx);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif
  // 进入与无 tcache 时类似的流程
  if (SINGLE_THREAD_P)
    {
      victim = _int_malloc (&main_arena, bytes);
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
              &main_arena == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }

```
在 `tcache->entries` 不为空时，将进入 `tcache_get()` 的流程获取 chunk，否则与 tcache 机制前的流程类似，这里主要分析第一种 `tcache_get()`。这里也可以看出 tcache 的优先级很高，比 fastbin 还要高（ fastbin 的申请在没进入 tcache 的流程中）。

#### tcache_get()
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
  --(tcache->counts[tc_idx]); // 获得一个 chunk，counts 减一
  return (void *) e;
}
```
`tcache_get()` 就是获得 chunk 的过程了。可以看出这个过程还是很简单的，从 `tcache->entries[tc_idx]` 中获得第一个 chunk，`tcache->counts` 减一，几乎没有任何保护。

#### __libc_free()
看完申请，再看看有 tcache 时的释放

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
`__libc_free()` 没有太多变化，`MAYBE_INIT_TCACHE ()` 在 tcache 不为空失去了作用。

#### _int_free()
跟进 `_int_free()` 
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
判断 `tc_idx` 合法，`tcache->counts[tc_idx]` 在 7 个以内时，就进入 `tcache_put()`，传递的两个参数是要释放的 chunk 和该 chunk 对应的 size 在 tcache 中的下标。


#### tcache_put()

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
`tcache_puts()` 完成了把释放的 chunk 插入到 `tcache->entries[tc_idx]` 链表头部的操作，也几乎没有任何保护。并且 **没有把 p 位置零**。

## References:

https://code.woboq.org/userspace/glibc/malloc/malloc.c.html

http://tukan.farm/2017/07/08/tcache/

https://github.com/bash-c/slides/blob/master/pwn_heap/tcache_exploitation.pdf

https://www.secpulse.com/archives/71958.html
