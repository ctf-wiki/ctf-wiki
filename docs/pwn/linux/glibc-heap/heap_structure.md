[EN](./heap_structure.md) | [ZH](./heap_structure-zh.md)
#堆related data structure


The operation of the heap is so complicated, so there must be a well-designed data structure inside glibc to manage it. The data structure corresponding to the heap is mainly divided into


- A macro structure that contains macro information about the heap through which the basic information of the heap can be indexed.
- Microstructure, which is used to specifically handle the allocation and reclaiming of memory blocks.


## Overview？？？？



** Give a macro picture here. **


## micro structure


Here we first introduce the structure of the details in the heap, and the vulnerability of the heap is closely related to these structures**.


### malloc_chunk



#### Overview


During the execution of the program, we call the memory requested by malloc as chunk. This memory is represented inside the ptmalloc by the malloc_chunk structure. When the chunk requested by the program is free, it will be added to the corresponding idle management list.


Very interestingly, ** they all use a uniform structure** regardless of the size of a chunk, whether it is allocated or released. Although they use the same data structure, they will behave differently depending on whether they are released.


The structure of malloc_chunk is as follows


```c++

/*

  This struct declaration is misleading (but accurate and necessary).

  It declares a "view" into memory allowing access to necessary

  fields at known offsets from a given base. See explanation below.

*/

struct malloc_chunk {



  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */

  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */



  struct malloc_chunk* fd;         /* double links -- used only if free. */

  struct malloc_chunk* bk;



  /* Only used for large blocks: pointer to next larger size.  */

  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */

  struct malloc_chunk* bk_nextsize;

};

```



First, here are some necessary explanations INTERNAL_SIZE_T, SIZE_SZ, MALLOC_ALIGN_MASK:


```c

/* INTERNAL_SIZE_T is the word-size used for internal bookkeeping of

   chunk sizes.

   The default version is the same as size_t.

   While not strictly necessary, it is best to define this as an

   unsigned type, even if size_t is a signed type. This may avoid some

   artificial size limitations on some systems.

   On a 64-bit machine, you may be able to reduce malloc overhead by

   defining INTERNAL_SIZE_T to be a 32 bit `unsigned int' at the

   expense of not being able to handle more than 2^32 of malloced

   space. If this limitation is acceptable, you are encouraged to set

   this unless you are on a platform requiring 16byte alignments. In

   this case the alignment requirements turn out to negate any

   potential advantages of decreasing size_t word size.

   Implementors: Beware of the possible combinations of:

     - INTERNAL_SIZE_T might be signed or unsigned, might be 32 or 64 bits,

       and might be the same width as int or as long

     - size_t might have different width and signedness as INTERNAL_SIZE_T

     - int and long might be 32 or 64 bits, and might be the same width

   To deal with this, most comparisons and difference computations

   among INTERNAL_SIZE_Ts should cast them to unsigned long, being

   aware of the fact that casting an unsigned int to a wider long does

   not sign-extend. (This also makes checking for negative numbers

   awkward.) Some of these casts result in harmless compiler warnings

   on some systems.  */

#ifndef INTERNAL_SIZE_T

# define INTERNAL_SIZE_T size_t

#endif


/* The corresponding word size.  */

#define SIZE_SZ (sizeof (INTERNAL_SIZE_T))



/* The corresponding bit mask value.  */

#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)

```



In general, size_t is a 64-bit unsigned integer in 64 bits and a 32-bit unsigned integer in 32 bits.


The specific explanation of each field is as follows


- **prev_size**, if the chunk's ** physically adjacent previous address chunk (the address difference between the two pointers is the previous chunk size)** is idle, then the field records the previous chunk The size (including the chunk header). Otherwise, this field can be used to store data for the physical chunk of the previous chunk. **The previous chunk here refers to the chunk ** of the lower address.
- **size** , the size of the chunk, the size must be an integer multiple of 2 * SIZE_SZ. If the requested memory size is not an integer multiple of 2 * SIZE_SZ, it will be converted to a multiple of the smallest 2 * SIZE_SZ that satisfies the size. In a 32-bit system, SIZE_SZ is 4; in a 64-bit system, SIZE_SZ is 8. The lower three bits of this field have no effect on the size of the chunk, they are represented from high to low respectively.
- NON_MAIN_ARENA, records whether the current chunk does not belong to the main thread, 1 means not belonging, 0 means belongs.
- IS_MAPPED, which records whether the current chunk is allocated by mmap.
- PREV_INUSE, records whether the previous chunk is allocated. In general, the P bit of the size field of the first allocated memory block in the heap is set to 1, in order to prevent access to the previous illegal memory. When the P bit of the size of a chunk is 0, we can get the size and address of the previous chunk through the prev_size field. This also facilitates the merging between free chunks.
- **fd, bk**. When the chunk is in the allocation state, it is the user's data starting from the fd field. When chunk is idle, it will be added to the corresponding idle management list. The meaning of the fields is as follows
- fd points to the next (non-physical neighbor) free chunk
- bk points to the previous (non-physical neighbor) free chunk
- Freed chunks can be added to the free chunk block list for unified management via fd and bk
- **fd_nextsize, bk_nextsize**, which is only used when the chunk is free, but it is used for larger chunks.
- fd_nextsize points to the first free block of the previous size that is different from the current chunk, and does not contain the head pointer of the bin.
- bk_nextsize points to the next free block of the current chunk size, excluding the head pointer of the bin.
- Large chunks that are generally free are arranged in descending order of fd, in descending order. **Doing so avoids traversing when looking for a suitable chunk. **


The appearance of an already allocated chunk is as follows. ** We call the first two fields called chunk headers, and the latter part is called user data. The memory pointer obtained by each malloc application actually points to the beginning of user data. **


When a chunk is in use, its prev_size field of the next chunk is invalid, and the part of the next chunk can also be used by the current chunk. **This is the spatial reuse in the chunk. **


```c++

chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        |             Size of previous chunk, if unallocated (P clear)  |

        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        |             Size of chunk, in bytes                     |A|M|P|

mem-> + - + - + - + - + - + - + - + - + - + - + + + + + + + + + + - + - + - + - + - + - + - + - + - + - + - + - + - +
        |             User data starts here...                          .

        .                                                               .

        .             (malloc_usable_size() bytes)                      .

next    .                                                               |

chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        |             (size of chunk, but used for application data)    |

        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        |             Size of next chunk, in bytes                |A|0|1|

        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```



The released chunks are recorded in a linked list (either a circular doubly linked list or a singly linked list). The specific structure is as follows


```c++

chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        |             Size of previous chunk, if unallocated (P clear)  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

`head:' |             Size of chunk, in bytes                     |A|0|P|

mem-> + - + - + - + - + - + - + - + - + - + - + + + + + + + + + + - + - + - + - + - + - + - + - + - + - + - + - + - +
        |             Forward pointer to next chunk in list             |

        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        |             Back pointer to previous chunk in list            |

        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        |             Unused space (may be 0 bytes long)                .

        .                                                               .

 next   .                                                               |

chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

`foot:' |             Size of chunk, in bytes                           |

        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        |             Size of next chunk, in bytes                |A|0|0|

        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```



It can be found that if a chunk is in the free state, there will be two locations to record their corresponding sizes.


1. The size field itself will be logged,


2. The chunks following it will be logged.


** In general, **, two free chunks of physical neighbors will be merged into one chunk. The heap manager merges two physically adjacent free chunk chunks through the prev_size field and the size field.


**! ! ! Some constraints on the heap, consider it in detail later! ! ! **


```c++

/*

    The three exceptions to all this are:

     1. The special chunk `top' doesn't bother using the

    trailing size field since there is no next contiguous chunk

    that would have to index off it. After initialization, `top'

    is forced to always exist.  If it would become less than

    MINSIZE bytes long, it is replenished.

     2. Chunks allocated via mmap, which have the second-lowest-order

    bit M (IS_MMAPPED) set in their size fields.  Because they are

    allocated one-by-one, each must contain its own trailing size

    field.  If the M bit is set, the other bits are ignored

    (because mmapped chunks are neither in an arena, nor adjacent

    to a freed chunk).  The M bit is also used for chunks which

    originally came from a dumped heap via malloc_set_state in

    hooks.c.

     3. Chunks in fastbins are treated as allocated chunks from the

    point of view of the chunk allocator.  They are consolidated

    with their neighbors only in bulk, in malloc_consolidate.

*/

```



#### chunk related macro


Here mainly introduces the size of the chunk, the alignment check, and some macros for conversion.


**chunk and mem pointer header conversion**


Mem points to the starting position of the memory the user gets.


```c++

/* conversion from malloc headers to user pointers, and back */

#define chunk2mem(p) ((void *) ((char *) (p) + 2 * SIZE_SZ))

#define mem2chunk(mem) ((mchunkptr)((char *) (mem) -2 * SIZE_SZ))

```



**Minimum chunk size**


```c++

/* The smallest possible chunk */

#define MIN_CHUNK_SIZE (offsetof(struct malloc_chunk, fd_nextsize))

```



Here, the offsetof function calculates the offset of fd_nextsize in malloc_chunk, indicating that the smallest chunk must contain at least the bk pointer.


**Minimum requested heap memory size**


The memory size requested by the user must be a minimum integer multiple of 2 * SIZE_SZ.


** Note: As for the current MIN_CHUNK_SIZE and MINSIZE sizes are the same, I personally think that the reason to add two macros is to facilitate the later modification of malloc_chunk. **


```c++

/* The smallest size we can malloc is an aligned minimal chunk */

//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1

#define MINSIZE                                                                \

    (unsigned long) (((MIN_CHUNK_SIZE + MALLOC_ALIGN_MASK) &                   \

                      ~MALLOC_ALIGN_MASK))

```



**Check if the memory allocated to the user is aligned**


2 * SIZE_SZ size aligned.


```c++

/* Check if m has acceptable alignment */

// MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1

#define aligned_OK(m) (((unsigned long) (m) & MALLOC_ALIGN_MASK) == 0)



#define misaligned_chunk(p)                                                    \

    ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem(p)) &       \

     MALLOC_ALIGN_MASK)

```



**Request Byte Count Judgment**


```c++

/*

   Check if a request is so large that it would wrap around zero when

   padded and aligned. To simplify some other code, the bound is made

   low enough so that adding MINSIZE will also not wrap around zero.

 */



#define REQUEST_OUT_OF_RANGE(req)                                              \

    ((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE))

```



** Convert user request memory size to actual allocated memory size**


```c++

/* pad request bytes into a usable size -- internal version */

//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1

#define request2size(req)                                                      \

    (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)                           \

         ? MINSIZE                                                             \

         : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)



/*  Same, except also perform argument check */



#define checked_request2size(req, sz)                                          \

    if (REQUEST_OUT_OF_RANGE(req)) {                                           \
        __set_errno(ENOMEM);                                                   \

        return 0;                                                              \

    }                                                                          \

    (sz) = request2size(req);

```



When a chunk is in the allocated state, the prev_size field of its next physical next chunk must be invalid, so this field can be used by the current chunk. This is the multiplexing between chunks in ptmalloc. The specific process is as follows


1. First, use REQUEST_OUT_OF_RANGE to determine if the chunk of the byte size requested by the user can be allocated.
2. Second, it should be noted that the byte requested by the user is used to store data, that is, the part after the chunk header. At the same time, due to the multiplexing between chunks, the prev_size field of the next chunk can be used. Therefore, you only need to add the SIZE_SZ size to fully store the content.
3. Since the minimum chunk of the application allowed in the system is MINSIZE, it is compared. If the minimum requirement is not met, then the MINSIZE byte needs to be allocated directly.
4. If it is greater, because the chunk requested in the system requires 2 * SIZE_SZ alignment, MALLOC_ALIGN_MASK needs to be added here to facilitate alignment.


** Personally think that it is not necessary to add MALLOC_ALIGN_MASK in the first line of the request2size macro. **


** It should be noted that the size obtained by such a calculation formula must ultimately satisfy the user's needs. **


**Marker related**


```c++

/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */

#define PREV_INUSE 0x1



/* extract inuse bit of previous chunk */

#define prev_inuse(p) ((p)->mchunk_size & PREV_INUSE)



/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */

#define IS_MMAPPED 0x2



/* check for mmap()'ed chunk */

#define chunk_is_mmapped(p) ((p)->mchunk_size & IS_MMAPPED)



/* size field is or'ed with NON_MAIN_ARENA if the chunk was obtained

   from a non-main arena.  This is only set immediately before handing

   the chunk to the user, if necessary.  */

#define NON_MAIN_ARENA 0x4



/* Check for chunk from main arena.  */

#define chunk_main_arena(p) (((p)->mchunk_size & NON_MAIN_ARENA) == 0)



/* Mark a chunk as not being on the main arena.  */

#define set_non_main_arena(p) ((p)->mchunk_size |= NON_MAIN_ARENA)



/*

   Bits to mask off when extracting size

   Note: IS_MMAPPED is intentionally not masked off from size field in

   macros for which mmapped chunks should never be seen. This should

   cause helpful core dumps to occur if it is tried by accident by

   people extending or adapting this malloc.

 */

#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

```



**Get chunk size**


```c++

/* Get size, ignoring use bits */

#define chunksize(p) (chunksize_nomask(p) & ~(SIZE_BITS))



/* Like chunksize, but do not mask SIZE_BITS.  */

#define chunksize_nomask(p) ((p)->mchunk_size)

```



**Get the next physical neighboring chunk**


```c++

/* Ptr to next physical malloc_chunk. */

#define next_chunk(p) ((mchunkptr)(((char *) (p)) + chunksize(p)))

```



**Get information about the previous chunk**


```c++

/* Size of the chunk below P.  Only valid if !prev_inuse (P).  */

#define prev_size(p) ((p)->mchunk_prev_size)



/* Set the size of the chunk below P.  Only valid if !prev_inuse (P).  */

#define set_prev_size(p, sz) ((p)->mchunk_prev_size = (sz))



/* Ptr to previous physical malloc_chunk.  Only valid if !prev_inuse (P).  */

#define prev_chunk(p) ((mchunkptr)(((char *) (p)) - prev_size(p)))

```



**Current chunk usage status related operations**


```c++

/* extract p's inuse bit */

#define inuse(p)                                                               \

    ((((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size) & PREV_INUSE)



/* set/clear chunk as being inuse without otherwise disturbing */

#define set_inuse(p)                                                           \

    ((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size |= PREV_INUSE



#define clear_inuse(p)                                                         \

    ((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size &= ~(PREV_INUSE)

```



**Set the size field of the chunk**


```c++

/* Set size at head, without disturbing its use bit */

// SIZE_BITS = 7

#define set_head_size(p, s)                                                    \

    ((p)->mchunk_size = (((p)->mchunk_size & SIZE_BITS) | (s)))



/* Set size/use field */

#define set_head(p, s) ((p)->mchunk_size = (s))



/* Set size at footer (only when chunk is not in use) */

#define set_foot(p, s)                                                         \

    (((mchunkptr)((char *) (p) + (s)))->mchunk_prev_size = (s))

```



**Get the chunk of the specified offset**


```c++

/* Treat space at ptr + offset as a chunk */

#define chunk_at_offset(p, s) ((mchunkptr)(((char *) (p)) + (s)))

```



**Specify the offset at the chunk usage state related operation**


```c++

/* check/set/clear inuse bits in known places */

#define inuse_bit_at_offset(p, s)                                              \

    (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size & PREV_INUSE)


#define set_inuse_bit_at_offset(p, s)                                          \

    (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size |= PREV_INUSE)



#define clear_inuse_bit_at_offset(p, s)                                        \

    (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size &= ~(PREV_INUSE))

```



### am


#### Overview


We have said that the chunks released by the user will not be returned to the system immediately, and ptmalloc will uniformly manage the free chunks in the heap area of the heap and mmap. When the user again requests memory allocation, the ptmalloc allocator will attempt to pick a suitable one for the user in the free chunk. This avoids frequent system calls and reduces the overhead of memory allocation.


In a specific implementation, ptmalloc manages idle chunks in a bin-wise manner. First, it will initially classify chunks into four categories based on the size of the free chunks and the state of use: fast bins, small bins, large bins, unsorted bins. There is still a finer division in each class, and similarly sized chunks are linked by a doubly linked list. That is to say, there will still be multiple unrelated lists in each type of bin to hold chunks of different sizes.


For small bins, large bins, unsorted bins, ptmalloc maintains them in the same array. The data structure corresponding to these bins is in malloc_state, as follows


```c++

#define NBINS 128

/* Normal bins packed as described above */

mchunkptr bins[ NBINS * 2 - 2 ];

```



Although the header of each bin uses the mchunkptr data structure, this is just for the convenience of converting each bin into a malloc_chunk pointer. When we use it, we will use this pointer as a chunk's fd or bk pointer to link together the free heap blocks. This saves space and increases usability. How is it saved? Here we take 32-bit system as an example.


| Meaning | bin1 fd/bin2 prev_size | bin1 bk/bin2 size | bin2 fd/bin3 prev_size | bin2 bk/bin3 size |
| ----- | ---------------------- | ----------------- | ---------------------- | ----------------- |

| bin bottom board | 0 | 1 | 2 | 3 |


It can be seen that in addition to the first bin (unsorted bin), each subsequent bin will share the field of the previous bin, which is treated as the prev_size and size of the malloc chunk. Here also illustrates a problem, the subscript of **bin is not consistent with the first few bins we are talking about. At the same time, the prev_size and size fields of the chunk of the bin header cannot be modified casually, because these two fields are used by other bins. **


The bin in the array is described as follows


1. The first one is unsorted bin, the word is like this, the chunks inside are not sorted, and the stored chunks are more complicated.
2. The bins with indexes from 2 to 63 are called small bins, and the chunks in the same small bin list are the same size. The number of bytes in the small bin list of two adjacent indexes differs by **2 machine words long**, that is, 32 bits differ by 8 bytes, and 64 bits differ by 16 bytes.
3. The bin behind small bins is called large bins. Each bin in large bins contains a range of chunks, with chunks arranged in descending order of fd pointers. Chunks of the same size are also arranged in the order of recent use.


In addition, the arrangement of these bins will follow a principle: ** Any two physically adjacent free chunks cannot be together**.


It should be noted that not all chunks are released into the bin immediately after they are released. In order to increase the speed of allocation, ptmalloc will put some small chunks** into the container of fast bins. ** Moreover, the usage flags of the chunks in the fastbin container are always set, so the above principles are not met. **


Bin general macro is as follows


```c++

typedef struct malloc_chunk *mbinptr;



/* addressing -- note that bin_at(0) does not exist */

#define bin_at(m, i)                                                           \

    (mbinptr)(((char *) &((m)->bins[ ((i) -1) * 2 ])) -                        \

              offsetof(struct malloc_chunk, fd))



/* analog of ++bin */

/ / Get the address of the next bin
#define next_bin(b) ((mbinptr)((char *) (b) + (sizeof(mchunkptr) << 1)))



/* Reminders about list directionality within bins */

// These two macros can be used to traverse the bin
/ / Get the chunk of the bin at the head of the list header
#define first(b) ((b)->fd)

/ / Get the chunk of the bin at the end of the chain
#define last(b) ((b)->bk)

```



#### Fast Bin


Most programs often apply and release some smaller blocks of memory. If some smaller chunks are released and there are free chunks adjacent to them and merged, then the next time you apply for the chunk of the corresponding size again, you need to split the chunk, which greatly reduces the heap. usage efficiency. **Because we spend most of our time in the process of merging, segmentation, and intermediate checks. ** Therefore, the fast bin is specifically designed in ptmalloc, and the corresponding variable is fastbinsY in malloc state.


```c++

/*

   Fastbins



    An array of lists holding recently freed small chunks.  Fastbins

    are not doubly linked.  It is faster to single-link them, and

    since chunks are never removed from the middles of these lists,

    double linking is not necessary. Also, unlike regular bins, they

    are not even processed in FIFO order (they use faster LIFO) since

    ordering doesn't much matter in the transient contexts in which

    fastbins are normally used.



    Chunks in fastbins keep their inuse bit set, so they cannot

    be consolidated with other free chunks. malloc_consolidate

    releases all chunks in fastbins and consolidates them with

    other free chunks.

 */

typedef struct malloc_chunk *mfastbinptr;



/*

    This is in malloc_state.

    /* Fastbins */

    mfastbinptr fastbinsY[ NFASTBINS ];

*/

```



In order to use the fast bin more efficiently, glibc uses a singly linked list to organize each bin, and ** each bin adopts the LIFO policy**, and the recently released chunk will be allocated earlier, so it is more suitable for Locality. That is to say, when the size of the chunk that the user needs is smaller than the maximum size of the fastbin, ptmalloc will first determine whether there is a free block of the corresponding size in the corresponding bin in the fastbin, if any, the chunk will be directly obtained from the bin. . If not, ptmalloc will do the next series of operations.


By default (**32-bit system is an example**), the maximum chunk size supported by default in fastbin is 64 bytes. But the chunk of data that it can support is up to 80 bytes. In addition, fastbin can support up to 10 bins, starting from 8 bytes in data space up to 80 bytes (note that the size of the data space is the same, that is, the prev_size and size fields are removed. Size) is defined as follows


```c++

#define NFASTBINS (fastbin_index(request2size(MAX_FAST_SIZE)) + 1)



#ifndef DEFAULT_MXFAST

#define DEFAULT_MXFAST (64 * SIZE_SZ / 4)

#endif
  

/* The maximum fastbin request size we support */

#define MAX_FAST_SIZE (80 * SIZE_SZ / 4)



/*

   Since the lowest 2 bits in max_fast don't matter in size comparisons,

   they are used as flags.

 */



/*

   FASTCHUNKS_BIT held in max_fast indicates that there are probably

   some fastbin chunks. It is set true on entering a chunk into any

   fastbin, and cleared only in malloc_consolidate.



   The truth value is inverted so that have_fastchunks will be true

   upon startup (since statics are zero-filled), simplifying

   initialization checks.

 */

/ / Determine whether the allocation area has fast bin chunk, 1 means no
#define FASTCHUNKS_BIT (1U)



#define have_fastchunks(M) (((M)->flags & FASTCHUNKS_BIT) == 0)

#define clear_fastchunks(M) catomic_or(&(M)->flags, FASTCHUNKS_BIT)
#define set_fastchunks(M) catomic_and(&(M)->flags, ~FASTCHUNKS_BIT)



/*

   NONCONTIGUOUS_BIT indicates that MORECORE does not return contiguous

   regions.  Otherwise, contiguity is exploited in merging together,

   when possible, results from consecutive MORECORE calls.



   The initial value comes from MORECORE_CONTIGUOUS, but is

   changed dynamically if mmap is ever used as an sbrk substitute.

 */

// Whether MORECORE returns a contiguous memory area.
// MORECORE in the main allocation area is actually sbr(), which returns the default virtual address space by default.
// The non-primary allocation area uses mmap() to allocate large blocks of virtual memory and then splits to simulate the behavior of the primary allocation area.
// By default, the mmap mapping area does not guarantee that the virtual address space is continuous, so the non-primary allocation area allocates non-contiguous virtual address space by default.
#define NONCONTIGUOUS_BIT (2U)



#define contiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) == 0)

#define noncontiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) != 0)

#define set_noncontiguous(M) ((M)->flags |= NONCONTIGUOUS_BIT)

#define set_contiguous(M) ((M)->flags &= ~NONCONTIGUOUS_BIT)



/* ARENA_CORRUPTION_BIT is set if a memory corruption was detected on the

   arena.  Such an arena is no longer used to allocate chunks.  Chunks

   allocated in that arena before detecting corruption are not freed.  */



#define ARENA_CORRUPTION_BIT (4U)



#define arena_is_corrupt(A) (((A)->flags & ARENA_CORRUPTION_BIT))

#define set_arena_corrupt(A) ((A)->flags |= ARENA_CORRUPTION_BIT)



/*

   Set value of max_fast.

   Use impossibly small value if 0.

   Precondition: there are no existing fastbin chunks.

   Setting the value clears fastchunk bit but preserves noncontiguous bit.

 */



#define set_max_fast(s)                                                        \

    global_max_fast =                                                          \

        (((s) == 0) ? SMALLBIN_WIDTH : ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK))

#define get_max_fast() global_max_fast

```



By default, ptmalloc calls set_max_fast(s) to set the global variable global_max_fast to DEFAULT_MXFAST, which is the maximum value of the chunk in the fast bins. When MAX_FAST_SIZE is set to 0, the system does not support fastbin.


**fastbin index**


```c++



#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[ idx ])



/* offset 2 to use otherwise unindexable first 2 bins */

// chunk size=2*size_sz*(2+idx)

/ / Here to reduce 2, otherwise, the first two bins have no way to index.
#define fastbin_index(sz)                                                      \

    ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)

```



** It is important to note that the inuse of the chunk of the fastbin range is always set to 1. Therefore they will not merge with other released chunks. **


However, when the size of the released chunk and the free chunk adjacent to the chunk are larger than FASTBIN_CONSOLIDATION_THRESHOLD, the memory fragmentation may be more. We need to merge the chunks in the fast bins to reduce the impact of memory fragmentation on the system.


```c++

/*

   FASTBIN_CONSOLIDATION_THRESHOLD is the size of a chunk in free()

   that triggers automatic consolidation of possibly-surrounding

   fastbin chunks. This is a heuristic, so the exact value should not

   matter too much. It is defined at half the default trim threshold as a

   compromise heuristic to only attempt consolidation if it is likely

   to lead to trimming. However, it is not dynamically tunable, since

   consolidation reduces fragmentation surrounding large chunks even

   if trimming is not used.

 */



#define FASTBIN_CONSOLIDATION_THRESHOLD (65536UL)

```



The **malloc_consolidate function combines all the chunks in the fastbin that can be merged with other chunks. See in detail the analysis of subsequent detailed functions. **


```

/*

	Chunks in fastbins keep their inuse bit set, so they cannot

    be consolidated with other free chunks. malloc_consolidate

    releases all chunks in fastbins and consolidates them with

    other free chunks.

 */

```



#### Small Bin



The relationship between the size of each chunk in small bins and the index of the bin it is in is: chunk_size = 2 * SIZE_SZ *index, as follows


| Subscript | SIZE_SZ=4 (32-bit) | SIZE_SZ=8 (64-bit) |
| ---- | -------------- | -------------- |

| 2    | 16             | 32             |

| 3    | 24             | 48             |

| 4    | 32             | 64             |

| 5    | 40             | 80             |

| x    | 2\*4\*x        | 2\*8\*x        |

| 63   | 504            | 1008           |



There are a total of 62 circular doubly linked lists in small bins, and the chunks stored in each linked list are the same size. For example, for a 32-bit system, the chunk size stored in the doubly linked list corresponding to subscript 2 is 16 bytes. Each linked list has a linked list node, which makes it easy to manage the internal nodes of the linked list. In addition, the linked list for each bin in **small bins uses the FIFO rule**, so the chunks that are first released in the same linked list are first allocated.


The small bin related macros are as follows


```c++

#define NSMALLBINS 64

#define SMALLBIN_WIDTH MALLOC_ALIGNMENT

// Do you need to correct the subscript of the small bin?
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)



#define MIN_LARGE_SIZE ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)

/ / Determine whether the size of the chunk is within the range of small bin
#define in_smallbin_range(sz)                                                  \

    ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)

// Get the index corresponding to the small bin according to the size of the chunk.
#define smallbin_index(sz)                                                     \

    ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4)                          \

                           : (((unsigned) (sz)) >> 3)) +                       \

     SMALLBIN_CORRECTION)

```



** Perhaps, everyone will be very confused, the size of the chunks in the fastbin and small bin will have a large part of the overlap, then the size of the bin in the small bin is not useful? ** In fact, the chunks in the fast bin are likely to be placed in the small bin. We will have a deep understanding when analyzing the specific source code later.


#### Large Bin



A large total of 63 bins are included in the large bins. The size of the chunks in each bin is inconsistent, but within a certain range. In addition, the 63 bins are divided into 6 groups, and the tolerances between the chunk sizes in each group bin are the same, as follows:

| Group | Quantity | Tolerance |
| ---- | ---- | ------- |

| 1 32 64B |
| 2 16 512B |
| 3    | 8    | 4096B   |

| 4 4 32768B |
| 5    | 2    | 262144B |

| 6 | 1 | No limit |


Here we take the large bin of the 32-bit platform as an example. The size of the first chunk of the first large bin is 512 bytes, which is in the first group, so the size of the chunk that the bin can store is [512, 512 + 64).


The macro about large bin is as follows. Here we take the initial chunk size of the first large bin on the 32-bit platform as 512 bytes, then 512&gt;&gt;6 = 8, so the subscript is 56+8= 64.


```c++

#define largebin_index_32(sz)                                                  \

    (((((unsigned long) (sz)) >> 6) <= 38)                                     \

         ? 56 + (((unsigned long) (sz)) >> 6)                                  \

         : ((((unsigned long) (sz)) >> 9) <= 20)                               \

               ? 91 + (((unsigned long) (sz)) >> 9)                            \

               : ((((unsigned long) (sz)) >> 12) <= 10)                        \

                     ? 110 + (((unsigned long) (sz)) >> 12)                    \

                     : ((((unsigned long) (sz)) >> 15) <= 4)                   \

                           ? 119 + (((unsigned long) (sz)) >> 15)              \

                           : ((((unsigned long) (sz)) >> 18) <= 2)             \

                                 ? 124 + (((unsigned long) (sz)) >> 18)        \

                                 : 126)



#define largebin_index_32_big(sz)                                              \

    (((((unsigned long) (sz)) >> 6) <= 45)                                     \

         ? 49 + (((unsigned long) (sz)) >> 6)                                  \

         : ((((unsigned long) (sz)) >> 9) <= 20)                               \

               ? 91 + (((unsigned long) (sz)) >> 9)                            \

               : ((((unsigned long) (sz)) >> 12) <= 10)                        \

                     ? 110 + (((unsigned long) (sz)) >> 12)                    \

                     : ((((unsigned long) (sz)) >> 15) <= 4)                   \

                           ? 119 + (((unsigned long) (sz)) >> 15)              \

                           : ((((unsigned long) (sz)) >> 18) <= 2)             \

                                 ? 124 + (((unsigned long) (sz)) >> 18)        \

                                 : 126)



// XXX It remains to be seen whether it is good to keep the widths of

// XXX the buckets the same or whether it should be scaled by a factor

// XXX of two as well.

#define largebin_index_64(sz)                                                  \

    (((((unsigned long) (sz)) >> 6) <= 48)                                     \

         ? 48 + (((unsigned long) (sz)) >> 6)                                  \

         : ((((unsigned long) (sz)) >> 9) <= 20)                               \

               ? 91 + (((unsigned long) (sz)) >> 9)                            \

               : ((((unsigned long) (sz)) >> 12) <= 10)                        \

                     ? 110 + (((unsigned long) (sz)) >> 12)                    \

                     : ((((unsigned long) (sz)) >> 15) <= 4)                   \

                           ? 119 + (((unsigned long) (sz)) >> 15)              \

                           : ((((unsigned long) (sz)) >> 18) <= 2)             \

                                 ? 124 + (((unsigned long) (sz)) >> 18)        \

                                 : 126)



#define largebin_index(sz)                                                     \

    (SIZE_SZ == 8 ? largebin_index_64(sz) : MALLOC_ALIGNMENT == 16             \

                                                ? largebin_index_32_big(sz)    \

                                                : largebin_index_32(sz))

```



#### Unsorted Bin



Unsorted bin can be thought of as a buffer before the free chunk returns to its own bin.


Its specific description in glibc is as follows


```c++

/*

   Unsorted chunks



    All remainders from chunk splits, as well as all returned chunks,

    are first placed in the "unsorted" bin. They are then placed

    in regular bins after malloc gives them ONE chance to be used before

    binning. So, basically, the unsorted_chunks list acts as a queue,

    with chunks being placed on it in free (and malloc_consolidate),

    and taken off (to be either used or placed in bins) in malloc.



    The NON_MAIN_ARENA flag is never set for unsorted chunks, so it

    does not have to be taken into account in size comparisons.

 */

```



From the macro below we can see


```c++

/* The otherwise unindexable 1-bin is used to hold unsorted chunks. */

#define unsorted_chunks(M) (bin_at(M, 1))

```



The unsorted bin is at the subscript 1 of the bin array we mentioned earlier. Therefore, the unsorted bin has only one linked list. Idle chunks in unsorted bin are out of order, with two main sources


- When a larger chunk is split into two halves, if the rest is greater than MINSIZE, it will be placed in the unsorted bin.
- When a chunk that does not belong to the fast bin is released, and the chunk is not in close proximity to the top chunk, the chunk is first placed in the unsorted bin. For an explanation of the top chunk, please refer to the introduction below.


In addition, the traversal order used by Unsorted Bin during the process is FIFO.


#### common macro



Here are some general macros.


**Unified to get the index of the chunk according to the size of the chunk**


```c++

#define bin_index(sz)                                                          \

    ((in_smallbin_range(sz)) ? smallbin_index(sz) : largebin_index(sz))

```



### Top Chunk



The description of top chunk in glibc is as follows


```c++

/*

   Top



    The top-most available chunk (i.e., the one bordering the end of

    available memory) is treated specially. It is never included in

    any bin, is used only if no other chunk is available, and is

    released back to the system if it is very large (see

    M_TRIM_THRESHOLD).  Because top initially

    points to its own bin with initial zero size, thus forcing

    extension on the first malloc request, we avoid having any special

    code in malloc to check whether it even exists yet. But we still

    need to do so when getting memory from system, so we make
    initial_top treat the bin as a legal but unusable chunk during the

    interval between initialization and the first call to

    sysmalloc. (This is somewhat delicate, since it relies on

    the 2 preceding words to be zero during this interval as well.)

 */



/* Conveniently, the unsorted bin can be used as dummy top on first call */

#define initial_top(M) (unsorted_chunks(M))

```



When the program first performs malloc, the heap is divided into two pieces, one for the user, and the remaining one is the top chunk. In fact, the so-called top chunk is the chunk with the highest physical address in the current heap. This chunk does not belong to any bin. Its function is to allocate all the bins if they are not up to the specified size. If the size is not less than the specified size, the allocation is made and the remaining part is used as the new top chunk. Otherwise, the heap is expanded and then allocated. The heap is extended by sbrk in the main arena, and the new heap is allocated by the mmap in the thread arena.


It should be noted that the prev_inuse bit of the top chunk is always 1, otherwise the previous chunk will be merged into the top chunk.


** In the initial case, we can use the unsorted chunk as the top chunk. **


### last remainder



When a user uses malloc to request memory allocation, the chunk found by ptmalloc2 may not match the size of the requested memory. In this case, the remaining portion after the split is called the last remainder chunk, and the unsort bin will also store the chunk. The top chunk splits the rest of the section as a last remainder.


## Macrostructure


### arena



In the example we introduced earlier, whether it is the main thread or the newly created thread, there will be a separate arena when applying for memory for the first time. So will each thread have an independent arena? Below we will introduce in detail.


#### arena Quantity


For different systems, the [constraints] of the number of arena (https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/arena.c#L847) are as follows


```text

For 32 bit systems:

     Number of arena = 2 * number of cores.

For 64 bit systems:

     Number of arena = 8 * number of cores.

```



Obviously, not every thread will have a corresponding arena. As for why the 64-bit system is set up, I don't want to understand it. In addition, because the number of cores per system is limited, when the number of threads is more than twice the number of cores (hyperthreading technology), there must be threads waiting, so there is no need to assign an arena to each thread.


#### arena Distribution Rules


**To be added. **


#### the difference


Unlike thread, main_arena is not in the applied heap, but a global variable in the data segment of libc.so.


### heap_info



When the program first starts executing, each thread has no heap area. When it applies for memory, it needs a structure to record the corresponding information, and the role of heap_info is this. And when the resources of the heap are used, you must apply for memory again. In addition, the generally applied heap is not continuous, so it is necessary to record the link structure between different heaps.


**This data structure is specifically prepared for memory requested from the Memory Mapping Segment, which is prepared for non-primary threads. **


The main thread can be extended by the program break location via the sbrk() function (until it touches the Memory Mapping Segment), with only one heap and no heap_info data structure.


The main structure of heap_info is as follows


```c++

#define HEAP_MIN_SIZE (32 * 1024)

#ifndef HEAP_MAX_SIZE

# ifdef DEFAULT_MMAP_THRESHOLD_MAX

#  define HEAP_MAX_SIZE (2 * DEFAULT_MMAP_THRESHOLD_MAX)

# else

#  define HEAP_MAX_SIZE (1024 * 1024) /* must be a power of two */

# endif
#endif


/* HEAP_MIN_SIZE and HEAP_MAX_SIZE limit the size of mmap()ed heaps

   that are dynamically created for multi-threaded programs.  The

   maximum size must be a power of two, for fast determination of

   which heap belongs to a chunk.  It should be much larger than the

   mmap threshold, so that requests with a size just below that

   threshold can be fulfilled without creating too many heaps.  */



/***************************************************************************/



/* A heap is a single contiguous memory region holding (coalesceable)

   malloc_chunks.  It is allocated with mmap() and always starts at an

   address aligned to HEAP_MAX_SIZE.  */



typedef struct _heap_info

{

  mstate ar_ptr; /* Arena for this heap. */

  struct _heap_info *prev; /* Previous heap. */

  size_t size;   /* Current size in bytes. */

  size_t mprotect_size; /* Size in bytes that has been mprotected

                           PROT_READ|PROT_WRITE.  */

  /* Make sure the following data is properly aligned, particularly

     that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of

     MALLOC_ALIGNMENT. */

  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];

} heap_info;

```



This structure is mainly to describe the basic information of the heap, including


- the address of the corresponding arena of the heap
- Since a thread requests a heap, it may be used up and must be applied again. Therefore, one thread may have multiple heaps. Prev records the address of the last heap_info. Here you can see that each heap's heap_info is linked through a singly linked list.
- size indicates the size of the current heap
- The last part ensures alignment (**What is the reason for the negative use here?**)


It seems that the structure should be quite important, but if we look closely at the implementation of the full malloc, we will find that it does not appear frequently.


### malloc_state



This structure is used to manage the heap and record the specific state of the memory of each arena's current application, such as whether there are free chunks, what size of free chunks, and so on. Whether it is thread arena or main arena, they all have only one malloc state structure. Since there may be more than one of the thread's arena, the malloc state structure will be in the latest application's arena.


**Note that the main arena's malloc_state is not part of the heap segment, but a global variable stored in the libc.so data segment. **


Its structure is as follows


```c++

struct malloc_state {

    /* Serialize access.  */

    __libc_lock_define(, mutex);



    /* Flags (formerly in max_fast).  */

    int flags;



    /* Fastbins */

    mfastbinptr fastbinsY[ NFASTBINS ];



    /* Base of the topmost chunk -- not otherwise kept in a bin */

    mchunkptr top;



    /* The remainder from the most recent split of a small request */

    mchunkptr last_remainder;


    /* Normal bins packed as described above */

    mchunkptr bins[ NBINS * 2 - 2 ];



    /* Bitmap of bins, help to speed up the process of determinating if a given bin is definitely empty.*/

    unsigned int binmap[ BINMAPSIZE ];



    /* Linked list, points to the next arena */

    struct malloc_state *next;



    /* Linked list for free arenas.  Access to this field is serialized

       by free_list_lock in arena.c.  */

    struct malloc_state *next_free;



    /* Number of threads attached to this arena.  0 if the arena is on

       the free list.  Access to this field is serialized by

       free_list_lock in arena.c.  */

    INTERNAL_SIZE_T attached_threads;



    /* Memory allocated from the system in this arena.  */

    INTERNAL_SIZE_T system_mem;

    INTERNAL_SIZE_T max_system_mem;

};

```



-   __libc_lock_define(, mutex);

- This variable is used to control the serial access of the program to the same allocation area. When a thread acquires the allocation area, other threads must wait for the thread allocation to complete before they can access the allocation area.


-   flags

- flags records some flags of the allocation area. For example, bit0 records whether the allocation area has a fast bin chunk, and bit1 identifies whether the allocation area can return a continuous virtual address space. details as follows


```c



/*

   FASTCHUNKS_BIT held in max_fast indicates that there are probably

   some fastbin chunks. It is set true on entering a chunk into any

   fastbin, and cleared only in malloc_consolidate.

   The truth value is inverted so that have_fastchunks will be true

   upon startup (since statics are zero-filled), simplifying

   initialization checks.

 */



#define FASTCHUNKS_BIT (1U)



#define have_fastchunks(M) (((M)->flags & FASTCHUNKS_BIT) == 0)

#define clear_fastchunks(M) catomic_or(&(M)->flags, FASTCHUNKS_BIT)

#define set_fastchunks(M) catomic_and(&(M)->flags, ~FASTCHUNKS_BIT)



/*

   NONCONTIGUOUS_BIT indicates that MORECORE does not return contiguous

   regions.  Otherwise, contiguity is exploited in merging together,

   when possible, results from consecutive MORECORE calls.

   The initial value comes from MORECORE_CONTIGUOUS, but is

   changed dynamically if mmap is ever used as an sbrk substitute.

 */



#define NONCONTIGUOUS_BIT (2U)



#define contiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) == 0)

#define noncontiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) != 0)

#define set_noncontiguous(M) ((M)->flags |= NONCONTIGUOUS_BIT)

#define set_contiguous(M) ((M)->flags &= ~NONCONTIGUOUS_BIT)



/* ARENA_CORRUPTION_BIT is set if a memory corruption was detected on the

   arena.  Such an arena is no longer used to allocate chunks.  Chunks

   allocated in that arena before detecting corruption are not freed.  */



#define ARENA_CORRUPTION_BIT (4U)



#define arena_is_corrupt(A) (((A)->flags & ARENA_CORRUPTION_BIT))

#define set_arena_corrupt(A) ((A)->flags |= ARENA_CORRUPTION_BIT)



```



-   fastbinsY[NFASTBINS]

- a pointer to the head of each fast chunk list
-   top

- Point to the top chunk of the allocation area
-   last_reminder

- The remaining part after the latest chunk split
-   bins

- A chunk list for storing unstored bins, small bins and large bins.
-   binmap

- ptmalloc uses a bit to identify whether a bin contains free chunks.


### malloc_par


**! ! To be added! ! **
