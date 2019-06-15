[EN](./heapoverflow_basic.md) | [ZH](./heapoverflow_basic-zh.md)
#堆溢


## Introduction


Heap overflow means that the number of bytes written by the program into a heap block exceeds the number of bytes that can be used by the heap itself (** is the number of bytes that can be used instead of the number of bytes requested by the user, because the heap manager The number of bytes requested by the user is adjusted, which also causes the number of available bytes to be no less than the number of bytes requested by the user**), thus causing data overflow and covering to ** physically adjacent high The next heap of addresses**.


It is not difficult to find that the basic premise of a heap overflow vulnerability is


- The program writes data to the heap.
- The size of the data written is not well controlled.


For the attacker, the heap overflow vulnerability can make the program crash, and the attacker can control the execution flow of the program.


A heap overflow is a specific buffer overflow (and stack overflow, bss segment overflow, etc.). However, unlike stack overflow, there is no return address on the heap that allows the attacker to directly control the execution flow, so we generally cannot control EIP directly through heap overflow. In general, our strategy for using heap overflow is


1. Overwrite the contents of the next chunk** physically adjacent to its **.
    -   prev_size

- size, which has three main bits and the true size of the heap.
        -   NON_MAIN_ARENA 

        -   IS_MAPPED  

        -   PREV_INUSE 

        -   the True chunk size

- chunk content, which changes the execution flow inherent in the program.
2. Use the mechanism in the heap (such as unlink, etc.) to implement the arbitrary address write (Write-Anything-Anywhere) or control the contents of the heap block to control the execution flow of the program.


## Basic example


Let&#39;s take a simple example:


```

#include <stdio.h>



int main(void) 

{

  char *chunk;

  chunk=malloc(24);

  puts("Get input:");

  gets(chunk);

  return 0;

}

```



The main purpose of this program is to call malloc to allocate memory on a heap, and then write a string to the heap. If the input string is too long, it will cause the area of the chunk to overflow and overwrite the top chunk. (In fact, puts internally calls malloc to allocate heap memory, which may not be covered by top chunk).
```

0x602000:	0x0000000000000000	0x0000000000000021 <===chunk

0x602010:	0x0000000000000000	0x0000000000000000

0x602020:	0x0000000000000000	0x0000000000020fe1 <===top chunk

0x602030:	0x0000000000000000	0x0000000000000000

0x602040:	0x0000000000000000	0x0000000000000000

```

print 'A'*100

Write
```

0x602000:	0x0000000000000000	0x0000000000000021 <===chunk

0x602010:	0x4141414141414141	0x4141414141414141

0x602020: 0x4141414141414141 0x4141414141414141 &lt;===top chunk (has been overflowed)
0x602030:	0x4141414141414141	0x4141414141414141

0x602040:	0x4141414141414141	0x4141414141414141

```





## 小述


Several important steps in heap overflow:


### Looking for heap allocation functions
Usually the heap is allocated by calling the glibc function malloc, which in some cases uses the calloc assignment. The difference between calloc and malloc is that **calloc is automatically emptied after allocation, which is fatal for the exploitation of certain information disclosure vulnerabilities**.


```

calloc(0x20);

//Equivalent to
ptr = malloc (0x20);
memset(ptr,0,0x20);

```

In addition to this, there is another type of allocation via realloc, which can function as both malloc and free.
```

#include <stdio.h>



int main(void) 

{

  char *chunk,*chunk1;

  chunk=malloc(16);

  chunk1=realloc(chunk,32);

  return 0;

}

```

The operation of realloc is not as simple as it is literally, and its internal operations will be different depending on different situations.


- When the size of realloc(ptr,size) is not equal to the size of ptr
- If the application size&gt; original size
- If the chunk is adjacent to the top chunk, extend the chunk directly to the new size.
- If the chunk is not adjacent to the top chunk, it is equivalent to free(ptr), malloc(new_size)
- If the application size &lt; original size
- If the difference is not enough to accommodate the next smallest chunk (32 bytes under 64 bits, 16 bytes under 32 bits), it remains unchanged
- If the difference can accommodate the next smallest chunk, then the original chunk is cut into two parts, and the part is free.
- When the size of realloc(ptr,size) is equal to 0, it is equivalent to free(ptr)
- When the size of realloc(ptr,size) is equal to the size of ptr, no action is taken.


### Looking for dangerous functions
By looking for dangerous functions, we quickly determine if the program is likely to have a heap overflow and, if so, where the heap overflows.


Common dangerous functions are as follows


- Enter
- gets, read a line directly, ignoring `&#39;\x00&#39;`
    -   scanf

    -   vscanf

- output
    -   sprintf

- string
- strcpy, string copy, encountered `&#39;\x00&#39;` stop
- strcat, string stitching, encountered `&#39;\x00&#39;` stop
- bcopy


### Determine the fill length
This part is mainly to calculate the distance between the address we started writing and the address we want to cover**.
A common misconception is that the malloc parameter is equal to the actual allocated heap size, but in fact the size allocated by ptmalloc is aligned. This length is typically twice the word length, such as a 32-bit system with 8 bytes and a 64-bit system with 16 bytes. However, for requests that are no longer than 2 times the word length, malloc will directly return the block of 2 times the word length, which is the smallest chunk. For example, a 64-bit system executing `malloc(0)` will return a block with a user area of 16 bytes.


```

#include <stdio.h>



int main(void) 

{

  char *chunk;

  chunk=malloc(0);

  puts("Get input:");

  gets(chunk);
  return 0;

}

```



```

/ / According to the number of bits in the system, malloc will allocate 8 or 16 bytes of user space
0x602000:	0x0000000000000000	0x0000000000000021

0x602010:	0x0000000000000000	0x0000000000000000

0x602020:	0x0000000000000000	0x0000000000020fe1

0x602030:	0x0000000000000000	0x0000000000000000

```

Note that the size of the user area is not equal to chunk_hear.size, chunk_hear.size=user area size + 2* word length


Another point is that the memory size of the user application mentioned above will be modified, and it is possible to store the content using the prev_size field of the next chunk that is physically adjacent to it. Go back and look at the previous sample code.
```

#include <stdio.h>



int main(void) 

{

  char *chunk;

  chunk=malloc(24);

  puts("Get input:");

  gets(chunk);

  return 0;

}

```

Looking at the above code, the chunk size we applied for is 24 bytes. But when we compile it into a 64-bit executable, the actual allocated memory will be 16 bytes instead of 24.
```

0x602000:	0x0000000000000000	0x0000000000000021

0x602010:	0x0000000000000000	0x0000000000000000

0x602020:	0x0000000000000000	0x0000000000020fe1

```

How does the 16-byte space fit the next 24 bytes of content? The answer is to borrow the pre_size field of the next block. Let&#39;s take a look at the conversion between the size of the memory requested by the user and the amount of memory actually allocated in glibc.


```c

/* pad request bytes into a usable size -- internal version */

//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1

#define request2size(req)                                                      \

    (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)                           \

         ? MINSIZE                                                             \

         : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

```



When req=24, request2size(24)=32. And remove the 16 bytes of the chunk header. In fact, the number of bytes available to the user is 16. According to what we learned earlier, we know that the chunk&#39;s pre_size only works when its previous block is released. So the user can actually use the prev_size field of the next chunk at this time, exactly 24 bytes. **Actually, ptmalloc allocates memory in double words as the basic unit. Taking 64-bit system as an example, the allocated space is an integer multiple of 16, that is, the chunks applied by the user are 16-byte aligned. **