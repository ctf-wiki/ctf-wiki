# House of Orange


## 介紹
House of Orange與其他的House of XX利用方法不同，這種利用方法來自於Hitcon CTF 2016中的一道同名題目。由於這種利用方法在此前的CTF題目中沒有出現過，因此之後出現的一系列衍生題目的利用方法我們稱之爲House of Orange。

## 概述
House of Orange的利用比較特殊，首先需要目標漏洞是堆上的漏洞但是特殊之處在於題目中不存在free函數或其他釋放堆塊的函數。我們知道一般想要利用堆漏洞，需要對堆塊進行malloc和free操作，但是在House of Orange利用中無法使用free函數，因此House of Orange核心就是通過漏洞利用獲得free的效果。


## 原理
如我們前面所述，House of Orange的核心在於在沒有free函數的情況下得到一個釋放的堆塊(unsorted bin)。
這種操作的原理簡單來說是當前堆的top chunk尺寸不足以滿足申請分配的大小的時候，原來的top chunk會被釋放並被置入unsorted bin中，通過這一點可以在沒有free函數情況下獲取到unsorted bins。

我們來看一下這個過程的詳細情況，我們假設目前的top chunk已經不滿足malloc的分配需求。
首先我們在程序中的`malloc`調用會執行到libc.so的`_int_malloc`函數中，在`_int_malloc`函數中，會依次檢驗fastbin、small bins、unsorted bin、large bins是否可以滿足分配要求，因爲尺寸問題這些都不符合。接下來`_int_malloc`函數會試圖使用top chunk，在這裏top chunk也不能滿足分配的要求，因此會執行如下分支。

```
/*
Otherwise, relay to handle system-dependent cases
*/
else {
      void *p = sysmalloc(nb, av);
      if (p != NULL && __builtin_expect (perturb_byte, 0))
	    alloc_perturb (p, bytes);
      return p;
}
```

此時ptmalloc已經不能滿足用戶申請堆內存的操作，需要執行sysmalloc來向系統申請更多的空間。
但是對於堆來說有mmap和brk兩種分配方式，我們需要讓堆以brk的形式拓展，之後原有的top chunk會被置於unsorted bin中。

綜上，我們要實現brk拓展top chunk，但是要實現這個目的需要繞過一些libc中的check。
首先，malloc的尺寸不能大於`mmp_.mmap_threshold`
```
if ((unsigned long)(nb) >= (unsigned long)(mp_.mmap_threshold) && (mp_.n_mmaps < mp_.n_mmaps_max))
```
如果所需分配的 chunk 大小大於 mmap 分配閾值，默認爲 128K，並且當前進程使用 mmap()分配的內存塊小於設定的最大值，將使用 mmap()系統調用直接向操作系統申請內存。

在sysmalloc函數中存在對top chunk size的check，如下

```
assert((old_top == initial_top(av) && old_size == 0) ||
	 ((unsigned long) (old_size) >= MINSIZE &&
	  prev_inuse(old_top) &&
	  ((unsigned long)old_end & pagemask) == 0));
```
這裏檢查了top chunk的合法性，如果第一次調用本函數，top chunk可能沒有初始化，所以可能old_size爲0。
如果top chunk已經初始化了，那麼top chunk的大小必須大於等於MINSIZE，因爲top chunk中包含了 fencepost，所以top chunk的大小必須要大於MINSIZE。其次top chunk必須標識前一個chunk處於inuse狀態，並且top chunk的結束地址必定是頁對齊的。此外top chunk除去fencepost的大小必定要小於所需chunk的大小，否則在_int_malloc()函數中會使用top chunk分割出chunk。

我們總結一下僞造的top chunk size的要求

1. 僞造的size必須要對齊到內存頁
2. size要大於MINSIZE(0x10)
3. size要小於之後申請的chunk size + MINSIZE(0x10)
4. size的prev inuse位必須爲1

之後原有的top chunk就會執行`_int_free`從而順利進入unsorted bin中。


## 示例

這裏給出了一個示例程序，程序模擬了一個溢出覆蓋到top chunk的size域。我們試圖把size改小從而實現brk擴展，並把原有的top chunk放入unsorted bin中。

```
#include <stdlib.h>
#define fake_size 0x41

int main(void)
{
    void *ptr;
    
    ptr=malloc(0x10);
    ptr=(void *)((long long)ptr+24);
    
    *((long long*)ptr)=fake_size; // overwrite top chunk size
    
    malloc(0x60);
    
    malloc(0x60);
}
```
這裏我們把top chunk的size覆蓋爲0x41。之後申請大於這個尺寸的堆塊，即0x60。
但是當我們執行這個示例時會發現，這個程序並不能利用成功，原因在於assert並沒有被滿足從而拋出了異常。

```
[#0] 0x7ffff7a42428 → Name: __GI_raise(sig=0x6)
[#1] 0x7ffff7a4402a → Name: __GI_abort()
[#2] 0x7ffff7a8a2e8 → Name: __malloc_assert(assertion=0x7ffff7b9e150 "(old_top == initial_top (av) && old_size == 0) || ((unsigned long) (old_size) >= MINSIZE && prev_inuse (old_top) && ((unsigned long) old_end & (pagesize - 1)) == 0)", file=0x7ffff7b9ab85 "malloc.c", line=0x95a, function=0x7ffff7b9e998 <__func__.11509> "sysmalloc")
[#3] 0x7ffff7a8e426 → Name: sysmalloc(nb=0x70, av=0x7ffff7dd1b20 <main_arena>)
```


## 正確的示例

我們回頭來看一下assert的條件，可以發現之前列出的條目都被滿足了除了第一條。

```
1.僞造的size必須要對齊到內存頁
```

什麼是對齊到內存頁呢？我們知道現代操作系統都是以內存頁爲單位進行內存管理的，一般內存頁的大小是4kb。那麼我們僞造的size就必須要對齊到這個尺寸。在覆蓋之前top chunk的size大小是20fe1，通過計算得知0x602020+0x20fe0=0x623000是對於0x1000（4kb）對齊的。

```
0x602000:	0x0000000000000000	0x0000000000000021
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000020fe1 <== top chunk
0x602030:	0x0000000000000000	0x0000000000000000
```
因此我們僞造的fake_size可以是0x0fe1、0x1fe1、0x2fe1、0x3fe1等對4kb對齊的size。而0x40不滿足對齊，因此不能實現利用。

```
#include <stdlib.h>
#define fake_size 0x1fe1

int main(void)
{
    void *ptr;
    
    ptr=malloc(0x10);
    ptr=(void *)((long long)ptr+24);
    
    *((long long*)ptr)=fake_size;
    
    malloc(0x2000);
    
    malloc(0x60);
}
```

進行分配之後我們可以觀察到原來的堆經過了brk擴展

```
//原有的堆
0x0000000000602000 0x0000000000623000 0x0000000000000000 rw- [heap]

//經過擴展的堆
0x0000000000602000 0x0000000000646000 0x0000000000000000 rw- [heap]
```

我們的申請被分配到0x623010的位置，同時原有的堆被置入unsorted bin

```
[+] unsorted_bins[0]: fw=0x602020, bk=0x602020
 →   Chunk(addr=0x602030, size=0x1fc0, flags=PREV_INUSE)
```

因爲unsorted bin中存在塊，所以我們下次的分配會切割這個塊

```
 malloc(0x60);
 0x602030

[+] unsorted_bins[0]: fw=0x602090, bk=0x602090
 →   Chunk(addr=0x6020a0, size=0x1f50, flags=PREV_INUSE)
```

可以看到分配的內存是從unsorted bin中切割的，內存佈局如下

```
0x602030:	0x00007ffff7dd2208	0x00007ffff7dd2208 <== 未被清零的unsorted bin鏈表
0x602040:	0x0000000000602020	0x0000000000602020
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000001f51 <== 切割剩下的新unsorted bin
0x6020a0:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x6020b0:	0x0000000000000000	0x0000000000000000

```


其實house of orange的要點正在於此，之後的利用因爲涉及到_IO_FILE的知識，放到IO_FILE獨立章節分享。

