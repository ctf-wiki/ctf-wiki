# 堆溢出

## 介紹

堆溢出是指程序向某個堆塊中寫入的字節數超過了堆塊本身可使用的字節數（**之所以是可使用而不是用戶申請的字節數，是因爲堆管理器會對用戶所申請的字節數進行調整，這也導致可利用的字節數都不小於用戶申請的字節數**），因而導致了數據溢出，並覆蓋到**物理相鄰的高地址**的下一個堆塊。

不難發現，堆溢出漏洞發生的基本前提是

- 程序向堆上寫入數據。
- 寫入的數據大小沒有被良好地控制。

對於攻擊者來說，堆溢出漏洞輕則可以使得程序崩潰，重則可以使得攻擊者控制程序執行流程。

堆溢出是一種特定的緩衝區溢出（還有棧溢出， bss 段溢出等）。但是其與棧溢出所不同的是，堆上並不存在返回地址等可以讓攻擊者直接控制執行流程的數據，因此我們一般無法直接通過堆溢出來控制 EIP 。一般來說，我們利用堆溢出的策略是

1.  覆蓋與其**物理相鄰的下一個 chunk** 的內容。
    -   prev_size
    -   size，主要有三個比特位，以及該堆塊真正的大小。
        -   NON_MAIN_ARENA 
        -   IS_MAPPED  
        -   PREV_INUSE 
        -   the True chunk size
    -   chunk content，從而改變程序固有的執行流。
2.  利用堆中的機制（如 unlink 等 ）來實現任意地址寫入（ Write-Anything-Anywhere）或控制堆塊中的內容等效果，從而來控制程序的執行流。

## 基本示例

下面我們舉一個簡單的例子：

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

這個程序的主要目的是調用 malloc 分配一塊堆上的內存，之後向這個堆塊中寫入一個字符串，如果輸入的字符串過長會導致溢出 chunk 的區域並覆蓋到其後的 top chunk 之中(實際上 puts 內部會調用 malloc 分配堆內存，覆蓋到的可能並不是 top chunk)。
```
0x602000:	0x0000000000000000	0x0000000000000021 <===chunk
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000020fe1 <===top chunk
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
```
print 'A'*100
進行寫入
```
0x602000:	0x0000000000000000	0x0000000000000021 <===chunk
0x602010:	0x4141414141414141	0x4141414141414141
0x602020:	0x4141414141414141	0x4141414141414141 <===top chunk(已被溢出)
0x602030:	0x4141414141414141	0x4141414141414141
0x602040:	0x4141414141414141	0x4141414141414141
```


## 小總結

堆溢出中比較重要的幾個步驟:

### 尋找堆分配函數
通常來說堆是通過調用 glibc 函數 malloc 進行分配的，在某些情況下會使用 calloc 分配。calloc 與 malloc 的區別是 **calloc 在分配後會自動進行清空，這對於某些信息泄露漏洞的利用來說是致命的**。

```
calloc(0x20);
//等同於
ptr=malloc(0x20);
memset(ptr,0,0x20);
```
除此之外，還有一種分配是經由 realloc 進行的，realloc 函數可以身兼 malloc 和 free 兩個函數的功能。
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
realloc的操作並不是像字面意義上那麼簡單，其內部會根據不同的情況進行不同操作

-   當realloc(ptr,size)的size不等於ptr的size時
    -   如果申請size>原來size
        -   如果chunk與top chunk相鄰，直接擴展這個chunk到新size大小
        -   如果chunk與top chunk不相鄰，相當於free(ptr),malloc(new_size) 
    -   如果申請size<原來size
        -   如果相差不足以容得下一個最小chunk(64位下32個字節，32位下16個字節)，則保持不變
        -   如果相差可以容得下一個最小chunk，則切割原chunk爲兩部分，free掉後一部分
-   當realloc(ptr,size)的size等於0時，相當於free(ptr)
-   當realloc(ptr,size)的size等於ptr的size，不進行任何操作

### 尋找危險函數
通過尋找危險函數，我們快速確定程序是否可能有堆溢出，以及有的話，堆溢出的位置在哪裏。

常見的危險函數如下

-   輸入
    -   gets，直接讀取一行，忽略 `'\x00'`
    -   scanf
    -   vscanf
-   輸出
    -   sprintf
-   字符串
    -   strcpy，字符串複製，遇到 `'\x00'` 停止
    -   strcat，字符串拼接，遇到 `'\x00'` 停止
    -   bcopy

### 確定填充長度
這一部分主要是計算**我們開始寫入的地址與我們所要覆蓋的地址之間的距離**。
一個常見的誤區是malloc的參數等於實際分配堆塊的大小，但是事實上 ptmalloc 分配出來的大小是對齊的。這個長度一般是字長的2倍，比如32位系統是8個字節，64位系統是16個字節。但是對於不大於2倍字長的請求，malloc會直接返回2倍字長的塊也就是最小chunk，比如64位系統執行`malloc(0)`會返回用戶區域爲16字節的塊。

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
//根據系統的位數，malloc會分配8或16字節的用戶空間
0x602000:	0x0000000000000000	0x0000000000000021
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000020fe1
0x602030:	0x0000000000000000	0x0000000000000000
```
注意用戶區域的大小不等於 chunk_head.size，chunk_head.size=用戶區域大小+2*字長

還有一點是之前所說的用戶申請的內存大小會被修改，其有可能會使用與其物理相鄰的下一個chunk的prev_size字段儲存內容。回頭再來看下之前的示例代碼
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
觀察如上代碼，我們申請的chunk大小是24個字節。但是我們將其編譯爲64位可執行程序時，實際上分配的內存會是16個字節而不是24個。
```
0x602000:	0x0000000000000000	0x0000000000000021
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000020fe1
```
16個字節的空間是如何裝得下24個字節的內容呢？答案是借用了下一個塊的pre_size域。我們可來看一下用戶申請的內存大小與glibc中實際分配的內存大小之間的轉換。

```c
/* pad request bytes into a usable size -- internal version */
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define request2size(req)                                                      \
    (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)                           \
         ? MINSIZE                                                             \
         : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
```

當req=24時，request2size(24)=32。而除去chunk 頭部的16個字節。實際上用戶可用chunk的字節數爲16。而根據我們前面學到的知識可以知道chunk的pre_size僅當它的前一塊處於釋放狀態時才起作用。所以用戶這時候其實還可以使用下一個chunk的prev_size字段，正好24個字節。**實際上 ptmalloc 分配內存是以雙字爲基本單位，以64位系統爲例，分配出來的空間是16的整數倍，即用戶申請的chunk都是16字節對齊的。**
