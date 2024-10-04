# 僞隨機數生成器介紹

## 概述

僞隨機數生成器（pseudorandom number generator，PRNG），又稱爲確定性隨機位生成器（deterministic random bit generator，DRBG），是用來生成**接近於絕對隨機數序列的數字序列**的算法。一般來說，PRNG 會依賴於一個初始值，也稱爲種子，來生成對應的僞隨機數序列。只要種子確定了，PRNG 所生成的隨機數就是完全確定的，因此其生成的隨機數序列並不是真正隨機的。

就目前而言，PRNG 在衆多應用都發揮着重要的作用，比如模擬（蒙特卡洛方法），電子競技，密碼應用。

## 隨機性的嚴格性

- 隨機性：隨機數應該不存在統計學偏差，是完全雜亂的數列。
- 不可預測性：不能從過去的序列推測出下一個出現的數。
- 不可重現性：除非數列保存下來，否則不能重現相同的數列。

這三個性質的嚴格性依次遞增。

一般來說，隨機數可以分爲三類

|    類別    | 隨機性 | 不可預測性 | 不可重現性 |
| :--------: | :----: | :--------: | :--------: |
| 弱僞隨機數 |   ✅    |     ❌      |     ❌      |
| 強僞隨機數 |   ✅    |     ✅      |     ❌      |
|  真隨機數  |   ✅    |     ✅      |     ✅      |

一般來說，密碼學中使用的隨機數是第二種。

## 週期

正如我們之前所說，一旦 PRNG 所依賴的種子確定了，那麼 PRNG 生成的隨機數序列基本也就確定了。這裏定義 PRNG 的週期如下：對於一個 PRNG 的**所有可能起始狀態**，不重複序列的最長長度。顯然，對於一個 PRNG 來說，其週期不會大於其所有可能的狀態。但是，需要注意的是，並不是當我們遇到重複的輸出時，就可以認爲是 PRNG 的週期，因爲 PRNG 的狀態一般都是大於輸出的位數的。

## 評價標準

參見維基百科，https://en.wikipedia.org/wiki/Pseudorandom_number_generator。

## 分類

目前通用的僞隨機數生成器主要有

-   線性同餘生成器，LCG
-   線性迴歸發生器
-   [Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister)
-   [xorshift](https://en.wikipedia.org/wiki/Xorshift) generators
-   [WELL](https://en.wikipedia.org/wiki/Well_Equidistributed_Long-period_Linear) family of generators
-   Linear feedback shift register，LFSR，線性反饋移位寄存器

## 問題

通常來說，僞隨機數生成器可能會有以下問題

-   在某些種子的情況下，其生成的隨機數序列的週期會比較小。
-   生成大數時，分配的不均勻。
-   連續值之間關聯密切，知道後續值，可以知道之前的值。
-   輸出序列的值的大小很不均勻。

## 參考

https://en.wikipedia.org/wiki/Pseudorandom_number_generator