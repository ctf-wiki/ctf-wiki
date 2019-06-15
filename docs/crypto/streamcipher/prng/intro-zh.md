[EN](./intro.md) | [ZH](./intro-zh.md)
# 伪随机数生成器介绍

## 概述

伪随机数生成器（pseudorandom number generator，PRNG），又称为确定性随机位生成器（deterministic random bit generator，DRBG），是用来生成**接近于绝对随机数序列的数字序列**的算法。一般来说，PRNG 会依赖于一个初始值，也称为种子，来生成对应的伪随机数序列。只要种子确定了，PRNG 所生成的随机数就是完全确定的，因此其生成的随机数序列并不是真正随机的。

就目前而言，PRNG 在众多应用都发挥着重要的作用，比如模拟（蒙特卡洛方法），电子竞技，密码应用。

## 随机性的严格性

- 随机性：随机数应该不存在统计学偏差，是完全杂乱的数列。
- 不可预测性：不能从过去的序列推测出下一个出现的数。
- 不可重现性：除非数列保存下来，否则不能重现相同的数列。

这三个性质的严格性依次递增。

一般来说，随机数可以分为三类

|    类别    | 随机性 | 不可预测性 | 不可重现性 |
| :--------: | :----: | :--------: | :--------: |
| 弱伪随机数 |   ✅    |     ❌      |     ❌      |
| 强伪随机数 |   ✅    |     ✅      |     ❌      |
|  真随机数  |   ✅    |     ✅      |     ✅      |

一般来说，密码学中使用的随机数是第二种。

## 周期

正如我们之前所说，一旦 PRNG 所依赖的种子确定了，那么 PRNG 生成的随机数序列基本也就确定了。这里定义 PRNG 的周期如下：对于一个 PRNG 的**所有可能起始状态**，不重复序列的最长长度。显然，对于一个 PRNG 来说，其周期不会大于其所有可能的状态。但是，需要注意的是，并不是当我们遇到重复的输出时，就可以认为是 PRNG 的周期，因为 PRNG 的状态一般都是大于输出的位数的。

## 评价标准

参见维基百科，https://en.wikipedia.org/wiki/Pseudorandom_number_generator。

## 分类

目前通用的伪随机数生成器主要有

-   线性同余生成器，LCG
-   线性回归发生器
-   [Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister)
-   [xorshift](https://en.wikipedia.org/wiki/Xorshift) generators
-   [WELL](https://en.wikipedia.org/wiki/Well_Equidistributed_Long-period_Linear) family of generators
-   Linear feedback shift register，LFSR，线性反馈移位寄存器

## 问题

通常来说，伪随机数生成器可能会有以下问题

-   在某些种子的情况下，其生成的随机数序列的周期会比较小。
-   生成大数时，分配的不均匀。
-   连续值之间关联密切，知道后续值，可以知道之前的值。
-   输出序列的值的大小很不均匀。

## 参考

https://en.wikipedia.org/wiki/Pseudorandom_number_generator