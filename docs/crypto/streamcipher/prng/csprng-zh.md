[EN](./csprng.md) | [ZH](./csprng-zh.md)
# 密码安全伪随机数生成器

## 介绍

密码学安全伪随机数生成器（cryptographically secure pseudo-random number generator，CSPRNG），也称为密码学伪随机数生成器（cryptographic pseudo-random number generator，CPRNG)，是一种特殊的伪随机数生成器。它需要满足满足一些必要的特性，以便于适合于密码学应用。

密码学的很多方面都需要随机数

-   密钥生成
-   生成初始化向量，IV，用于分组密码的 CBC，CFB，OFB 模式
-   nounce，用于防止重放攻击以及分组密码的 CTR 模式等、
-   [one-time pads](https://en.wikipedia.org/wiki/One-time_pad)
-   某些签名方案中的盐，如 [ECDSA](https://en.wikipedia.org/wiki/ECDSA)， [RSASSA-PSS](https://en.wikipedia.org/w/index.php?title=RSASSA-PSS&action=edit&redlink=1)

## 需求

毫无疑问，密码学安全伪随机数生成器的要求肯定比一般的伪随机数生成器要高。一般而言，CSPRNG 的要求可以分为两类

-   通过统计随机性测试。CSPRNG 必须通过 [next-bit test](https://en.wikipedia.org/wiki/Next-bit_test)，也就是说，知道了一个序列的前 k 个比特，攻击者不可能在多项式时间内以大于 50% 的概率预测出来下一个比特位。这里特别提及一点，姚期智曾在 1982 年证明，如果一个生成器可以通过  [next-bit test](https://en.wikipedia.org/wiki/Next-bit_test)，那么它也可以通过所有其他的多项式时间统计测试。
-   必须能够抵抗足够强的攻击，比如当生成器的部分初始状态或者运行时的状态被攻击者获知时，攻击者仍然不能够获取泄漏状态之前的生成的随机数。

## 分类

就目前而看， CSPRNG 的设计可以分为以下三类

-   基于密码学算法，如密文或者哈希值。
-   基于数学难题
-   某些特殊目的的设计

## 参考文献

-   https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator