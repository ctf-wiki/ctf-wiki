[散列函数 - 维基百科](https://zh.wikipedia.org/wiki/%E6%95%A3%E5%88%97%E5%87%BD%E6%95%B8)

散列函数（或散列算法，又称哈希函数，英语：Hash Function）是一种从任何一种数据中创建小的数字「指纹」的方法。散列函数把消息或数据压缩成摘要，使得数据量变小，将数据的格式固定下来。该函数将数据打乱混合，重新创建一个叫做散列值（hash values，hash codes，hash sums，或 hashes）的指纹。散列值通常用来代表一个短的随机字母和数字组成的字符串。好的散列函数在输入域中很少出现散列冲突。在散列表和数据处理中，不抑制冲突来区别数据，会使得数据库记录更难找到。

- 单向性：对于任意消息 $x$，计算 $H(x)$ 很容易，相反则很难实现。
- 破解方式：通常只能暴力破解。

**Hash 算法分类**

| 算法类型   | 输出 Hash 值长度       |
| ------ | ----------------- |
| MD5    | 128 bit / 256 bit |
| SHA1   | 160 bit           |
| SHA256 | 256 bit           |
| SHA512 | 512 bit           |

**HashCat 工具**

目前最好的基于 CPU 和 GPU 破解 Hash 的软件。

[HashCat 官网](http://www.hashcat.net/hashcat/)

[HashCat 简单使用](http://www.freebuf.com/sectool/112479.html)

## MD5

### 题目

- CFF 2016 好多盐
  - JarvisOJ 好多盐