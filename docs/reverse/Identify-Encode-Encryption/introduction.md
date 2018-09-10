
---
typora-root-url: ../../../docs
---
## 前言

在对数据进行变换的过程中，除了简单的字节操作之外，还会使用一些常用的编码加密算法，因此如果能够快速识别出对应的编码或者加密算法，就能更快的分析出整个完整的算法。CTF 逆向中通常出现的加密算法包括base64、TEA、AES、RC4、MD5等。

## Base64

Base64 是一种基于64个可打印字符来表示二进制数据的表示方法。转换的时候，将3字节的数据，先后放入一个24位的缓冲区中，先来的字节占高位。数据不足3字节的话，于缓冲器中剩下的比特用0补足。每次取出6比特（因为 ![{\displaystyle 2^{6}=64}](https://wikimedia.org/api/rest_v1/media/math/render/svg/c4becc8d811901597b9807eccff60f0897e3701a)），按照其值选择`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ `中的字符作为编码后的输出，直到全部输入数据转换完成。





通常而言 Base64 的识别特征为索引表，当我们能找到 `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ ` 这样索引表，再经过简单的分析基本就能判定是 Base64 编码。

![](http://ob2hrvcxg.bkt.clouddn.com/20180822140744.png)



当然，有些题目 base64 的索引表是会变的，一些变种的 base64 主要 就是修改了这个索引表。





## Tea

在[密码学](https://zh.wikipedia.org/wiki/%E5%AF%86%E7%A0%81%E5%AD%A6)中，**微型加密算法**（Tiny Encryption Algorithm，TEA）是一种易于描述和[执行](https://zh.wikipedia.org/w/index.php?title=%E6%89%A7%E8%A1%8C&action=edit&redlink=1)的[块密码](https://zh.wikipedia.org/wiki/%E5%A1%8A%E5%AF%86%E7%A2%BC)，通常只需要很少的代码就可实现。其设计者是[剑桥大学计算机实验室](https://zh.wikipedia.org/wiki/%E5%89%91%E6%A1%A5%E5%A4%A7%E5%AD%A6)的[大卫·惠勒](https://zh.wikipedia.org/w/index.php?title=%E5%A4%A7%E5%8D%AB%C2%B7%E6%83%A0%E5%8B%92&action=edit&redlink=1)与[罗杰·尼达姆](https://zh.wikipedia.org/w/index.php?title=%E7%BD%97%E6%9D%B0%C2%B7%E5%B0%BC%E8%BE%BE%E5%A7%86&action=edit&redlink=1)。



参考代码：

```c
#include <stdint.h>

void encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void decrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;                                   
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}
```



在 Tea 算法中其最主要的识别特征就是 拥有一个 image number ：0x9e3779b9 。当然，这 Tea 算法也有魔改的，感兴趣的可以看 2018 0ctf Quals milk-tea。
