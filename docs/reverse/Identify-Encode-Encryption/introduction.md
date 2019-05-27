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





## RC4

在[密码学](https://zh.wikipedia.org/wiki/%E5%AF%86%E7%A2%BC%E5%AD%B8)中，**RC4**（来自Rivest Cipher 4的缩写）是一种[流加密](https://zh.wikipedia.org/wiki/%E6%B5%81%E5%8A%A0%E5%AF%86)算法，[密钥](https://zh.wikipedia.org/wiki/%E5%AF%86%E9%92%A5)长度可变。它加解密使用相同的密钥，因此也属于[对称加密算法](https://zh.wikipedia.org/wiki/%E5%AF%B9%E7%A7%B0%E5%8A%A0%E5%AF%86)。RC4是[有线等效加密](https://zh.wikipedia.org/wiki/%E6%9C%89%E7%B7%9A%E7%AD%89%E6%95%88%E5%8A%A0%E5%AF%86)（WEP）中采用的加密算法，也曾经是[TLS](https://zh.wikipedia.org/wiki/%E4%BC%A0%E8%BE%93%E5%B1%82%E5%AE%89%E5%85%A8%E5%8D%8F%E8%AE%AE)可采用的算法之一。



```C
void rc4_init(unsigned char *s, unsigned char *key, unsigned long Len) //初始化函数
{
    int i =0, j = 0;
    char k[256] = {0};
    unsigned char tmp = 0;
    for (i=0;i<256;i++) {
        s[i] = i;
        k[i] = key[i%Len];
    }
    for (i=0; i<256; i++) {
        j=(j+s[i]+k[i])%256;
        tmp = s[i];
        s[i] = s[j]; //交换s[i]和s[j]
        s[j] = tmp;
    }
 }

void rc4_crypt(unsigned char *s, unsigned char *Data, unsigned long Len) //加解密
{
    int i = 0, j = 0, t = 0;
    unsigned long k = 0;
    unsigned char tmp;
    for(k=0;k<Len;k++) {
        i=(i+1)%256;
        j=(j+s[i])%256;
        tmp = s[i];
        s[i] = s[j]; //交换s[x]和s[y]
        s[j] = tmp;
        t=(s[i]+s[j])%256;
        Data[k] ^= s[t];
     }
} 
```

通过分析初始化代码，可以看出初始化代码中，对字符数组s进行了初始化赋值，且赋值分别递增。之后对s进行了256次交换操作。通过识别初始化代码，可以知道rc4算法。

其伪代码表示为：

初始化长度为256的[S盒](https://zh.wikipedia.org/wiki/S%E7%9B%92)。第一个for循环将0到255的互不重复的元素装入S盒。第二个for循环根据密钥打乱S盒。

```c
  for i from 0 to 255
     S[i] := i
 endfor
 j := 0
 for( i=0 ; i<256 ; i++)
     j := (j + S[i] + key[i mod keylength]) % 256
     swap values of S[i] and S[j]
 endfor
```

下面i,j是两个指针。每收到一个字节，就进行while循环。通过一定的算法（(a),(b)）定位S盒中的一个元素，并与输入字节异或，得到k。循环中还改变了S盒（(c)）。如果输入的是[明文](https://zh.wikipedia.org/wiki/%E6%98%8E%E6%96%87)，输出的就是[密文](https://zh.wikipedia.org/wiki/%E5%AF%86%E6%96%87)；如果输入的是密文，输出的就是明文。

```c
 i := 0
 j := 0
 while GeneratingOutput:
     i := (i + 1) mod 256   //a
     j := (j + S[i]) mod 256 //b
     swap values of S[i] and S[j]  //c
     k := inputByte ^ S[(S[i] + S[j]) % 256]
     output K
 endwhile
```

此算法保证每256次循环中S盒的每个元素至少被交换过一次



## MD5

**MD5消息摘要算法**（英语：MD5 Message-Digest Algorithm），一种被广泛使用的[密码散列函数](https://zh.wikipedia.org/wiki/%E5%AF%86%E7%A2%BC%E9%9B%9C%E6%B9%8A%E5%87%BD%E6%95%B8)，可以产生出一个128位（16[字节](https://zh.wikipedia.org/wiki/%E5%AD%97%E8%8A%82)）的散列值（hash value），用于确保信息传输完整一致。MD5由美国密码学家[罗纳德·李维斯特](https://zh.wikipedia.org/wiki/%E7%BD%97%E7%BA%B3%E5%BE%B7%C2%B7%E6%9D%8E%E7%BB%B4%E6%96%AF%E7%89%B9)（Ronald Linn Rivest）设计，于1992年公开，用以取代[MD4](https://zh.wikipedia.org/wiki/MD4)算法。这套算法的程序在 [RFC 1321](https://tools.ietf.org/html/rfc1321) 中被加以规范。



伪代码表示为：

```
/Note: All variables are unsigned 32 bits and wrap modulo 2^32 when calculating
var int[64] r, k

//r specifies the per-round shift amounts
r[ 0..15]：= {7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22} 
r[16..31]：= {5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20}
r[32..47]：= {4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23}
r[48..63]：= {6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21}

//Use binary integer part of the sines of integers as constants:
for i from 0 to 63
    k[i] := floor(abs(sin(i + 1)) × 2^32)

//Initialize variables:
var int h0 := 0x67452301
var int h1 := 0xEFCDAB89
var int h2 := 0x98BADCFE
var int h3 := 0x10325476

//Pre-processing:
append "1" bit to message
append "0" bits until message length in bits ≡ 448 (mod 512)
append bit length of message as 64-bit little-endian integer to message

//Process the message in successive 512-bit chunks:
for each 512-bit chunk of message
    break chunk into sixteen 32-bit little-endian words w[i], 0 ≤ i ≤ 15

    //Initialize hash value for this chunk:
    var int a := h0
    var int b := h1
    var int c := h2
    var int d := h3

    //Main loop:
    for i from 0 to 63
        if 0 ≤ i ≤ 15 then
            f := (b and c) or ((not b) and d)
            g := i
        else if 16 ≤ i ≤ 31
            f := (d and b) or ((not d) and c)
            g := (5×i + 1) mod 16
        else if 32 ≤ i ≤ 47
            f := b xor c xor d
            g := (3×i + 5) mod 16
        else if 48 ≤ i ≤ 63
            f := c xor (b or (not d))
            g := (7×i) mod 16
 
        temp := d
        d := c
        c := b
        b := leftrotate((a + f + k[i] + w[g]),r[i]) + b
        a := temp
    Next i
    //Add this chunk's hash to result so far:
    h0 := h0 + a
    h1 := h1 + b 
    h2 := h2 + c
    h3 := h3 + d
End ForEach
var int digest := h0 append h1 append h2 append h3 //(expressed as little-endian)
```

其鲜明的特征是：

```c
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
```

