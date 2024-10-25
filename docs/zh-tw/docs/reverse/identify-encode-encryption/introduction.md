# 常見加密算法和編碼識別

## 前言

在對數據進行變換的過程中，除了簡單的字節操作之外，還會使用一些常用的編碼加密算法，因此如果能夠快速識別出對應的編碼或者加密算法，就能更快的分析出整個完整的算法。CTF 逆向中通常出現的加密算法包括base64、TEA、AES、RC4、MD5等。

## Base64

Base64 是一種基於64個可打印字符來表示二進制數據的表示方法。轉換的時候，將3字節的數據，先後放入一個24位的緩衝區中，先來的字節佔高位。數據不足3字節的話，於緩衝器中剩下的比特用0補足。每次取出6比特（因爲 ![{\displaystyle 2^{6}=64}](https://wikimedia.org/api/rest_v1/media/math/render/svg/c4becc8d811901597b9807eccff60f0897e3701a)），按照其值選擇`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ `中的字符作爲編碼後的輸出，直到全部輸入數據轉換完成。





通常而言 Base64 的識別特徵爲索引表，當我們能找到 `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ ` 這樣索引表，再經過簡單的分析基本就能判定是 Base64 編碼。

![](http://ob2hrvcxg.bkt.clouddn.com/20180822140744.png)



當然，有些題目 base64 的索引表是會變的，一些變種的 base64 主要 就是修改了這個索引表。





## Tea

在[密碼學](https://zh.wikipedia.org/wiki/%E5%AF%86%E7%A0%81%E5%AD%A6)中，**微型加密算法**（Tiny Encryption Algorithm，TEA）是一種易於描述和[執行](https://zh.wikipedia.org/w/index.php?title=%E6%89%A7%E8%A1%8C&action=edit&redlink=1)的[塊密碼](https://zh.wikipedia.org/wiki/%E5%A1%8A%E5%AF%86%E7%A2%BC)，通常只需要很少的代碼就可實現。其設計者是[劍橋大學計算機實驗室](https://zh.wikipedia.org/wiki/%E5%89%91%E6%A1%A5%E5%A4%A7%E5%AD%A6)的[大衛·惠勒](https://zh.wikipedia.org/w/index.php?title=%E5%A4%A7%E5%8D%AB%C2%B7%E6%83%A0%E5%8B%92&action=edit&redlink=1)與[羅傑·尼達姆](https://zh.wikipedia.org/w/index.php?title=%E7%BD%97%E6%9D%B0%C2%B7%E5%B0%BC%E8%BE%BE%E5%A7%86&action=edit&redlink=1)。



參考代碼：

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



在 Tea 算法中其最主要的識別特徵就是 擁有一個 magic number ：0x9e3779b9 。當然，這 Tea 算法也有魔改的，感興趣的可以看 2018 0ctf Quals milk-tea。





## RC4

在[密碼學](https://zh.wikipedia.org/wiki/%E5%AF%86%E7%A2%BC%E5%AD%B8)中，**RC4**（來自Rivest Cipher 4的縮寫）是一種[流加密](https://zh.wikipedia.org/wiki/%E6%B5%81%E5%8A%A0%E5%AF%86)算法，[密鑰](https://zh.wikipedia.org/wiki/%E5%AF%86%E9%92%A5)長度可變。它加解密使用相同的密鑰，因此也屬於[對稱加密算法](https://zh.wikipedia.org/wiki/%E5%AF%B9%E7%A7%B0%E5%8A%A0%E5%AF%86)。RC4是[有線等效加密](https://zh.wikipedia.org/wiki/%E6%9C%89%E7%B7%9A%E7%AD%89%E6%95%88%E5%8A%A0%E5%AF%86)（WEP）中採用的加密算法，也曾經是[TLS](https://zh.wikipedia.org/wiki/%E4%BC%A0%E8%BE%93%E5%B1%82%E5%AE%89%E5%85%A8%E5%8D%8F%E8%AE%AE)可採用的算法之一。



```C
void rc4_init(unsigned char *s, unsigned char *key, unsigned long Len) //初始化函數
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
        s[i] = s[j]; //交換s[i]和s[j]
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
        s[i] = s[j]; //交換s[x]和s[y]
        s[j] = tmp;
        t=(s[i]+s[j])%256;
        Data[k] ^= s[t];
     }
} 
```

通過分析初始化代碼，可以看出初始化代碼中，對字符數組s進行了初始化賦值，且賦值分別遞增。之後對s進行了256次交換操作。通過識別初始化代碼，可以知道rc4算法。

其僞代碼表示爲：

初始化長度爲256的[S盒](https://zh.wikipedia.org/wiki/S%E7%9B%92)。第一個for循環將0到255的互不重複的元素裝入S盒。第二個for循環根據密鑰打亂S盒。

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

下面i,j是兩個指針。每收到一個字節，就進行while循環。通過一定的算法（(a),(b)）定位S盒中的一個元素，並與輸入字節異或，得到k。循環中還改變了S盒（(c)）。如果輸入的是[明文](https://zh.wikipedia.org/wiki/%E6%98%8E%E6%96%87)，輸出的就是[密文](https://zh.wikipedia.org/wiki/%E5%AF%86%E6%96%87)；如果輸入的是密文，輸出的就是明文。

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

此算法保證每256次循環中S盒的每個元素至少被交換過一次



### python解密腳本

對應例題：《從 0 到 1》RE 篇——BabyAlgorithm

[題目鏈接](https://buuoj.cn/challenges#[%E7%AC%AC%E4%BA%94%E7%AB%A0%20CTF%E4%B9%8BRE%E7%AB%A0]BabyAlgorithm)

```python
import base64
def rc4_main(key = "init_key", message = "init_message"):
    print("RC4解密主函數調用成功")
    print('\n')
    s_box = rc4_init_sbox(key)
    crypt = rc4_excrypt(message, s_box)
    return crypt
def rc4_init_sbox(key):
    s_box = list(range(256))
    print("原來的 s 盒：%s" % s_box)
    print('\n')
    j = 0
    for i in range(256):
        j = (j + s_box[i] + ord(key[i % len(key)])) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
    print("混亂後的 s 盒：%s"% s_box)
    print('\n')
    return s_box
def rc4_excrypt(plain, box):
    print("調用解密程序成功。")
    print('\n')
    plain = base64.b64decode(plain.encode('utf-8'))
    plain = bytes.decode(plain)
    res = []
    i = j = 0
    for s in plain:
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        t = (box[i] + box[j]) % 256
        k = box[t]
        res.append(chr(ord(s) ^ k))
    print("res用於解密字符串，解密後是：%res" %res)
    print('\n')
    cipher = "".join(res)
    print("解密後的字符串是：%s" %cipher)
    print('\n')
    print("解密後的輸出(沒經過任何編碼):")
    print('\n')
    return cipher
a=[] #cipher
key=""
s=""
for i in a:
    s+=chr(i)
s=str(base64.b64encode(s.encode('utf-8')), 'utf-8')
rc4_main(key, s)
```

## MD5

**MD5消息摘要算法**（英語：MD5 Message-Digest Algorithm），一種被廣泛使用的[密碼散列函數](https://zh.wikipedia.org/wiki/%E5%AF%86%E7%A2%BC%E9%9B%9C%E6%B9%8A%E5%87%BD%E6%95%B8)，可以產生出一個128位（16[字節](https://zh.wikipedia.org/wiki/%E5%AD%97%E8%8A%82)）的散列值（hash value），用於確保信息傳輸完整一致。MD5由美國密碼學家[羅納德·李維斯特](https://zh.wikipedia.org/wiki/%E7%BD%97%E7%BA%B3%E5%BE%B7%C2%B7%E6%9D%8E%E7%BB%B4%E6%96%AF%E7%89%B9)（Ronald Linn Rivest）設計，於1992年公開，用以取代[MD4](https://zh.wikipedia.org/wiki/MD4)算法。這套算法的程序在 [RFC 1321](https://tools.ietf.org/html/rfc1321) 中被加以規範。



僞代碼表示爲：

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

其鮮明的特徵是：

```c
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
```
