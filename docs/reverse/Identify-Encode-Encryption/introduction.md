[EN](./introduction.md) | [ZH](./introduction-zh.md)
---

typora-root-url: ../../../docs

---

## Foreword


In the process of transforming data, in addition to simple byte operations, some common encoding and encryption algorithms are used, so if the corresponding encoding or encryption algorithm can be quickly identified, the entire integrity can be analyzed more quickly. Algorithm. Encryption algorithms commonly found in CTF reversals include base64, TEA, AES, RC4, MD5, and so on.


## Base64


Base64 is a representation of binary data based on 64 printable characters. When converting, put 3 bytes of data into a 24-bit buffer, and the first byte occupies the high position. If the data is less than 3 bytes, the remaining bits in the buffer are complemented by 0. Take 6 bits each time (because![{\displaystyle 2^{6}=64}](https://wikimedia.org/api/rest_v1/media/math/render/svg/c4becc8d811901597b9807eccff60f0897e3701a)), select by value `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ The characters in ` are used as encoded output until all input data conversion is completed.










In general, the recognition feature of Base64 is the index table. When we can find the index table of `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ `, we can basically determine the Base64 encoding through simple analysis.


![](http://ob2hrvcxg.bkt.clouddn.com/20180822140744.png)







Of course, some index base64 index tables will change, some variants of base64 mainly modify the index table.










## Tea



In [Cryptography] (https://zh.wikipedia.org/wiki/%E5%AF%86%E7%A0%81%E5%AD%A6), **Micro Encryption Algorithm** , TEA) is an easy to describe and [execute] (https://zh.wikipedia.org/w/index.php?title=%E6%89%A7%E8%A1%8C&amp;action=edit&amp;redlink=1) Block password] (https://zh.wikipedia.org/wiki/%E5%A1%8A%E5%AF%86%E7%A2%BC), usually only requires a small amount of code to achieve. The designer is [Cambridge University Computer Lab] (https://en.wikipedia.org/wiki/%E5%89%91%E6%A1%A5%E5%A4%A7%E5%AD%A6) [David Wheeler] (https://en.wikipedia.org/w/index.php?title=%E5%A4%A7%E5%8D%AB%C2%B7%E6%83%A0%E5 %8B%92&amp;action=edit&amp;redlink=1) with [Roger Niddam] (https://en.wikipedia.org/w/index.php?title=%E7%BD%97%E6%9D%B0% C2%B7%E5%B0%BC%E8%BE%BE%E5%A7%86&amp;action=edit&amp;redlink=1).






Reference Code:


```c

#include <stdint.h>



void encrypt (uint32_t* v, uint32_t* k) {

    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */

    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */

uint32_t k0 = k [0], k1 = k [1], k2 = k [2], k3 = k [3]; / * cache key * /
    for (i=0; i < 32; i++) {                       /* basic cycle start */

sum + = delta;
v0 + = ((v1 &lt;&lt; 4) + k0) ^ (v1 + sum) ^ ((v1 &gt;&gt; 5) + k1);
v1 + = ((v0 &lt;&lt; 4) + k2) ^ (v0 + sum) ^ ((v0 &gt;&gt; 5) + k3);
    }                                              /* end cycle */

v [0] = v0; v [1] = v1;
}



void decrypt (uint32_t* v, uint32_t* k) {

uint32_t v0 = v [0], v1 = v [1], sum = 0xC6EF3720, i; / * set up * /
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */

uint32_t k0 = k [0], k1 = k [1], k2 = k [2], k3 = k [3]; / * cache key * /
    for (i=0; i<32; i++) {                         /* basic cycle start */

v1 - = ((v0 &lt;&lt; 4) + k2) ^ (v0 + sum) ^ ((v0 &gt;&gt; 5) + k3);
v0 - = ((v1 &lt;&lt; 4) + k0) ^ (v1 + sum) ^ ((v1 &gt;&gt; 5) + k1);
sum - = delta;
    }                                              /* end cycle */

v [0] = v0; v [1] = v1;
}

```







The main recognition feature in the Tea algorithm is to have an image number : 0x9e3779b9 . Of course, this Tea algorithm also has a magic change, interested can see 2018 0ctf Quals milk-tea.










## RC4



In [Cryptography] (https://zh.wikipedia.org/wiki/%E5%AF%86%E7%A2%BC%E5%AD%B8), **RC4** (from Rivest Cipher 4 Abbreviation) is a [stream encryption] (https://zh.wikipedia.org/wiki/%E6%B5%81%E5%8A%A0%E5%AF%86) algorithm, [key] (https: //zh.wikipedia.org/wiki/%E5%AF%86%E9%92%A5) Variable length. It uses the same key for encryption and decryption, so it also belongs to [symmetric encryption algorithm] (https://zh.wikipedia.org/wiki/%E5%AF%B9%E7%A7%B0%E5%8A%A0%E5 %AF%86). RC4 is [Wired Equivalent Encryption] (https://en.wikipedia.org/wiki/%E6%9C%89%E7%B7%9A%E7%AD%89%E6%95%88%E5%8A% The encryption algorithm used in A0%E5%AF%86) (WEP) was also [TLS] (https://zh.wikipedia.org/wiki/%E4%BC%A0%E8%BE%93%E5 %B1%82%E5%AE%89%E5%85%A8%E5%8D%8F%E8%AE%AE) One of the algorithms that can be used.






```C

Void rc4_init(unsigned char *s, unsigned char *key, unsigned long Len) //Initialization function
{

    int i =0, j = 0;

char k [256] = {0};
    unsigned char tmp = 0;

    for (i=0;i<256;i++) {

        s[i] = i;

k [i] = key [i% Len];
    }

    for (i=0; i<256; i++) {

        j=(j+s[i]+k[i])%256;

        tmp = s[i];

s[i] = s[j]; //exchange s[i] and s[j]
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

s[i] = s[j]; // swap s[x] and s[y]
        s[j] = tmp;

        t=(s[i]+s[j])%256;

        Data[k] ^= s[t];

     }

} 

```



By analyzing the initialization code, it can be seen that in the initialization code, the character array s is initialized and assigned, and the assignment values are incremented. Then 256 exchange operations were performed on s. The rc4 algorithm can be known by identifying the initialization code.


Its pseudo code is expressed as:


Initialize [S box] with a length of 256 (https://zh.wikipedia.org/wiki/S%E7%9B%92). The first for loop loads 0 to 255 non-repeating elements into the S box. The second for loop scrambles the S box based on the key.


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



Below i, j are two pointers. Each time a byte is received, a while loop is performed. An element in the S box is located by a certain algorithm ((a), (b)) and XORed with the input byte to obtain k. The S box ((c)) is also changed in the loop. If the input is [plain text] (https://zh.wikipedia.org/wiki/%E6%98%8E%E6%96%87), the output is [ciphertext] (https://zh.wikipedia. Org/wiki/%E5%AF%86%E6%96%87); if the input is ciphertext, the output is plaintext.


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



This algorithm guarantees that each element of the S box is exchanged at least once every 256 cycles.






## MD5



**MD5 Message-Digest Algorithm**, a widely used [cryptographic hash function] (https://en.wikipedia.org/wiki/%E5%AF%86%) E7%A2%BC%E9%9B%9C%E6%B9%8A%E5%87%BD%E6%95%B8), can produce a 128-bit (16 [bytes] (https://zh. wikipedia.org/wiki/%E5%AD%97%E8%8A%82)) The hash value used to ensure complete and consistent information transfer. MD5 by American cryptographer [Ronald Levist] (https://en.wikipedia.org/wiki/%E7%BD%97%E7%BA%B3%E5%BE%B7%C2%B7% E6%9D%8E%E7%BB%B4%E6%96%AF%E7%89%B9) (Ronald Linn Rivest) designed to be published in 1992 to replace [MD4] (https://en.wikipedia .org/wiki/MD4) algorithm. The program for this algorithm is specified in [RFC 1321] (https://tools.ietf.org/html/rfc1321).






The pseudo code is expressed as:


```

/Note: All variables are unsigned 32 bits and wrap modulo 2^32 when calculating

was int [64] r, k


//r specifies the per-round shift amounts

r[ 0..15]：= {7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22} 

r[16..31]：= {5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20}

r[32..47]：= {4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23}

r[48..63]：= {6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21}



//Use binary integer part of the sines of integers as constants:

for i from 0 to 63

    k[i] := floor(abs(sin(i + 1)) × 2^32)



//Initialize variables:

was int h0: = 0x67452301
was int h1: = 0xEFCDAB89
was int h2: = 0x98BADCFE
was int h3: = 0x10325476


//Pre-processing:

append "1" bit to message

append "0" bits until message length in bits ≡ 448 (mod 512)

append bit length of message as 64-bit little-endian integer to message



//Process the message in successive 512-bit chunks:

for each 512-bit chunk of message

    break chunk into sixteen 32-bit little-endian words w[i], 0 ≤ i ≤ 15



    //Initialize hash value for this chunk:

var int a: = h0
was int b: = h1
was int c: = h2
var int d: = h3


    //Main loop:

    for i from 0 to 63

        if 0 ≤ i ≤ 15 then

            f := (b and c) or ((not b) and d)

g: = i
        else if 16 ≤ i ≤ 31

            f := (d and b) or ((not d) and c)

g: = (5 × i + 1) vs. 16
        else if 32 ≤ i ≤ 47

            f := b xor c xor d

g: = (3 × i + 5) vs. 16
        else if 48 ≤ i ≤ 63

            f := c xor (b or (not d))

g: = (7 × i) vs. 16
 

        temp := d

        d := c

        c := b

        b := leftrotate((a + f + k[i] + w[g]),r[i]) + b

        a := temp

    Next i

    //Add this chunk's hash to result so far:

    h0 := h0 + a

h1: = h1 + b
    h2 := h2 + c

    h3 := h3 + d

End ForEach

var int digest := h0 append h1 append h2 append h3 //(expressed as little-endian)

```



Its distinctive features are:


```c

    h0 = 0x67452301;

    h1 = 0xefcdab89;

    h2 = 0x98badcfe;

    h3 = 0x10325476;

```


