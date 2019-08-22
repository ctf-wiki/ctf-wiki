[EN](./dsa.md) | [ZH](./dsa-zh.md)
# DSA


The ElGamal signature algorithm described above is not commonly used in practice, and its variant DSA is more commonly used.


## Fundamental


### Key Generation


1. Select a suitable hash function. Currently, SHA1 is generally selected. Currently, a stronger hash function H can be selected.
2. Select the length L and N of the key, which determine the security of the signature. In the original DSS (**Digital Signature Standard**) it was suggested that L must be a multiple of 64, and $512 \leq L \leq 1024$, of course, can be larger. The N must be no larger than the length of the hash function H output. FIPS 186-3 gives some suggested examples of L and N values: (1024, 160), (2048, 224), (2048, 256), and (3, 072, 256).
3. Select the prime number q of N bits.
4. Select the prime number p of L bits such that p-1 is a multiple of q.
5. Select the g that satisfies the minimum positive integer k of $g^k \equiv 1 \bmod p$ as q, ie g in the background of modulo p, ord(g)=q. That is, in the sense of modulo p, its exponential power can generate subgroups with q elements. Here, we can get g by calculating $g=h^{\frac{p-1}{q}} \bmod p$, where $1&lt; h &lt; p-1$ .
6. Select private key x, $0 <x<q$ ，计算$y \equiv g^x \bmod p$ 。


The public key is (p, q, g, y) and the private key is (x).


### Signature


The signature steps are as follows


1. Select the random integer number k as the temporary key, $0 <k<q$ 。
2. Calculate $r\equiv (g^k \bmod p) \bmod q$
3. Calculate $s\equiv (H(m)+xr)k^{-1} \bmod q$


The result of the signature is (r, s). It should be noted that the important difference here with Elgamal is that the hash function is used to hash the message.


### Verification


The verification process is as follows


1. Calculate the auxiliary value, $w=s^{-1} \bmod q$
2. Calculate the auxiliary value, $u_1=H(m)w \bmod q$
3. Calculate the auxiliary value, $u_2=rw \bmod q$
4. 计算 $ v = (g ^ y ^ {} {u_1 u_2} \ way p) \ $ q way
5. If v is equal to r, the verification is successful.


### Correctness derivation


First, g satisfies the minimum positive integer k of $g^k \equiv 1 \bmod p$ as q. So $g^q \equiv 1 \bmod p$ . So $g^x \equiv g^{x \bmod q} \bmod p$ . and then


$v=(g^{u_1}y^{u_2} \bmod p) \bmod q=g^{u_1}g^{xu_2} \equiv g^{H(m)w}g^{xrw} \equiv g^{H(m)w+xrw}$



Also $s\equiv (H(m)+xr)k^{-1} \bmod q$ and $w=s^{-1} \bmod q$


$k \equiv s^{-1}(H(m)+xr) \equiv H(m)w+xrw \bmod q$



So $v \equiv g^k$ . Correctness is proven.


## safety


### Known k


#### Principle


If we know the random key k, then we can calculate the private key d based on $s\equiv (H(m)+xr)k^{-1} \bmod q$, which almost breaks the DSA.


In general, the hash value of the message will be given.


$x \equiv r^{-1}(ks-H(m)) \bmod q$



### k分享


#### Principle


If k is shared during the two signatures, we can attack.


Suppose the signed message is m1, m2, obviously, the values of r are the same, in addition


$s_1\equiv (H(m_1)+xr)k^{-1} \bmod q$



$s_2\equiv (H(m_2)+xr)k^{-1} \bmod q$



Here we don&#39;t know the rest except x and k, then


$s_1k \equiv H(m_1)+xr$



$s_2k \equiv H(m_2)+xr$



Two-type subtraction


$k(s_1-s_2) \equiv H(m_1)-H(m_2) \bmod q$



At this point, we can solve for k, and further we can solve x.


#### Example


Here we take the DSA of the Huxiang Cup as an example, but we can&#39;t do it directly, because we found that the signature did not pass when verifying message4. I have no source questions. , here I take the modified topic DSA in Jarvis OJ as an example.


```shell

➜ 2016 Hunan Cup DSA git: (master) ✗ openssl sha1 -verify dsa_public.pem -signature packet1/sign1.bin packet1/message1
Verified OK

➜ 2016 Hunan Cup DSA git: (master) ✗ openssl sha1 -verify dsa_public.pem -signature packet2/sign2.bin packet2/message1
packet2/message1: No such file or directory

➜  2016湖湘杯DSA git:(master) ✗ openssl sha1 -verify dsa_public.pem -signature packet2/sign2.bin  packet2/message2 

Verified OK

➜  2016湖湘杯DSA git:(master) ✗ openssl sha1 -verify dsa_public.pem -signature packet3/sign3.bin  packet3/message3 

Verified OK

➜  2016湖湘杯DSA git:(master) ✗ openssl sha1 -verify dsa_public.pem -signature packet4/sign4.bin  packet4/message4

Verified OK

```



It can be seen that all four messages are verified. The reason why I think of sharing k here is because the title of the PS3 has been used to crack this method, from the online search can know the attack.


Below, let&#39;s take a look at the signed value, the command used here is as follows


```shell

➜ 2016 Huxiang Cup DSA git: (master) ✗ openssl asn1parse -inform der -in packet4/sign4.bin
    0:d=0  hl=2 l=  44 cons: SEQUENCE          

2: d = 1 hl = 2 = 20 prime: INTEGER: 5090DA81FEDE048D706D80E0AC47701E5A9EF1CC
   24:d=1  hl=2 l=  20 prim: INTEGER           :5E10DED084203CCBCEC3356A2CA02FF318FD4123

➜ 2016 Huxiang Cup DSA git: (master) ✗ openssl asn1parse -inform der -in packet3/sign3.bin
    0:d=0  hl=2 l=  44 cons: SEQUENCE          

2: d = 1 hl = 2 = 20 prime: INTEGER: 5090DA81FEDE048D706D80E0AC47701E5A9EF1CC
24: d = 1 hl = 2 l = 20 prim: INTEGER: 30EB88E6A4BFB1B16728A974210AE4E41B42677D
➜ 2016 Hunan Cup DSA git: (master) ✗ openssl asn1parse -inform der -in packet2/sign2.bin
    0:d=0  hl=2 l=  44 cons: SEQUENCE          

2: d = 1 hl = 2 l = 20 prim: INTEGER: 60B9F2A5BA689B802942D667ED5D1EED066C5A7F
24: d = 1 hl = 2 l = 20 prim: INTEGER: 3DC8921BA26B514F4D991A85482750E0225A15B5
➜ 2016 Hunan Cup DSA git: (master) ✗ openssl asn1parse -inform der -in packet1/sign1.bin
    0:d=0  hl=2 l=  45 cons: SEQUENCE          

2: d = 1 hl = 2 l = 21 prim: INTEGER: 8158B477C5AA033D650596E93653C730D26BA409
25: d = 1 hl = 2 l = 20 prim: INTEGER: 165B9DD1C93230C31111E5A4E6EB5181F990F702


```



Among them, the first value obtained is r, and the second value is s. You can see that the 4th packet and the 3rd packet share k because their r is the same.

Here we can use openssl to see the public key


```shell

➜ 2016 Hunan Cup DSA git: (master) ✗ openssl dsa -in dsa_public.pem -text -noout -pubin
read DSA key

pub: 

45: bb: 18: f6: 0e: b0: 51: f9: d4: 8c: d9: 56:
    33:0a:4f:f3:0a:f5:34:4f:6c:95:40:06:1d:53:83:

29: 2d: 95: c4: df: c8: ac: 26: c: 45: 2e: 17:
e: 5c: c6: 15: 9e: 03: 7b: cc: f5: 64: ef: 36: 1c: 18: c9:
: 9: 8: 1: 2: 1: 2: 1: 6: 1: 1: 6: 1: 1: 60: bb: 73: 0d: 60: bb: 73: 0: 60: 1: 2
    11:f1:cf:08:cf:bc:34:cc:aa:79:ef:1d:ad:8a:7a:

6f: ac: it: 86: 65: 90: 06: d4: fa: f0: 57: 71: 68: 57: ec:
7c: a6: 04: ad: e2: c3: d7: 31: d6: d0: 2f: 93: 31: 98: d3:
90: c3: ef: c3: f3: ff: 04: 6f
P:   

    00:c0:59:6c:3b:5e:93:3d:33:78:be:36:26:be:31:

5e: e7: 0c: a6: b5: b1: 1a: 51: 9b: 55: 23: d4:
45: 66: e2: 2c: c8: 8b: f: c5: 6a: ad: 66:
    ad:28:13:88:f0:bb:c6:b8:02:6b:7c:80:26:e9:11:

    84:be:e0:c8:ad:10:cc:f2:96:be:cf:e5:05:05:38:

3c: b4: a9: 54: b3: 7c: b5: 88: 67: 2f: 7c:
f2: fa: 05: 38: fd: ad: 83: 93: 4a: 45: e4: f9: 9d: 38: from:
    57:c0:8a:24:d0:0d:1c:c5:d5:fb:db:73:29:1c:d1:

0c: e7: 57: 68: 90: b6: ba: 08: 9b
Q:   

00: 86: 8f: 78: b8: c8: 50: 0b: eb: f6: 7a: 58: e3:
53: 9d: 35: 70: d1: bd
G:   

4c: d5: e6: b6: 6a: 6e: b7: e9: 27: 94:
cb: 11: af: 5a: 08: d9: d4: f8: a3: f2: 50: 03: 72: 91: ba:
5f: ff: 3c: 29: a8: c3: 7b: c4: ee: 5f: 98: ec: 17: f4: 18:
bc: 71: 61: 01: 6c: 94: c8: 49: 02: e4: 00:
    d8:cf:6a:61:c1:3a:fd:56:73:ca:a5:fb:41:15:08:

    cd:b3:50:1b:df:f7:3e:74:79:25:f7:65:86:f4:07:

9f: it: 12: 09: 8b: 34: 50: 84: 4: 2: 9e: 5d: 0A: 99: bd:
86: 5: 05: 70: d5: 19: 7d: f4: a1: c9: b8: 01: 8f: b9: 9c:
dc: e9: 15: 7b: 98: 50: 01: 79
```



Below, we can directly use the above principle to write a program, the program is as follows


```python

#coding=utf8

from Crypto.PublicKey import DSA

from hashlib import sha1

import gmpy2

with open('./dsa_public.pem') as f:

    key = DSA.importKey(f)

y = key.y
    g = key.g

    p = key.p

    q = key.q

f3 = open(r"packet3/message3", 'r')

f4 = open(r"packet4/message4", 'r')

data3 = f3.read ()
data4 = f4.read()

Sha = sha1()
sha.update(data3)

m3 = int (sha.hexdigest (), 16)
Sha = sha1()
sha.update(data4)

m4 = int (sha.hexdigest (), 16)
print m3, m4
s3 = 0x30EB88E6A4BFB1B16728A974210AE4E41B42677D
s4 = 0x5E10DED084203CCBCEC3356A2CA02FF318FD4123
r = 0x5090DA81FEDE048D706D80E0AC47701E5A9EF1CC

ds = s4 - s3
dm = m4 - m3
k = gmpy2.mul(dm, gmpy2.invert(ds, q))

k = gmpy2.f_mod(k, q)

tmp = gmpy2.mul (k, s3) - m3
x = tmp * gmpy2.invert(r, q)

x = gmpy2.f_mod(x, q)

print int(x)

```



** I found that pycrypto installed by pip does not have the importKey function of DSA. . . I had to download and install pycrypto from github. . . **


Results are as follows


```shell

➜ 2016 Huxiang Cup DSA git: (master) ✗ python exp.py
1104884177962524221174509726811256177146235961550 943735132044536149000710760545778628181961840230

520793588153805320783422521615148687785086070744

```


