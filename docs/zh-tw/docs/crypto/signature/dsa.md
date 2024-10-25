# DSA

上面所描述的ElGamal簽名算法在實際中並不常用，更常用的是其變體DSA。

## 基本原理

### 密鑰生成

1. 選擇一個合適的哈希函數，目前一般選擇SHA1，當前也可以選擇強度更高的哈希函數H。
2. 選擇密鑰的長度L和N，這兩個值決定了簽名的安全程度。在最初的DSS（**Digital Signature Standard** ）中建議L必須爲64的倍數，並且$512 \leq L \leq 1024$ ，當然，也可以更大。N必須大小必須不大於哈希函數H輸出的長度。FIPS 186-3給出了一些建議的L和N的取值例子：(1024, 160)， (2048, 224)， (2048, 256)，以及 (3,072, 256)。
3. 選擇N比特的素數q。
4. 選擇L比特的素數p，使得p-1是q的倍數。
5. 選擇滿足$g^k \equiv 1 \bmod p$ 的最小正整數k爲q的g，即在模p的背景下，ord(g)=q的g。即g在模p的意義下，其指數次冪可以生成具有q個元素的子羣。這裏，我們可以通過計算$g=h^{\frac{p-1}{q}} \bmod p$ 來得到g，其中$1< h < p-1$ 。
6. 選擇私鑰x，$0<x<q$ ，計算$y \equiv g^x \bmod p$ 。

公鑰爲(p,q,g,y)，私鑰爲(x)。

### 簽名

簽名步驟如下

1. 選擇隨機整數數k作爲臨時密鑰，$0<k<q$ 。
2. 計算$r\equiv (g^k \bmod p) \bmod q$
3. 計算$s\equiv (H(m)+xr)k^{-1} \bmod q$

簽名結果爲(r,s)。需要注意的是，這裏與Elgamal很重要的不同是這裏使用了哈希函數對消息進行了哈希處理。

### 驗證

驗證過程如下

1. 計算輔助值，$w=s^{-1} \bmod q$
2. 計算輔助值，$u_1=H(m)w \bmod q$
3. 計算輔助值，$u_2=rw \bmod q$
4. 計算$v=(g^{u_1}y^{u_2} \bmod p) \bmod q$
5. 如果v與r相等，則校驗成功。

### 正確性推導

首先，g 滿足 $g^k \equiv 1 \bmod p$ 的最小正整數k爲q。所以 $g^q \equiv 1 \bmod p$  。所以 $g^x \equiv g^{x \bmod q} \bmod p$ 。進而

$v=(g^{u_1}y^{u_2} \bmod p) \bmod q=g^{u_1}g^{xu_2} \equiv g^{H(m)w}g^{xrw} \equiv g^{H(m)w+xrw}$

又$s\equiv (H(m)+xr)k^{-1} \bmod q$ 且$w=s^{-1} \bmod q$ 所以

$k \equiv s^{-1}(H(m)+xr) \equiv H(m)w+xrw \bmod q$

所以$v \equiv g^k$ 。正確性得證。

## 安全性

### 已知k

#### 原理

如果知道了隨機密鑰k，那麼我們就可以根據$s\equiv (H(m)+xr)k^{-1} \bmod q$ 計算私鑰d，幾乎攻破了DSA。

這裏一般情況下，消息的hash值都會給出。

$x \equiv r^{-1}(ks-H(m)) \bmod q$

### k共享

#### 原理

如果在兩次簽名的過程中共享了k，我們就可以進行攻擊。

假設簽名的消息爲m1,m2，顯然，兩者的r的值一樣，此外

$s_1\equiv (H(m_1)+xr)k^{-1} \bmod q$

$s_2\equiv (H(m_2)+xr)k^{-1} \bmod q$

這裏我們除了x和k不知道剩下的均知道，那麼

$s_1k \equiv H(m_1)+xr$

$s_2k \equiv H(m_2)+xr$

兩式相減

$k(s_1-s_2) \equiv H(m_1)-H(m_2) \bmod q$

此時 即可解出k，進一步我們可以解出x。

#### 例子

這裏我們以湖湘杯的DSA爲例，但是不能直接去做，，，因爲發現在驗證message4的時候簽名不通過。源題目我沒有了，。，，這裏我以Jarvis OJ中經過修改的題目DSA爲例

```shell
➜  2016湖湘杯DSA git:(master) ✗ openssl sha1 -verify dsa_public.pem -signature packet1/sign1.bin  packet1/message1  
Verified OK
➜  2016湖湘杯DSA git:(master) ✗ openssl sha1 -verify dsa_public.pem -signature packet2/sign2.bin  packet2/message1 
packet2/message1: No such file or directory
➜  2016湖湘杯DSA git:(master) ✗ openssl sha1 -verify dsa_public.pem -signature packet2/sign2.bin  packet2/message2 
Verified OK
➜  2016湖湘杯DSA git:(master) ✗ openssl sha1 -verify dsa_public.pem -signature packet3/sign3.bin  packet3/message3 
Verified OK
➜  2016湖湘杯DSA git:(master) ✗ openssl sha1 -verify dsa_public.pem -signature packet4/sign4.bin  packet4/message4
Verified OK
```

可以看出四則消息全部校驗通過。這裏之所以會聯想到共享k是因爲題目中提示了PS3的破解曾用到這個方法，從網上搜索可知該攻擊。

下面，我們看一下簽名後的值，這裏使用的命令如下

```shell
➜  2016湖湘杯DSA git:(master) ✗ openssl asn1parse -inform der -in packet4/sign4.bin  
    0:d=0  hl=2 l=  44 cons: SEQUENCE          
    2:d=1  hl=2 l=  20 prim: INTEGER           :5090DA81FEDE048D706D80E0AC47701E5A9EF1CC
   24:d=1  hl=2 l=  20 prim: INTEGER           :5E10DED084203CCBCEC3356A2CA02FF318FD4123
➜  2016湖湘杯DSA git:(master) ✗ openssl asn1parse -inform der -in packet3/sign3.bin  
    0:d=0  hl=2 l=  44 cons: SEQUENCE          
    2:d=1  hl=2 l=  20 prim: INTEGER           :5090DA81FEDE048D706D80E0AC47701E5A9EF1CC
   24:d=1  hl=2 l=  20 prim: INTEGER           :30EB88E6A4BFB1B16728A974210AE4E41B42677D
➜  2016湖湘杯DSA git:(master) ✗ openssl asn1parse -inform der -in packet2/sign2.bin  
    0:d=0  hl=2 l=  44 cons: SEQUENCE          
    2:d=1  hl=2 l=  20 prim: INTEGER           :60B9F2A5BA689B802942D667ED5D1EED066C5A7F
   24:d=1  hl=2 l=  20 prim: INTEGER           :3DC8921BA26B514F4D991A85482750E0225A15B5
➜  2016湖湘杯DSA git:(master) ✗ openssl asn1parse -inform der -in packet1/sign1.bin  
    0:d=0  hl=2 l=  45 cons: SEQUENCE          
    2:d=1  hl=2 l=  21 prim: INTEGER           :8158B477C5AA033D650596E93653C730D26BA409
   25:d=1  hl=2 l=  20 prim: INTEGER           :165B9DD1C93230C31111E5A4E6EB5181F990F702

```

其中，獲取的第一個值是r，第二個值是s。可以看到第4個packet和第3個packet共享了k，因爲他們的r一致。

這裏我們可以使用openssl看下公鑰

```shell
➜  2016湖湘杯DSA git:(master) ✗ openssl dsa -in dsa_public.pem -text -noout  -pubin 
read DSA key
pub: 
    45:bb:18:f6:0e:b0:51:f9:d4:82:18:df:8c:d9:56:
    33:0a:4f:f3:0a:f5:34:4f:6c:95:40:06:1d:53:83:
    29:2d:95:c4:df:c8:ac:26:ca:45:2e:17:0d:c7:9b:
    e1:5c:c6:15:9e:03:7b:cc:f5:64:ef:36:1c:18:c9:
    9e:8a:eb:0b:c1:ac:f9:c0:c3:5d:62:0d:60:bb:73:
    11:f1:cf:08:cf:bc:34:cc:aa:79:ef:1d:ad:8a:7a:
    6f:ac:ce:86:65:90:06:d4:fa:f0:57:71:68:57:ec:
    7c:a6:04:ad:e2:c3:d7:31:d6:d0:2f:93:31:98:d3:
    90:c3:ef:c3:f3:ff:04:6f
P:   
    00:c0:59:6c:3b:5e:93:3d:33:78:be:36:26:be:31:
    5e:e7:0c:a6:b5:b1:1a:51:9b:55:23:d4:0e:5b:a7:
    45:66:e2:2c:c8:8b:fe:c5:6a:ad:66:91:8b:9b:30:
    ad:28:13:88:f0:bb:c6:b8:02:6b:7c:80:26:e9:11:
    84:be:e0:c8:ad:10:cc:f2:96:be:cf:e5:05:05:38:
    3c:b4:a9:54:b3:7c:b5:88:67:2f:7c:09:57:b6:fd:
    f2:fa:05:38:fd:ad:83:93:4a:45:e4:f9:9d:38:de:
    57:c0:8a:24:d0:0d:1c:c5:d5:fb:db:73:29:1c:d1:
    0c:e7:57:68:90:b6:ba:08:9b
Q:   
    00:86:8f:78:b8:c8:50:0b:eb:f6:7a:58:e3:3c:1f:
    53:9d:35:70:d1:bd
G:   
    4c:d5:e6:b6:6a:6e:b7:e9:27:94:e3:61:1f:41:53:
    cb:11:af:5a:08:d9:d4:f8:a3:f2:50:03:72:91:ba:
    5f:ff:3c:29:a8:c3:7b:c4:ee:5f:98:ec:17:f4:18:
    bc:71:61:01:6c:94:c8:49:02:e4:00:3a:79:87:f0:
    d8:cf:6a:61:c1:3a:fd:56:73:ca:a5:fb:41:15:08:
    cd:b3:50:1b:df:f7:3e:74:79:25:f7:65:86:f4:07:
    9f:ea:12:09:8b:34:50:84:4a:2a:9e:5d:0a:99:bd:
    86:5e:05:70:d5:19:7d:f4:a1:c9:b8:01:8f:b9:9c:
    dc:e9:15:7b:98:50:01:79
```

下面，我們直接利用上面的原理編寫程序即可，程序如下

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
data3 = f3.read()
data4 = f4.read()
sha = sha1()
sha.update(data3)
m3 = int(sha.hexdigest(), 16)
sha = sha1()
sha.update(data4)
m4 = int(sha.hexdigest(), 16)
print m3, m4
s3 = 0x30EB88E6A4BFB1B16728A974210AE4E41B42677D
s4 = 0x5E10DED084203CCBCEC3356A2CA02FF318FD4123
r = 0x5090DA81FEDE048D706D80E0AC47701E5A9EF1CC
ds = s4 - s3
dm = m4 - m3
k = gmpy2.mul(dm, gmpy2.invert(ds, q))
k = gmpy2.f_mod(k, q)
tmp = gmpy2.mul(k, s3) - m3
x = tmp * gmpy2.invert(r, q)
x = gmpy2.f_mod(x, q)
print int(x)
```

**我發現pip安裝的pycrypto竟然沒有DSA的importKey函數。。。只好從github上下載安裝了pycrypto。。。**

結果如下

```shell
➜  2016湖湘杯DSA git:(master) ✗ python exp.py
1104884177962524221174509726811256177146235961550 943735132044536149000710760545778628181961840230
520793588153805320783422521615148687785086070744
```

