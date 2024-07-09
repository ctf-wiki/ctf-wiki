# ARX: Add-Rotate-Xor

## 概述

ARX 運算是如下 3 種基本運算的統稱
- Add 有限域上的模加
- Rotate 循環移位
- Xor 異或

有許多常見的塊加密算法在輪函數中只用到了這 3 種基本運算，典型例子如 Salsa20、Speck 等。另外 [IDEA](./idea.md) 也採用了類似的基本運算來構建加解密操作，不過以乘法代替了移位。

## 優缺點

### 優點

- 操作簡單，運算速度快
- 執行時間爲常數，可以避免基於時間的測信道攻擊
- 組合後的函數表達能力足夠強（參見下方例題）

### 缺點

- 在三種基本運算當中，Rotate、Xor 對於單個 bit 來說均是完全線性的運算，可能會帶來一定的脆弱性(參見[Rotational cryptanalysis](https://en.wikipedia.org/wiki/Rotational_cryptanalysis))

## 題目

### 2018 *ctf primitive

#### 分析

本題要求我們組合一定數目以內的 Add-Rotate-Xor 運算，使得獲得的加密算法能夠將固定明文加密成指定的隨機密文，即通過基礎運算來構建任意置換函數。成功構建 3 次之後即可獲得 flag。

#### 解題思路

對於模 256 下的運算，一種典型的基於 ARX 的換位操作可以表示爲如下組合
```
RotateLeft_1(Add_255(RotateLeft_7(Add_2(x))))
```

上述函數對應了一個將 254 和 255 進行交換，同時保持其它數字不變的置換運算。

直覺上來說，由於在第一步的模加 2 運算中，僅有輸入爲 254、255 時會發生進位，該組合函數得以區別對待這一情況。

利用上述原子操作，我們可以構造出任意兩個數字 `a,b` 的置換，結合 Xor 操作，我們可以減少所需的基本操作數目，使其滿足題目給出的限制。一種可能的操作步驟如下：

1. 對於 `a,b`，通過模加操作使得 `a` 爲0
2. 通過右移使得b的最低位爲 1
3. 若 `b` 不爲 1，進行 `Xor 1, Add 255` 操作，保持 `a` 仍然爲0，同時 `b` 的數值減小
4. 重複操作2-3直至 `b` 爲1
5. 進行 `Add 254` 及換位操作，交換 `a,b`
6. 對於換位以外的所有操作，加入對應的逆運算，確保 `a,b` 以外的數值不變

完整的解題腳本如下：

```python
from pwn import *
import string
from hashlib import sha256

#context.log_level='debug'
def dopow():
    chal = c.recvline()
    post = chal[12:28]
    tar = chal[33:-1]
    c.recvuntil(':')
    found = iters.bruteforce(lambda x:sha256(x+post).hexdigest()==tar, string.ascii_letters+string.digits, 4)
    c.sendline(found)

#c = remote('127.0.0.1',10001)
c = remote('47.75.4.252',10001)
dopow()
pt='GoodCipher'

def doswap(a,b):
    if a==b:
        return
    if a>b:
        tmp=b
        b=a
        a=tmp
    ans=[]
    ans.append((0,256-a))
    b-=a
    a=0
    while b!=1:
        tmp=0
        lo=1
        while b&lo==0:
            lo<<=1
            tmp+=1
        if b==lo:
            ans.append((1,8-tmp))
            break
        if tmp!=0:
            ans.append((1,8-tmp))
        b>>=tmp
        ans.append((2,1))
        b^=1
        ans.append((0,255))
        b-=1
    ans.append((0,254))

    for a,b in ans:
        c.sendline('%d %d'%(a,b))
        c.recvline()
    for a,b in [(0,2),(1,7),(0,255),(1,1)]:
        c.sendline('%d %d'%(a,b))
        c.recvline()
    for a,b in ans[::-1]:
        if a==0:
            c.sendline('%d %d'%(a,256-b))
        elif a==1:
            c.sendline('%d %d'%(a,8-b))
        elif a==2:
            c.sendline('%d %d'%(a,b))
        c.recvline()

for i in range(3):
    print i
    m=range(256)
    c.recvuntil('ciphertext is ')
    ct=c.recvline().strip()
    ct=ct.decode('hex')
    assert len(ct)==10
    for i in range(10):
        a=ord(ct[i])
        b=ord(pt[i])
        #print m[a],b
        doswap(m[a],b)
        for j in range(256):
            if m[j]==b:
                m[j]=m[a]
                m[a]=b
                break
    c.sendline('-1')

c.recvuntil('Your flag here.\n')
print c.recvline()
```
