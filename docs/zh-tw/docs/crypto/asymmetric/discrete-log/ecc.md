# ECC

## 概述

ECC 全稱爲橢圓曲線加密，EllipseCurve Cryptography，是一種基於橢圓曲線數學的公鑰密碼。與傳統的基於大質數因子分解困難性的加密方法不同，ECC依賴於解決橢圓曲線離散對數問題的困難性。它的優勢主要在於相對於其它方法，它可以在使用較短密鑰長度的同時保持相同的密碼強度。目前橢圓曲線主要採用的有限域有

- 以素數爲模的整數域GF(p)，通常在通用處理器上更爲有效。
- 特徵爲 2 的伽羅華域GF（2^m），可以設計專門的硬件。

## 基本知識

我們首先來瞭解一下有限域上的橢圓曲線，有限域上的橢圓曲線是指在橢圓曲線的定義式

$y^2+axy+by=x^3+cx^2+dx+e$

中所有的係數都是在某個有限域GF(p)中的元素，其中p爲一個大素數。

當然，並不是所有的橢圓曲線都適合於加密，最爲常用的方程如下

$y^2=x^3+ax+b$

其中$4a^3+27b^2 \bmod p \neq 0$

我們稱該方程的所有解(x,y)，($x\in Fp , y \in Fp$)，以及一個稱爲“無窮遠點”(O)組成的集合爲定義在Fp上的一個橢圓曲線，記爲E(Fp)。

一般定義橢圓曲線密碼需要以下條件

假設E(Fp)對於點的運算$\oplus$ 形成一個able羣（交換羣，逆元存在，封閉性等），設$p\in E(Fq)$ ，且滿足下列條件的t很大

$p \oplus p \oplus ... \oplus p=O$

其中共有t個p參與運算。這裏我們稱t爲p的週期。此外，對於$Q\in E(Fq)$ ，定有某個正整數m使得下列式子成立，定義$m=log_pq$

$Q=m\cdot p =p \oplus p \oplus ... \oplus p$ （m個p參與運算）

此外，假設G是該$E_q (a,b)$ 的生成元，即可以生成其中的所有元素，其階爲滿足$nG=O$ 的最小正整數n。

## ECC中的ElGamal

這裏我們假設用戶B要把消息加密後傳給用戶A。

### 密鑰生成

用戶A先選擇一條橢圓曲線$E_q (a,b)$ ，然後選擇其上的一個生成元G，假設其階爲n，之後再選擇一個正整數$n_a$作爲密鑰，計算$P_a=n_aG$。

其中，$E_q(a,b), q,G$都會被公開。

公鑰爲$P_a$，私鑰爲$n_a $。

### 加密

用戶B在向用戶A發送消息m，這裏假設消息m已經被編碼爲橢圓曲線上的點，其加密步驟如下

1. 查詢用戶A的公鑰$E_q(a,b), q, P_a,G$ 。
2. 在(1,q-1) 的區間內選擇隨機數k 。
3. 根據A的公鑰計算點$(x_1,y_1)=kG$ 。
4. 計算點$(x_2,y_2)=kP_a$ ，如果爲O，則從第二步重新開始。
5. 計算$C=m+(x_2,y_2)$
6. 將$((x_1,y_1),C)$ 發送給A。

### 解密

解密步驟如下

1. 利用私鑰計算點$n_a(x_1,y_1)=n_akG=kP_a=(x_2,y_2)$。
2. 計算消息$m=C-(x_2,y_2)$ 。

### 關鍵點

這裏的關鍵點在於我們即使知道了$(x_1,y_1)$ 也難以知道k，這是由離散對數的問題的難度決定的。

## 2013 SECCON CTF quals Cryptanalysis

這裏我們以2013年SECCON CTF quals 中的 Cryptanalysis 爲例，題目如下

![img](./figure/2013-seccon-ctf-crypt-desp.png)

這裏，我們已知橢圓曲線方程以及對應的生成元 base，還知道相應的模數以及公鑰以及加密後的結果。

但是可以看出的我們的模數太小，我們暴力枚舉獲取結果。

這裏直接參考 github上的 sage 程序，暴力跑出 secret key。之後便可以解密了。

```python

a = 1234577
b = 3213242
n = 7654319

E = EllipticCurve(GF(n), [0, 0, 0, a, b])

base = E([5234568, 2287747])
pub = E([2366653, 1424308])

c1 = E([5081741, 6744615])
c2 = E([610619, 6218])

X = base

for i in range(1, n):
    if X == pub:
        secret = i
        print "[+] secret:", i
        break
    else:
        X = X + base
        print i

m = c2 - (c1 * secret)

print "[+] x:", m[0]
print "[+] y:", m[1]
print "[+] x+y:", m[0] + m[1]
```

暴力跑出結果

```shell
[+] secret: 1584718
[+] x: 2171002
[+] y: 3549912
[+] x+y: 5720914
```

## 參考

- https://github.com/sonickun/ctf-crypto-writeups/tree/master/2013/seccon-ctf-quals/cryptanalysis
