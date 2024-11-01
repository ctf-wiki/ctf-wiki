# 單表代換加密

## 通用特點

在單表替換加密中，所有的加密方式幾乎都有一個共性，那就是明密文一一對應。所以說，一般有以下兩種方式來進行破解

- 在密鑰空間較小的情況下，採用暴力破解方式
- 在密文長度足夠長的時候，使用詞頻分析，http://quipqiup.com/

當密鑰空間足夠大，而密文長度足夠短的情況下，破解較爲困難。

## 凱撒密碼

### 原理

凱撒密碼（Caesar）加密時會將明文中的 **每個字母** 都按照其在字母表中的順序向後（或向前）移動固定數目（**循環移動**）作爲密文。例如，當偏移量是左移 3 的時候（解密時的密鑰就是 3）：

```
明文字母表：ABCDEFGHIJKLMNOPQRSTUVWXYZ
密文字母表：DEFGHIJKLMNOPQRSTUVWXYZABC
```

使用時，加密者查找明文字母表中需要加密的消息中的每一個字母所在位置，並且寫下密文字母表中對應的字母。需要解密的人則根據事先已知的密鑰反過來操作，得到原來的明文。例如：

```
明文：THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG
密文：WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ
```

根據偏移量的不同，還存在**若干特定的愷撒密碼名稱**：

- 偏移量爲 10：Avocat （A→K）
- 偏移量爲 13：[ROT13](https://zh.wikipedia.org/wiki/ROT13)
- 偏移量爲 -5：Cassis （K 6）
- 偏移量爲 -6：Cassette （K 7）

此外，還有還有一種基於密鑰的凱撒密碼 Keyed Caesar。其基本原理是 **利用一個密鑰，將密鑰的每一位轉換爲數字（一般轉化爲字母表對應順序的數字），分別以這一數字爲密鑰加密明文的每一位字母。**

這裏以 **XMan 一期夏令營分享賽宮保雞丁隊 Crypto 100** 爲例進行介紹。

```
密文：s0a6u3u1s0bv1a
密鑰：guangtou
偏移：6,20,0,13,6,19,14,20
明文：y0u6u3h1y0uj1u
```

### 破解

對於不帶密鑰的凱撒密碼來說，其基本的破解方法有兩種方式

1. 遍歷 26 個偏移量，適用於普遍情況
2. 利用詞頻分析，適用於密文較長的情況。

其中，第一種方式肯定可以得到明文，而第二種方式則不一定可以得到正確的明文。

而對於基於密鑰的凱撒密碼來說，一般來說必須知道對應的密鑰。

### 工具

一般我們有如下的工具，其中JPK比較通用。

- JPK，可解帶密鑰與不帶密鑰
- http://planetcalc.com/1434/
- http://www.qqxiuzi.cn/bianma/ROT5-13-18-47.php

## 移位密碼

與凱撒密碼類似，區別在於移位密碼不僅會處理字母，還會處理數字和特殊字符，常用 ASCII 碼錶進行移位。其破解方法也是遍歷所有的可能性來得到可能的結果。

## Atbash Cipher

### 原理

埃特巴什碼（Atbash Cipher）其實可以視爲下面要介紹的簡單替換密碼的特例，它使用字母表中的最後一個字母代表第一個字母，倒數第二個字母代表第二個字母。在羅馬字母表中，它是這樣出現的：

```
明文：A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
密文：Z Y X W V U T S R Q P O N M L K J I H G F E D C B A
```

下面給出一個例子：

```
明文：the quick brown fox jumps over the lazy dog
密文：gsv jfrxp yildm ulc qfnkh levi gsv ozab wlt
```

### 破解

可以看出其密鑰空間足夠短，同時當密文足夠長時，仍然可以採用詞頻分析的方法解決。

### 工具

- http://www.practicalcryptography.com/ciphers/classical-era/atbash-cipher/

## 簡單替換密碼

### 原理

簡單替換密碼（Simple Substitution Cipher）加密時，將每個明文字母替換爲與之唯一對應且不同的字母。它與愷撒密碼之間的區別是其密碼字母表的字母不是簡單的移位，而是完全是混亂的，這也使得其破解難度要高於凱撒密碼。 比如：

```
明文字母 : abcdefghijklmnopqrstuvwxyz
密鑰字母 : phqgiumeaylnofdxjkrcvstzwb
```

a 對應 p，d 對應 h，以此類推。

```
明文：the quick brown fox jumps over the lazy dog
密文：cei jvaql hkdtf udz yvoxr dsik cei npbw gdm
```

而解密時，我們一般是知道了每一個字母的對應規則，纔可以正常解密。

### 破解

由於這種加密方式導致其所有的密鑰個數是$26!$ ，所以幾乎上不可能使用暴力的解決方式。所以我們 一般採用詞頻分析。

### 工具

- http://quipqiup.com/

## 仿射密碼 

### 原理

仿射密碼的加密函數是 $E(x)=(ax+b)\pmod m$，其中

- $x$ 表示明文按照某種編碼得到的數字
- $a$ 和 $m$ 互質
- $m$ 是編碼系統中字母的數目。

解密函數是 $D(x)=a^{-1}(x-b)\pmod m$，其中 $a^{-1}$ 是 $a$ 在 $\mathbb{Z}_{m}$ 羣的乘法逆元。

下面我們以 $E(x) = (5x + 8) \bmod 26$ 函數爲例子進行介紹，加密字符串爲 `AFFINE CIPHER`，這裏我們直接採用字母表26個字母作爲編碼系統

| 明文      | A   | F   | F   | I   | N   | E   | C   | I   | P   | H   | E   | R   |
| --------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| x         | 0   | 5   | 5   | 8   | 13  | 4   | 2   | 8   | 15  | 7   | 4   | 17  |
| $y=5x+8$  | 8   | 33  | 33  | 48  | 73  | 28  | 18  | 48  | 83  | 43  | 28  | 93  |
| $y\mod26$ | 8   | 7   | 7   | 22  | 21  | 2   | 18  | 22  | 5   | 17  | 2   | 15  |
| 密文      | I   | H   | H   | W   | V   | C   | S   | W   | F   | R   | C   | P   |

其對應的加密結果是 `IHHWVCSWFRCP`。

對於解密過程，正常解密者具有a與b，可以計算得到 $a^{-1}$ 爲 21，所以其解密函數是$D(x)=21(x-8)\pmod {26}$ ，解密如下

| 密文        | I    | H    | H   | W   | V   | C    | S   | W   | F   | R   | C    | P   |
| ----------- | :--- | :--- | --- | --- | --- | ---- | --- | --- | --- | --- | ---- | --- |
| $y$         | 8    | 7    | 7   | 22  | 21  | 2    | 18  | 22  | 5   | 17  | 2    | 15  |
| $x=21(y-8)$ | 0    | -21  | -21 | 294 | 273 | -126 | 210 | 294 | -63 | 189 | -126 | 147 |
| $x\mod26$   | 0    | 5    | 5   | 8   | 13  | 4    | 2   | 8   | 15  | 7   | 4    | 17  |
| 明文        | A    | F    | F   | I   | N   | E    | C   | I   | P   | H   | E    | R   |

可以看出其特點在於只有 26 個英文字母。

### 破解

首先，我們可以看到的是，仿射密碼對於任意兩個不同的字母，其最後得到的密文必然不一樣，所以其也具有最通用的特點。當密文長度足夠長時，我們可以使用頻率分析的方法來解決。

其次，我們可以考慮如何攻擊該密碼。可以看出當$a=1$ 時，仿射加密是凱撒加密。而一般來說，我們利用仿射密碼時，其字符集都用的是字母表，一般只有26個字母，而不大於26的與26互素的個數一共有 

$$
\phi(26)=\phi(2) \times \phi(13) = 12
$$

算上b的偏移可能，一共有可能的密鑰空間大小也就是 

$$
12 \times 26 = 312
$$

一般來說，對於該種密碼，我們至少得是在已知部分明文的情況下才可以攻擊。下面進行簡單的分析。

這種密碼由兩種參數來控制，如果我們知道其中任意一個參數，那我們便可以很容易地快速枚舉另外一個參數得到答案。

但是，假設我們已經知道採用的字母集，這裏假設爲26個字母，我們還有另外一種解密方式，我們只需要知道兩個加密後的字母 $y_1,y_2$ 即可進行解密。那麼我們還可以知道

$$
y_1=(ax_1+b)\pmod{26} \\
y_2=(ax_2+b)\pmod{26}
$$

兩式相減，可得

$$
y_1-y_2=a(x_1-x_2)\pmod{26}
$$

這裏 $y_1,y_2$ 已知，如果我們知道密文對應的兩個不一樣的字符 $x_1$ 與 $x_2$ ，那麼我們就可以很容易得到 $a$ ，進而就可以得到 $b$ 了。

### 例子

這裏我們以TWCTF 2016 的 super_express爲例進行介紹。簡單看一下給的源碼

```python
import sys
key = '****CENSORED***************'
flag = 'TWCTF{*******CENSORED********}'

if len(key) % 2 == 1:
    print("Key Length Error")
    sys.exit(1)

n = len(key) / 2
encrypted = ''
for c in flag:
    c = ord(c)
    for a, b in zip(key[0:n], key[n:2*n]):
        c = (ord(a) * c + ord(b)) % 251
    encrypted += '%02x' % c

print encrypted
```

可以發現，雖然對於 flag 中的每個字母都加密了 n 次，如果我們仔細分析的話，我們可以發現

$$
\begin{align*}
c_1&=a_1c+b_1 \\
c_2&=a_2c_1+b_2 \\
   &=a_1a_2c+a_2b_1+b_2 \\
   &=kc+d
\end{align*}  
$$

根據第二行的推導，我們可以得到其實 $c_n$ 也是這樣的形式，可以看成 $c_n=xc+y$ ，並且，我們可以知道的是，key 是始終不變化的，所以說，其實這個就是仿射密碼。

此外，題目中還給出了密文以及部分部分密文對應的明文，那麼我們就很容易利用已知明文攻擊的方法來攻擊了，利用代碼如下

```python
import gmpy

key = '****CENSORED****************'
flag = 'TWCTF{*******CENSORED********}'

f = open('encrypted', 'r')
data = f.read().strip('\n')
encrypted = [int(data[i:i + 2], 16) for i in range(0, len(data), 2)]
plaindelta = ord(flag[1]) - ord(flag[0])
cipherdalte = encrypted[1] - encrypted[0]
a = gmpy.invert(plaindelta, 251) * cipherdalte % 251
b = (encrypted[0] - a * ord(flag[0])) % 251
a_inv = gmpy.invert(a, 251)
result = ""
for c in encrypted:
    result += chr((c - b) * a_inv % 251)
print result
```

結果如下

```shell
➜  TWCTF2016-super_express git:(master) ✗ python exploit.py
TWCTF{Faster_Than_Shinkansen!}
```
