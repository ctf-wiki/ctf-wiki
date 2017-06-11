## Playfair 密码

[Playfair Cipher - 维基百科](https://en.wikipedia.org/wiki/Playfair_cipher)

Playfair 密码（英文：Playfair cipher 或 Playfair square）是一种替换密码，1854 年由查尔斯·惠斯通（Charles Wheatstone）的英国人发明。

基本算法如下：

1. 选取一个英文字作密钥。除去重复出现的字母。将密匙的字母逐个逐个加入 5 × 5 的矩阵内，剩下的空间将未加入的英文字母依 a-z 的顺序加入。（将 q 去除，或将 i 和 j 视作同一字。）
2. 将要加密的讯息分成两个一组。若组内的字母相同，将 X（或 Q）加到该组的第一个字母后，重新分组。若剩下一个字，也加入 X 字。
3. 在每组中，找出两个字母在矩阵中的地方。
   - 若两个字母不同行也不同列，在矩阵中找出另外两个字母，使这四个字母成为一个长方形的四个角。
   - 若两个字母同行，取这两个字母右方的字母（若字母在最右方则取最左方的字母）。
   - 若两个字母同列，取这两个字母下方的字母（若字母在最下方则取最上方的字母）。

新找到的两个字母就是原本的两个字母加密的结果。

### 例子

取 playfair example 为密匙，得

```
P L A Y F
I R E X M
B C D G H
K N O Q S
T U V W Z
```

要加密的讯息为 Hide the gold in the tree stump：

```
HI DE TH EG OL DI NT HE TR EX ES TU MP
```

就会得到

```
BM OD ZB XD NA BE KU DM UI XM MO UV IF
```

## Polybius 密码（棋盘密码）

[Polybius square - 维基百科](https://en.wikipedia.org/wiki/Polybius_square)

常用密码表

|      | 1    | 2    | 3    | 4    | 5    |
| :--- | ---- | ---- | ---- | ---- | :--- |
| 1    | A    | B    | C    | D    | E    |
| 2    | F    | G    | H    | I/J  | K    |
| 3    | L    | M    | N    | O    | P    |
| 4    | Q    | R    | S    | T    | U    |
| 5    | V    | W    | X    | Y    | Z    |

举个例子，明文 HELLO，加密后就是 23 15 31 31 34。

另一种密码表

|      | A    | D    | F    | G    | X    |
| ---- | ---- | ---- | ---- | ---- | ---- |
| A    | b    | t    | a    | l    | p    |
| D    | d    | h    | o    | z    | k    |
| F    | q    | f    | v    | s    | n    |
| G    | g    | j    | c    | u    | x    |
| X    | m    | r    | e    | w    | y    |

注意，这里字母的顺序被打乱了哦。

A D F G X 的由来：

> 1918 年，第一次世界大战将要结束时，法军截获了一份德军电报，电文中的所有单词都由 A、D、F、G、X 五个字母拼成，因此被称为 ADFGX 密码。ADFGX 密码是 1918 年 3 月由德军上校 Fritz Nebel 发明的，是结合了 Polybius 密码和置换密码的双重加密方案。

举个例子，HELLO，使用这个表格加密，就是 DD XF AG AG DF。

## 维吉尼亚密码

[维吉尼亚密码 - 维基百科](https://zh.wikipedia.org/wiki/%E7%BB%B4%E5%90%89%E5%B0%BC%E4%BA%9A%E5%AF%86%E7%A0%81)

维吉尼亚密码（又译维热纳尔密码）是使用一系列凯撒密码组成密码字母表的加密算法，属于多表密码的一种简单形式。

![维吉尼亚表格](/crypto/classical/figure/vigenere1.jpg)

### 例子

```
明文：come greatwall
密钥：crypto
```

- 填充对齐

| 明文   | c    | o    | m    | e    | g    | r    | e    | a    | t    | w    | a    | l    | l    |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 密钥   | c    | r    | y    | p    | t    | o    | c    | r    | y    | p    | t    | o    | c    |

- 查表得密文

  ![维吉尼亚加密](/crypto/classical/figure/vigenere2.jpg)

  ```
  明文：come greatwall
  密钥：crypto
  密文：efkt zferrltzn
  ```

### 破解方法

对包括维吉尼亚密码在内的所有多表密码的破译都是以字母频率为基础的，但直接的频率分析却并不适用。例如，如果 P 是密文中出现次数最多的字母，则 P 很有可能对应 E（前提是明文的语言为英语）。原因在于 E 是英语中使用频率最高的字母。然而，由于在维吉尼亚密码中，E 可以被加密成不同的密文，因而简单的频率分析在这里并没有用。

破译维吉尼亚密码的关键在于它的密钥是循环重复的。如果我们知道了密钥的长度，那密文就可以被看作是交织在一起的凯撒密码，而其中每一个都可以单独破解。使用卡西斯基试验和弗里德曼试验来得到密钥的长度。

卡西斯基试验是基于类似 the 这样的常用单词有可能被同样的密钥字母进行加密，从而在密文中重复出现。例如，明文中不同的 CRYPTO 可能被密钥 ABCDEF 加密成不同的密文：

```
密钥：ABCDEF AB CDEFA BCD EFABCDEFABCD
明文：CRYPTO IS SHORT FOR CRYPTOGRAPHY
密文：CSASXT IT UKSWT GQU GWYQVRKWAQJB
```

此时明文中重复的元素在密文中并不重复。然而，如果密钥相同的话，结果可能便为（使用密钥 ABCD）：

```
密钥：ABCDAB CD ABCDA BCD ABCDABCDABCD
明文：CRYPTO IS SHORT FOR CRYPTOGRAPHY
密文：CSASTP KV SIQUT GQU CSASTPIUAQJB
```

此时卡西斯基试验就能产生效果。对于更长的段落此方法更为有效，因为通常密文中重复的片段会更多。如通过下面的密文就能破译出密钥的长度：

```
密文：DYDUXRMHTVDVNQDQNWDYDUXRMHARTJGWNQD
```

其中，两个 DYDUXRMH 的出现相隔了 18 个字母。因此，可以假定密钥的长度是 18 的约数，即长度为 18、9、6、3 或 2。而两个 NQD 则相距 20 个字母，意味着密钥长度应为 20、10、5、4 或 2。取两者的交集，则可以基本确定密钥长度为 2。

### 工具

- 已知秘钥
  - Python 的 pycipher 库
  - [在线解密 Vigenère cipher](http://planetcalc.com/2468/)
- 未知秘钥
  - http://www.practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher/，待完成
  - [在线解密 Vigenère Cipher Codebreaker](http://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx)
  - [在线解密 Vigenere Solver](https://www.guballa.de/vigenere-solver)

## Nihilist 密码

又称关键字密码：明文 + 关键字 = 密文。

以关键字 helloworld 为例。

### 加解密过程

- 利用密钥构造棋盘矩阵（类似 Polybius 密码）
  - 新建一个 5 × 5 矩阵
  - 将字符不重复地依次填入矩阵
  - 剩下部分按字母顺序填入
  - 字母 i 和 j 等价

|      | 1    | 2    | 3     | 4    | 5    |
| ---- | ---- | ---- | ----- | ---- | ---- |
| 1    | h    | e    | l     | o    | w    |
| 2    | r    | d    | a     | b    | c    |
| 3    | f    | g    | i / j | k    | m    |
| 4    | n    | p    | q     | s    | t    |
| 5    | u    | v    | x     | y    | z    |

- 加密过程

  参照矩阵 M 进行加密：

  ```
  a -> M[2,3] -> 23
  t -> M[4,5] -> 45
  ```

- 解密过程

   参照矩阵 M 进行解密：

   ```
   23 -> M[2,3] -> a
   45 -> M[4,5] -> t
   ```

### 特征

密文纯数字，从 1 到 5，最大不超过 55，密文长度偶数。

## 希尔密码

[希尔密码 - 维基百科](https://zh.wikipedia.org/wiki/%E5%B8%8C%E5%B0%94%E5%AF%86%E7%A0%81)

每个字母当作 26 进制数字：A=0，B=1，C=2 等，一串字母当成 n 维向量，跟一个 n × n 的矩阵相乘，再将得出的结果模 26。

注意用作加密的矩阵（即密匙）在 $\mathbb{Z}_{26}^{n}​$ 必须是可逆的，否则就不可能解码。只有矩阵的行列式和 26 互质，才是可逆的。

### 例子

```
明文：ACT
```

将明文化为矩阵。
$$
\begin{bmatrix}
0\\\\
2\\\\
19
\end{bmatrix}
$$
假设密钥为：
$$
\begin{bmatrix}
6 & 24 & 1\\\\
13 & 16 & 10\\\\
20 & 17 & 15
\end{bmatrix}
$$
加密过程为：
$$
\begin{bmatrix}
6 & 24 & 1\\\\
13 & 16 & 10\\\\
20 & 17 & 15
\end{bmatrix}
\begin{bmatrix}
0\\\\
2\\\\
19
\end{bmatrix}
\equiv
\begin{bmatrix}
67\\\\
222\\\\
319
\end{bmatrix}
\equiv
\begin{bmatrix}
15\\\\
14\\\\
7
\end{bmatrix}
\bmod 26
$$
密文即为

```
密文：POH
```
### 工具

- http://www.practicalcryptography.com/ciphers/hill-cipher/
- CAP4(cryptographic analysis program v4)

### 例子

- ISCC 2015 base decrypt 150

## AutokeyCipher

自动密钥密码（Autokey Cipher）是多表替换密码，与维吉尼亚密码密切相关，但使用不同的方法生成密钥，通常来说要比维吉尼亚密码更安全。自动密钥密码主要有两种，关键词自动密钥密码和原文自动密钥密码.下面我们以关键词自动密钥为例：

明文： `THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG`

关键词： `CULTURE`

自动生成密钥： `CULTURE THE QUICK BROWN FOX JUMPS OVER THE`

接下来的加密过程和维吉尼亚密码类似，从密表可得：

密文： `VBP JOZGD IVEQV HYY AIICX CSNL FWW ZVDP WVK`

### 特点

### 工具

- 已知关键词
  - Python 的 pycipher 库
- 未知关键词
  - http://www.practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-autokey-cipher/
  - tools 文件夹下 break_autokey.py，待完成。