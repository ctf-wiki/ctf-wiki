## 通用特点

- 明密文一一对应，可以使用词频分析

## 凯撒密码

明文中的所有字母都在字母表上向后（或向前）按照一个固定数目进行偏移后被替换成密文。

恺撒密码的替换方法是通过排列明文和密文字母表，密文字母表示通过将明文字母表向左或向右移动一个固定数目的位置。例如，当偏移量是左移 3 的时候（解密时的密钥就是 3）：

```
明文字母表：ABCDEFGHIJKLMNOPQRSTUVWXYZ
密文字母表：DEFGHIJKLMNOPQRSTUVWXYZABC
```

使用时，加密者查找明文字母表中需要加密的消息中的每一个字母所在位置，并且写下密文字母表中对应的字母。需要解密的人则根据事先已知的密钥反过来操作，得到原来的明文。例如：

```
明文：THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG
密文：WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ
```

### 特定恺撒密码

根据偏移量的不同，还存在若干特定的恺撒密码名称：

- 偏移量为 10：Avocat （A→K）
- 偏移量为 13：[ROT13](https://zh.wikipedia.org/wiki/ROT13)
- 偏移量为 -5：Cassis （K 6）
- 偏移量为 -6：Cassette （K 7）

### 工具

其实其基本的破解方法就是**遍历 26 个偏移量，或利用词频分析**。

- JPK
- http://planetcalc.com/1434/
- http://www.qqxiuzi.cn/bianma/ROT5-13-18-47.php

## 基于密钥的凯撒 Keyed Caesar

利用一个密钥，将密钥的每一位转换为数字，分别以这一数字为密钥加密明文的每一位。

```
明文：s0a6u3u1s0bv1a
密钥：guangtou
偏移：7,21,1,14,7,20,15,21
密文：y0u6u3h1y0uj1u
```

> 题目来源：XMan 一期夏令营分享赛宫保鸡丁队 Crypto 100

### 工具

- JPK

## 移位密码

与凯撒密码类似，区别在于移位密码也会处理数字和特殊字符，常用 ASCII 码表进行移位。

## 埃特巴什码 Atbash Cipher

埃特巴什码（Atbash Cipher）是一个系统：最后一个字母代表第一个字母，倒数第二个字母代表第二个字母。

在罗马字母表中，它是这样出现的：

```
常文：A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
密文：Z Y X W V U T S R Q P O N M L K J I H G F E D C B A
```

### 例子

明文： `the quick brown fox jumps over the lazy dog`

密文： `gsv jfrxp yildm ulc qfnkh levi gsv ozab wlt`

### 工具

- http://www.practicalcryptography.com/ciphers/classical-era/atbash-cipher/

## 简单替换密码

简单换位密码（Simple Substitution Cipher）加密方式是以每个明文字母被与之唯一对应且不同的字母替换的方式实现的，它不同于恺撒密码，因为密码字母表的字母不是简单的移位，而是完全是混乱的。

### 例子

 比如：

```
明文字母 : abcdefghijklmnopqrstuvwxyz
明文字母 : phqgiumeaylnofdxjkrcvstzwb
```

a 对应 p，d 对应 h，以此类推。

明文： `the quick brown fox jumps over the lazy dog`

密文： `cei jvaql hkdtf udz yvoxr dsik cei npbw gdm`

### 工具

- http://quipqiup.com/

## 仿射密码 

[仿射密码 - 维基百科](https://zh.wikipedia.org/wiki/%E4%BB%BF%E5%B0%84%E5%AF%86%E7%A2%BC)

仿射密码是一种替换密码。它是一个字母对一个字母的。

它的加密函数是 $E(x)=(ax+b)\pmod m$，其中

- $a$ 和 $m$ 互质；
- $m$ 是字母的数目。

解密函数是 $D(x)=a^{-1}(x-b)\pmod m$，其中 $a^{-1}$ 是 $a$ 在 $\mathbb{Z}_{m}$ 群的乘法逆元。

### 例子

下面我们以 $E(x) = (5x + 8) \bmod 26$ 函数为例子

![example](/crypto/classical/figure/affine-example.png)

### 特点

- 只有 26 个英文字母

### 例子

- TWCTF 2016 - super_express
  - Jarvis OJ - Crypto - cuper express