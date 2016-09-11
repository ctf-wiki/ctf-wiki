# Classical Cipher 古典密码

## 单表代换密码

### 凯撒密码

明文中的所有字母都在字母表上向后（或向前）按照一个固定数目进行偏移后被替换成密文。

恺撒密码的替换方法是通过排列明文和密文字母表，密文字母表示通过将明文字母表向左或向右移动一个固定数目的位置。例如，当偏移量是左移3的时候（解密时的密钥就是3）：

```
明文字母表：ABCDEFGHIJKLMNOPQRSTUVWXYZ
密文字母表：DEFGHIJKLMNOPQRSTUVWXYZABC
```

使用时，加密者查找明文字母表中需要加密的消息中的每一个字母所在位置，并且写下密文字母表中对应的字母。需要解密的人则根据事先已知的密钥反过来操作，得到原来的明文。例如：

```
明文：THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG
密文：WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ
```

#### 特定恺撒密码名称

根据偏移量的不同，还存在若干特定的恺撒密码名称：

* 偏移量为 10：Avocat (A→K)
* 偏移量为 13：[ROT13](https://zh.wikipedia.org/wiki/ROT13)
* 偏移量为 -5：Cassis (K 6)
* 偏移量为 -6：Cassette (K 7)

#### 密码破解

遍历 26 个偏移量，或利用词频分析。

#### 基于密钥的凯撒 Keyed Caesar

利用一个密钥，将密钥的每一位转换为数字，分别以这一数字为密钥加密明文的每一位。

```
明文：s0a6u3u1s0bv1a
密钥：guangtou
偏移：7,21,1,14,7,20,15,21
密文：y0u6u3h1y0uj1u
```

> 题目来源：XMan 一期夏令营分享赛宫保鸡丁队 Crypto 100

### 移位密码

与凯撒密码类似，区别在于移位密码也会处理数字和特殊字符，常用 ASCII 码表进行移位。

### 埃特巴什码 Atbash Cipher

埃特巴什码（Atbash Cipher）是一个系统：最后一个字母代表第一个字母，倒数第二个字母代表第二个字母。

在罗马字母表中，它是这样出现的：

```
常文：A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
密文：Z Y X W V U T S R Q P O N M L K J I H G F E D C B A
```

### 仿射密码

[仿射密码 - 维基百科](https://zh.wikipedia.org/wiki/%E4%BB%BF%E5%B0%84%E5%AF%86%E7%A2%BC)

仿射密码是一种替换密码。它是一个字母对一个字母的。

它的加密函数是![](http://latex.codecogs.com/gif.latex?e%28x%29%3Dax&plus;b%5C%20%28mod%5C%20m%29)，其中

* ![](http://latex.codecogs.com/gif.latex?a)和![](http://latex.codecogs.com/gif.latex?m)互质；
* ![](http://latex.codecogs.com/gif.latex?m)是字母的数目。

解码函数是![](http://latex.codecogs.com/gif.latex?d%28x%29%3Da%5E%7B-1%7D%28x-b%29%5C%20%28mod%5C%20m%29)，其中![](http://latex.codecogs.com/gif.latex?a%5E%7B-1%7D)是![](http://latex.codecogs.com/gif.latex?a)在![](http://latex.codecogs.com/gif.latex?%5Cmathbb%7BZ%7D_m)群的乘法逆元。

## 多表代换密码

### Playfair 密码

[Playfair Cipher - 维基百科](https://en.wikipedia.org/wiki/Playfair_cipher)

Playfair密码（英文：Playfair cipher 或 Playfair square）是一种替换密码，1854年由查尔斯·惠斯通（Charles Wheatstone）的英国人发明。

#### 算法

1. 选取一个英文字作密钥。除去重复出现的字母。将密匙的字母逐个逐个加入 5×5 的矩阵内，剩下的空间将未加入的英文字母依 a-z 的顺序加入。（将 q 去除，或将 i 和 j 视作同一字。）
2. 将要加密的讯息分成两个一组。若组内的字母相同，将 X（或 Q）加到该组的第一个字母后，重新分组。若剩下一个字，也加入 X 字。
3. 在每组中，找出两个字母在矩阵中的地方。
   * 若两个字母不同行也不同列，在矩阵中找出另外两个字母，使这四个字母成为一个长方形的四个角。
   * 若两个字母同行，取这两个字母右方的字母（若字母在最右方则取最左方的字母）。
   * 若两个字母同列，取这两个字母下方的字母（若字母在最下方则取最上方的字母）。


新找到的两个字母就是原本的两个字母加密的结果。

#### 例子

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

### Polybius 密码（棋盘密码）

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

![](http://7xry4x.com1.z0.glb.clouddn.com/16-9-11/48970260.jpg)

注意，这里字母的顺序被打乱了哦。

A D F G X 的由来：

> 1918 年，第一次世界大战将要结束时，法军截获了一份德军电报，电文中的所有单词都由 A、D、F、G、X 五个字母拼成，因此被称为 ADFGX 密码。ADFGX 密码是 1918 年 3 月由德军上校 Fritz Nebel 发明的，是结合了 Polybius 密码和置换密码的双重加密方案。

举个例子，HELLO，使用这个表格加密，就是 DD XF AG AG DF。

### 维吉尼亚密码



