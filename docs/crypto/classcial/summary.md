# 总结

## 经验

古典密码的基本解题思路可以总结如下

- 已知密码，识别密码
- 未知密码，分析密码特性，利用暴力破解或者相应思路求解

有以下几种方法可以用来识别密码

- 加密方式判别
- 字符集判别
- 加密结果样子判别

## 实验吧 围在栅栏里的爱

题目描述

> 最近一直在好奇一个问题，QWE到底等不等于ABC？
>
> -.- .. --.- .-.. .-- - ..-. -.-. --.- --. -. ... --- ---
>
> flag格式：CTF{xxx}

首先，根据密码样式判断是摩斯电码，解密后得到 `KIQLWTFCQGNSOO`，看着也不像 flag，题目中还有还有栅栏与 `QWE到底等不等于ABC`，两个都试了试之后，发现是先 QWE 然后栅栏可得到结果。  

首先键盘 QWE 解密，试着解密得到 `IILYOAVNEBSAHR`。继而栅栏解密得到 `ILOVESHIYANBAR`。

## 2017 SECCON Vigenere3d

程序如下

```python
# Vigenere3d.py
import sys
def _l(idx, s):
    return s[idx:] + s[:idx]
def main(p, k1, k2):
    s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}"
    t = [[_l((i+j) % len(s), s) for j in range(len(s))] for i in range(len(s))]
    i1 = 0
    i2 = 0
    c = ""
    for a in p:
        c += t[s.find(a)][s.find(k1[i1])][s.find(k2[i2])]
        i1 = (i1 + 1) % len(k1)
        i2 = (i2 + 1) % len(k2)
    return c
print main(sys.argv[1], sys.argv[2], sys.argv[2][::-1])

$ python Vigenere3d.py SECCON{**************************} **************
POR4dnyTLHBfwbxAAZhe}}ocZR3Cxcftw9
```

首先，我们先来分析一下 t 的构成

$$
t[i][j]=s[i+j:]+s[:i+j] \\
t[i][k]=s[i+k:]+s[:i+k]
$$

$t[i][j][k]$ 为 $t[i][j]$ 中的第 k 个字符，$t[i][k][j]$ 为 $t[i][k]$ 中的第 j 个字符。无论是 $i+j+k$ 是否超过 `len(s)` 两者都始终保持一致，即 $t[i][j][k]=t[i][k][j]$ 。

故而，其实对于相同的明文来说，可能有多个秘钥使其生成相同的密文。

然而上面分析就是单纯地分析而已，，下面开始正题。

不难看出，密文的每一位只与明文的相应位相关，而且，秘钥的每一位的空间最大也就是 s 的大小，所以我们可以使用爆破来获取秘钥。这里根据上述命令行提示，可以知道秘钥长度为 14，恰好明文前面7个字节已知。恢复秘钥的 exp 如下

```python
def get_key(plain, cipher):
    s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}"
    t = [[_l((i + j) % len(s), s) for j in range(len(s))]
         for i in range(len(s))]
    i1 = 0
    i2 = 0
    key = ['*'] * 14
    for i in range(len(plain)):
        for i1 in range(len(s)):
            for i2 in range(len(s)):
                if t[s.find(plain[i])][s.find(s[i1])][s.find(s[i2])] == cipher[
                        i]:
                    key[i] = s[i1]
                    key[13 - i] = s[i2]
    return ''.join(key)
```

恢复明文的脚本如下

```python
def decrypt(cipher, k1, k2):
    s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}"
    t = [[_l((i + j) % len(s), s) for j in range(len(s))]
         for i in range(len(s))]
    i1 = 0
    i2 = 0
    plain = ""
    for a in cipher:
        for i in range(len(s)):
            if t[i][s.find(k1[i1])][s.find(k2[i2])] == a:
                plain += s[i]
                break
        i1 = (i1 + 1) % len(k1)
        i2 = (i2 + 1) % len(k2)
    return plain
```

得到明文如下

```shell
➜  2017_seccon_vigenere3d git:(master) python exp.py
SECCON{Welc0me_to_SECCON_CTF_2017}
```
