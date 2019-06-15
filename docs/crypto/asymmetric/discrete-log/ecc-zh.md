[EN](./ecc.md) | [ZH](./ecc-zh.md)


# ECC

## 概述

ECC 全称为椭圆曲线加密，EllipseCurve Cryptography，是一种基于椭圆曲线数学的公钥密码。与传统的基于大质数因子分解困难性的加密方法不同，ECC依赖于解决椭圆曲线离散对数问题的困难性。它的优势主要在于相对于其它方法，它可以在使用较短密钥长度的同时保持相同的密码强度。目前椭圆曲线主要采用的有限域有

- 以素数为模的整数域GF(p)，通常在通用处理器上更为有效。
- 特征为 2 的伽罗华域GF（2^m），可以设计专门的硬件。

## 基本知识

我们首先来了解一下有限域上的椭圆曲线，有限域上的椭圆曲线是指在椭圆曲线的定义式

$y^2+axy+by=x^3+cx^2+dx+e$

中所有的系数都是在某个有限域GF(p)中的元素，其中p为一个大素数。

当然，并不是所有的椭圆曲线都适合于加密，最为常用的方程如下

$y^2=x^3+ax+b$

其中$4a^3+27b^2 \bmod p \neq 0$

我们称该方程的所有解(x,y)，($x\in Fp , y \in Fp$)，以及一个称为“无穷远点”(O)组成的集合为定义在Fp上的一个椭圆曲线，记为E(Fp)。

一般定义椭圆曲线密码需要以下条件

假设E(Fp)对于点的运算$\oplus$ 形成一个able群（交换群，逆元存在，封闭性等），设$p\in E(Fq)$ ，且满足下列条件的t很大

$p \oplus p \oplus ... \oplus p=O$

其中共有t个p参与运算。这里我们称t为p的周期。此外，对于$Q\in E(Fq)$ ，定有某个正整数m使得下列式子成立，定义$m=log_pq$

$Q=m\cdot p =p \oplus p \oplus ... \oplus p$ （m个p参与运算）

此外，假设G是该$E_q (a,b)$ 的生成元，即可以生成其中的所有元素，其阶为满足$nG=O$ 的最小正整数n。

## ECC中的ElGamal

这里我们假设用户B要把消息加密后传给用户A。

### 密钥生成

用户A先选择一条椭圆曲线$E_q (a,b)$ ，然后选择其上的一个生成元G，假设其阶为n，之后再选择一个正整数$n_a$作为密钥，计算$P_a=n_aG$。

其中，$E_q(a,b), q,G$都会被公开。

公钥为$P_a$，私钥为$n_a $。

### 加密

用户B在向用户A发送消息m，这里假设消息m已经被编码为椭圆曲线上的点，其加密步骤如下

1. 查询用户A的公钥$E_q(a,b), q, P_a,G$ 。
2. 在(1,q-1) 的区间内选择随机数k 。
3. 根据A的公钥计算点$(x_1,y_1)=kG$ 。
4. 计算点$(x_2,y_2)=kP_a$ ，如果为O，则从第二步重新开始。
5. 计算$C=m+(x_2,y_2)$
6. 将$((x_1,y_1),C)$ 发送给A。

### 解密

解密步骤如下

1. 利用私钥计算点$n_a(x_1,y_1)=n_akG=kP_a=(x_2,y_2)$。
2. 计算消息$m=C-(x_2,y_2)$ 。

### 关键点

这里的关键点在于我们即使知道了$(x_1,y_1)$ 也难以知道k，这是由离散对数的问题的难度决定的。

## 2013 SECCON CTF quals Cryptanalysis

这里我们以2013年SECCON CTF quals 中的 Cryptanalysis 为例，题目如下

![img](./figure/2013-seccon-ctf-crypt-desp.png)

这里，我们已知椭圆曲线方程以及对应的生成元 base，还知道相应的模数以及公钥以及加密后的结果。

但是可以看出的我们的模数太小，我们暴力枚举获取结果。

这里直接参考 github上的 sage 程序，暴力跑出 secret key。之后便可以解密了。

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

暴力跑出结果

```shell
[+] secret: 1584718
[+] x: 2171002
[+] y: 3549912
[+] x+y: 5720914
```

## 参考

- https://github.com/sonickun/ctf-crypto-writeups/tree/master/2013/seccon-ctf-quals/cryptanalysis
