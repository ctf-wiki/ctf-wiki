## ElGamal

### 概述

ElGamal算法的安全性是基于求解离散对数问题的困难性，于1984年提出，也是一种双钥密码体制，既可以用于加密又可用于数字签名。

如果我们假设p是至少是160位的十进制素数，**并且p-1有大素因子**，此外g是 $Z_p^*$  的生成元，并且 $y \in Z_p^*$  。那么如何找到一个唯一的整数x($0\leq x \leq p-2$) ，满足$g^x \equiv y \bmod p$ 在算法上是困难的，这里将x记为$x=log_gy$ 。

### 基本原理

这里我们假设A要给B发送消息m。

#### 密钥生成

基本步骤如下

1. 选取一个足够大的素数p，以便于在$Z_p$ 上求解离散对数问题是困难的。
2. 选取$Z_p^*$ 的生成元g。
3. 随机选取整数k,$0\leq k \leq p-2$ ，并计算$g^k \equiv y \bmod p$ 。

其中私钥为{k}，公钥为{p,g,y} 。

#### 加密

A选取随机数$r \in Z_{p-1}$ ，对明文加密$E_k(m,r)=(y_1,y_2)$ 。其中$y_1 \equiv g^r \bmod p$ ，$y_2 \equiv my^r \bmod p$ 。

#### 解密

$D_k(y_1,y_2)=y_2(y_1^k)^-1 \bmod p \equiv m(g^k)^r(g^{rk})^{-1} \equiv m \bmod p$ 。

#### 难点

虽然我们知道了y1,但是我们却没有办法知道其对应的r。

### 例子

这里我们以2015年 MMA-CTF-2015中的Alicegame为例进行介绍。这题最初在没有给出源码的时候却是比较难做，因为这个给一个m，给一个r就得到加密结果，，这太难想。

我们来简单分析一下源码，首先程序最初生成了pk与sk

```python
    (pk, sk) = genkey(PBITS)
```

其中genkey函数如下

```python
def genkey(k):
    p = getPrime(k)
    g = random.randrange(2, p)
    x = random.randrange(1, p-1)
    h = pow(g, x, p)
    pk = (p, g, h)
    sk = (p, x)
    return (pk, sk)
```

p为k位的素数，g为(2,p)范围内的书，x在(1,p-1)范围内。并且计算了$h \equiv g^x \bmod p$ 。看到这里，差不多就知道，这应该是一个数域上的ElGamal加密了。其中pk为公钥，sk为私钥。

接下来 程序输出了10次m和r。并且，利用如下函数加密

```python
def encrypt(pk, m, r = None):
    (p, g, h) = pk
    if r is None:
        r = random.randrange(1, p-1)
    c1 = pow(g, r, p)
    c2 = (m * pow(h, r, p)) % p
    return (c1, c2)
```

其加密方法确实是ElGamal方式的加密。

最后程序对flag进行了加密。此时的r是由程序自己random的。

分析一下，这里我们在十轮循环中可以控制m和r，并且

$c_1 \equiv g^r \bmod p$

$c_2 \equiv m * h^{r} \bmod p$

如果我们设置

1. r=1，m=1，那么我们就可以获得$c_1=g,c_2=h$ 。
2. r=1，m=-1，那么我们就可以获得$c_1=g, c_2 = p-h$ 。进而我们就可以得到素数p。

我们得到素数p有什么用呢?p的位数在201位左右，很大啊。

但是啊，它生成素数p之后，没有进行检查啊。我们在之前说过p-1必须有大素因子，如果有小的素因子的话，那我们就可以攻击了。其攻击主要是使用到了baby step-giant step 与 Pohlig-Hellman algorithm 算法，有兴趣的可以看看，这里sage本身自带的计算离散对数的函数已经可以处理这样的情况了，参见[discrete_log](http://doc.sagemath.org/html/en/reference/groups/sage/groups/generic.html) 。

具体代码如下，需要注意的是，，这个消耗内存比较大，，不要随便拿虚拟机跑。。。还有就是这尼玛交互让我头疼啊，，，

```python
import socket
from Crypto.Util.number import *
from sage.all import *


def get_maxfactor(N):
    f = factor(N)
    print 'factor done'
    return f[-1][0]

maxnumber = 1 << 70
i = 0
while 1:
    print 'cycle: ',i
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 9999))
    sock.recv(17)
    # get g,h
    sock.recv(512)
    sock.sendall("1\n")
    sock.recv(512)
    sock.sendall("1\n")
    data = sock.recv(1024)
    print data
    if '\n' in data:
        data =data[:data.index('\n')]
    else:
        # receive m=
        sock.recv(1024)
    (g,h) = eval(data)
    
    # get g,p
    sock.sendall("-1\n")
    sock.recv(512)
    sock.sendall("1\n")
    data = sock.recv(1024)
    print data
    if '\n' in data:
        data = data[:data.index('\n')]
    else:
        # receive m=
        sock.recv(512)
    (g,tmp) = eval(data)
    p = tmp+h
    tmp = get_maxfactor(p-1)
    if tmp<maxnumber:
        print 'may be success'
        # skip the for cycle
        sock.sendall('quit\n');
        data = sock.recv(1024)
        print 'receive data: ',data
        data = data[data.index(":")+1:]
        (c1,c2)=eval(data)
        # generate the group
        g = Mod(g, p)
        h = Mod(h, p)
        c1 = Mod(c1, p)
        c2 = Mod(c2, p)
        x = discrete_log(h, g)
        print "x = ", x
        print "Flag: ", long_to_bytes(long(c2 / ( c1 ** x)))
    sock.sendall('quit\n')
    sock.recv(1024)
    sock.close()
    i += 1
```

最后迫于计算机内存不够，，没计算出来，，，有时候会崩，多运行几次。。

## ECC

### 概述

ECC全称为椭圆曲线加密，EllipseCurve Cryptography，是一种基于椭圆曲线数学的公钥密码。与传统的基于大质数因子分解困难性的加密方法不同，ECC依赖于解决椭圆曲线离散对数问题的困难性。它的优势主要在于相对于其它方法，它可以在使用较短秘钥长度的同时保持相同的密码强度。目前椭圆曲线主要采用的有限域有

- 以素数为模的整数域GF(p)，通常在通用处理器上更为有效。
- 特征为2的伽罗华域GF（2^m），可以设计专门的硬件。

### 基本知识

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

### ECC中的ElGamal

这里我们假设用户B要把消息加密后传给用户A。

#### 秘钥生成

用户A先选择一条椭圆曲线$E_q (a,b)$ ，然后选择其上的一个生成元G，假设其阶为n，之后再选择一个正整数$n_a$作为密钥，计算$P_a=n_aG$。

其中，$E_q(a,b), q,G$都会被公开。

公钥为$P_a$，私钥为$n_a $。

#### 加密

用户B在向用户A发送消息m，这里假设消息m已经被编码为椭圆曲线上的点，其加密步骤如下

1. 查询用户A的公钥$E_q(a,b), q, P_a,G$ 。
2. 在(1,q-1) 的区间内选择随机数k 。
3. 根据A的公钥计算点$(x_1,y_1)=kG$ 。
4. 计算点$(x_2,y_2)=kP_a$ ，如果为O，则从第二步重新开始。
5. 计算$C=m+(x_2,y_2)$
6. 将$((x_1,y_1),C)$ 发送给A。

#### 解密

解密步骤如下

1. 利用私钥计算点$n_a(x_1,y_1)=n_akG=kP_a=(x_2,y_2)$。
2. 计算消息$m=C-(x_2,y_2)$ 。

#### 关键点

这里的关键点在于我们即使知道了$(x_1,y_1)$ 也难以知道k，这是由离散对数的问题的难度决定的。

### 例子

参考：https://github.com/sonickun/ctf-crypto-writeups/tree/master/2013/seccon-ctf-quals/cryptanalysis 。

这里我们以2013年SECCON CTF quals 中的 Cryptanalysis为例，题目如下

![](/crypto/asymmetric/discrete_log/example/2013 SECCON CTF quals Cryptanalysis/20140127213558.png)

这里，我们已知椭圆曲线方程以及对应的生成元base，还知道相应的模数以及公钥以及加密后的结果。

但是可以看出的我们的模数太小，我们暴力枚举获取结果。

这里直接参考github上的sage程序，暴力跑出secret key。之后便可以解密了。

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

