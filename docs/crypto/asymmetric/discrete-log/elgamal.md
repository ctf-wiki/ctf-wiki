# ElGamal

## 概述

ElGamal算法的安全性是基于求解离散对数问题的困难性，于1984年提出，也是一种双钥密码体制，既可以用于加密又可用于数字签名。

如果我们假设p是至少是160位的十进制素数，**并且p-1有大素因子**，此外g是 $Z_p^*$  的生成元，并且 $y \in Z_p^*$  。那么如何找到一个唯一的整数x($0\leq x \leq p-2$) ，满足$g^x \equiv y \bmod p$ 在算法上是困难的，这里将x记为$x=log_gy$ 。

## 基本原理

这里我们假设A要给B发送消息m。

### 密钥生成

基本步骤如下

1. 选取一个足够大的素数p，以便于在$Z_p$ 上求解离散对数问题是困难的。
2. 选取$Z_p^*$ 的生成元g。
3. 随机选取整数k,$0\leq k \leq p-2$ ，并计算$g^k \equiv y \bmod p$ 。

其中私钥为{k}，公钥为{p,g,y} 。

### 加密

A选取随机数$r \in Z_{p-1}$ ，对明文加密$E_k(m,r)=(y_1,y_2)$ 。其中$y_1 \equiv g^r \bmod p$ ，$y_2 \equiv my^r \bmod p$ 。

### 解密

$D_k(y_1,y_2)=y_2(y_1^k)^-1 \bmod p \equiv m(g^k)^r(g^{rk})^{-1} \equiv m \bmod p$ 。

### 难点

虽然我们知道了y1,但是我们却没有办法知道其对应的r。

## 2015 MMA CTF Alicegame

这里我们以2015年 MMA-CTF-2015 中的 Alicegame 为例进行介绍。这题最初在没有给出源码的时候却是比较难做，因为这个给一个 m，给一个 r 就得到加密结果，，这太难想。

我们来简单分析一下源码，首先程序最初生成了 pk 与 sk

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