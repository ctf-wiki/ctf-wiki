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

## 2018 Code Blue lagalem

题目描述如下

```python
from Crypto.Util.number import *
from key import FLAG

size = 2048
rand_state = getRandomInteger(size // 2)


def keygen(size):
    q = getPrime(size)
    k = 2
    while True:
        p = q * k + 1
        if isPrime(p):
            break
        k += 1
    g = 2
    while True:
        if pow(g, q, p) == 1:
            break
        g += 1
    A = getRandomInteger(size) % q
    B = getRandomInteger(size) % q
    x = getRandomInteger(size) % q
    h = pow(g, x, p)
    return (g, h, A, B, p, q), (x,)


def rand(A, B, M):
    global rand_state
    rand_state, ret = (A * rand_state + B) % M, rand_state
    return ret


def encrypt(pubkey, m):
    g, h, A, B, p, q = pubkey
    assert 0 < m <= p
    r = rand(A, B, q)
    c1 = pow(g, r, p)
    c2 = (m * pow(h, r, p)) % p
    return (c1, c2)


# pubkey, privkey = keygen(size)

m = bytes_to_long(FLAG)
c1, c2 = encrypt(pubkey, m)
c1_, c2_ = encrypt(pubkey, m)

print pubkey
print(c1, c2)
print(c1_, c2_)
```

可以看出，该算法就是一个 ElGamal 加密，给了同一个明文两组加密后的结果，其特点在于使用的随机数 r 是通过线性同余生成器生成的，则我们知道

$c2 \equiv m * h^{r} \bmod p$

$c2\_ \equiv m*h^{(Ar+B) \bmod q} \equiv m*h^{Ar+B}\bmod p$

则

$c2^A*h^B/c2\_ \equiv m^{A-1}\bmod p$

其中，c2，c2_，A，B，h 均知道。则我们知道

$m^{A-1} \equiv t \bmod p$

我们假设已知 p 的一个原根 g，则我们可以假设

$g^x \equiv t$

$g^y \equiv m$

则

$g^{y(A-1)}\equiv g^x \bmod p$

则

$y(A-1) \equiv x \bmod p-1$

进而我们知道

$y(A-1)-k(p-1)=x$

这里我们知道 A，p，x，则我们可以利用扩展欧几里得定理求得

$s(A-1)+w(p-1)=gcd(A-1,t-1)$

如果gcd(A-1,t-1)=d，则我们直接计算

$t^s \equiv m^{s(A-1)} \equiv m^d \bmod p$

如果 d=1，则直接知道 m。

如果 d 不为1，则就有点麻烦了。。

这里这道题目中恰好 d=1，因此可以很容易进行求解。

```python
import gmpy2
data = open('./transcript.txt').read().split('\n')
g, h, A, B, p, q = eval(data[0])

c1, c2 = eval(data[1])
c1_, c2_ = eval(data[2])

tmp = gmpy2.powmod(c2, A, p) * gmpy2.powmod(h, B, p) * gmpy2.invert(c2_, p)
tmp = tmp % p

print 't=', tmp
print 'A=', A
print 'p=', p
gg, x, y = gmpy2.gcdext(A - 1, p - 1)
print gg

m = gmpy2.powmod(tmp, x, p)
print hex(m)[2:].decode('hex')
```

flag

```shell
➜  2018-CodeBlue-lagalem git:(master) ✗ python exp.py
t= 24200833701856688878756977616650401715079183425722900529883514170904572086655826119242478732147288453761668954561939121426507899982627823151671207325781939341536650446260662452251070281875998376892857074363464032471952373518723746478141532996553854860936891133020681787570469383635252298945995672350873354628222982549233490189069478253457618473798487302495173105238289131448773538891748786125439847903309001198270694350004806890056215413633506973762313723658679532448729713653832387018928329243004507575710557548103815480626921755313420592693751934239155279580621162244859702224854316335659710333994740615748525806865323
A= 22171697832053348372915156043907956018090374461486719823366788630982715459384574553995928805167650346479356982401578161672693725423656918877111472214422442822321625228790031176477006387102261114291881317978365738605597034007565240733234828473235498045060301370063576730214239276663597216959028938702407690674202957249530224200656409763758677312265502252459474165905940522616924153211785956678275565280913390459395819438405830015823251969534345394385537526648860230429494250071276556746938056133344210445379647457181241674557283446678737258648530017213913802458974971453566678233726954727138234790969492546826523537158
p= 36416598149204678746613774367335394418818540686081178949292703167146103769686977098311936910892255381505012076996538695563763728453722792393508239790798417928810924208352785963037070885776153765280985533615624550198273407375650747001758391126814998498088382510133441013074771543464269812056636761840445695357746189203973350947418017496096468209755162029601945293367109584953080901393887040618021500119075628542529750701055865457182596931680189830763274025951607252183893164091069436120579097006203008253591406223666572333518943654621052210438476603030156263623221155480270748529488292790643952121391019941280923396132717
1
CBCTF{183a3ce8ed93df613b002252dfc741b2}
```

## 参考

- https://www.math.auckland.ac.nz/~sgal018/crypto-book/solns.pdf，20.4.1