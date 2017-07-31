# Coppersmith Related  Attack

# 基本原理

首先，我们来简单介绍一下**Coppersmith method** 方法，该方法由[Don Coppersmith](https://en.wikipedia.org/wiki/Don_Coppersmith) 提出，可以用来找到单变量或者二元变量的多项式在模某个整数下的根，这里我们主要以单变量为主，假设我们有如下的一个在模N意义下的多项式F

$F(x)=x^n+a_{n-1}x^{n-1}+\cdots +a_1x+a_0 $

假设该多项式在模N意义下有一个根$x_0$ ，这里我们令$x_0 < M^{\frac{1}{n}}$ 。如果等号成立的话，显然只有$x^n$ 这一项，那0就是，也满足。

**Coppersmith method** 主要是通过[Lenstra–Lenstra–Lovász lattice basis reduction algorithm](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm) (LLL) 方法来找到与该函数具有相同根$x_0$ 但有更小系数的多项式。关于更加详细的介绍，请自行搜索。

# Basic Broadcast Attack

## 攻击条件

如果一个用户使用同一个加密指数e加密了同一个密文，并发送给了其他e个用户。那么就会产生广播攻击。这一攻击由Håstad提出。

## 攻击原理

这里我们假设e为3，并且加密者使用了三个不同的模数$n_1,n_2,n_3$ 给三个不同的用户发送了加密后的消息m，如下
$$
\begin{align}
c\_1&=m^3\bmod n\_1 \\\\
c\_2&=m^3\bmod n\_2 \\\\
c\_3&=m^3\bmod n\_3 \\\\
\end{align}
$$
这里我们假设$n_1,n_2,n_3$ 互相互素，不然，我们就可以直接进行分解，然后得到d，进而然后直接解密。

同时，我们假设$m<n_i, 1\leq i \leq 3$ 。如果这个条件不满足的话，就会使得情况变得比较复杂，这里我们暂不讨论。

既然他们互素，那么我们可以根据中国剩余定理，可得$m^3 \equiv C \bmod n_1n_2n_3$ 。

此外，既然$m<n_i, 1\leq i \leq 3$ ，那么我们知道$m^3 < n_1n_2n_3$ 并且$C<m^3 < n_1n_2n_3$ ，那么$m^3 = C $ ，我们对C开三次根即可得到m的值。

对于较大的e来说，我们只是需要更多的明密文对。

## 例子

参考http://ohroot.com/2016/07/11/rsa-in-ctf。

这里我们以SCTF RSA3中的level4为例进行介绍，首先编写代码提取cap包中的数据，如下

```shell
#!/usr/bin/env python

from scapy.all import *
import zlib
import struct

PA = 24
packets = rdpcap('./syc_security_system_traffic3.pcap')
client = '192.168.1.180'
list_n = []
list_m = []
list_id = []
data = []
for packet in packets:
    # TCP Flag PA 24 means carry data
    if packet[TCP].flags == PA or packet[TCP].flags == PA + 1:
        src = packet[IP].src
        raw_data = packet[TCP].load
        head = raw_data.strip()[:7]
        if head == "We have":
            n, e = raw_data.strip().replace("We have got N is ",
                                            "").split('\ne is ')
            data.append(n.strip())
        if head == "encrypt":
            m = raw_data.replace('encrypted messages is 0x', '').strip()
            data.append(str(int(m, 16)))

with open('./data.txt', 'w') as f:
    for i in range(0, len(data), 2):
        tmp = ','.join(s for s in data[i:i + 2])
        f.write(tmp + '\n')

```

其次，利用得到的数据直接使用中国剩余定理求解。

```python
from functools import reduce
import gmpy
import json, binascii


def modinv(a, m):
    return int(gmpy.invert(gmpy.mpz(a), gmpy.mpz(m)))


def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a * b, n)
    # 并行运算
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * modinv(p, n_i) * p
    return int(sum % prod)


nset = []
cset = []
with open("data.txt") as f:
    now = f.read().strip('\n').split('\n')
    for item in now:
        item = item.split(',')
        nset.append(int(item[0]))
        cset.append(int(item[1]))

m = chinese_remainder(nset, cset)
m = int(gmpy.mpz(m).root(19)[0])
print binascii.unhexlify(hex(m)[2:-1])

```

得到密文，然后再次解密即可得到flag。

```shell
H1sTaDs_B40aDcadt_attaCk_e_are_same_and_smA9l
```

# Broadcast Attack with Linear Padding

对于具有线性填充的情况下，仍然可以攻击，这时候就会使用**Coppersmith method** 的方法了，这里暂不介绍。可以参考

- https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Generalizations

# Related Message Attack

## 攻击条件

当Alice使用同一公钥对两个具有某种线性关系的消息M1与M2 进行加密，并将加密后的消息C1，C2发送给了Bob时，我们就可能可以获得对应的消息M1与M2。这里我们假设模数为N，两者之间的线性关系如下

$M_1 \equiv f(M_2) \bmod N$

其中f为一个线性函数，比如说$f=ax+b$。

在具有较小错误概率下的情况下，其复杂度为$O(elog^2N)$ 。

这一攻击由Franklin，Reiter提出。

## 攻击原理

首先，我们知道$C_1 \equiv M_1 ^e \bmod N$ ，并且$M_1 \equiv f(M_2) \bmod N$ ，那么我们可以知道$M_2$ 是$f(x)^e \equiv C_1 \bmod N$ 的一个解，即它是方程$f(x)^e-C_1$ 在模N意义下的一个根。同样的，$M_2$ 是$x^e - C_2$ 在模N意义下的一个根。所以说$x-M_2$ 同时整除以上两个多项式。因此，我们可以求得两个多项式的最大公因子，如果最大公因子恰好是线性的话，那么我们就求得了$M_2$ 。需要注意的是，在e=3的情况下，最大公因子一定是线性的。

这里我们关注一下e=3，且$f(x)=ax+b$ 的情况。首先我们有

$C_1 \equiv M_1 ^3 \bmod N$ 且$M_1 \equiv aM_2+b \bmod N$

那么我们有

$C_1 \equiv (aM_2+b)^3 \bmod N$ 且$C_2 \equiv M_2^3 \bmod N$

我们需要明确一下我们想要得到的是消息M，所以需要将其单独构造出来。

首先，我们有式1

$(aM_2+b)^3=a^3M_2^3+3a^2M^2b+3aM_2b^2+b^3$ 

再者我们构造如下式2

$(aM_2)^3-b^3 \equiv (aM_2-b)(a^2M_2^2+aM_2b+b^2) \bmod N$

根据式1我们有

$a^3M_2^3-2b^3+3b(a^2M_2^2+aM_2b+b^2) \equiv C_1 \bmod N$

继而我们有式3

$3b(a^2M_2^2+aM_2b+b^2) \equiv C_1-a^3C_2+2b^3 \bmod N$

那么我们根据式2与式3可得

$(a^3C_2-b^3)*3b \equiv (aM_2-b)( C_1-a^3C_2+2b^3 ) \bmod N$

进而我们有

$aM_2-b=\frac{3a^3bC_2-3b^4}{C_1-a^3C_2+2b^3}$

进而

$aM_2\equiv  \frac{2a^3bC_2-b^4+C_1b}{C_1-a^3C_2+2b^3}$

进而

$M_2 \equiv\frac{2a^3bC_2-b^4+C_1b}{aC_1-a^4C_2+2ab^3}=\frac{b}{a}\frac{C_1+2a^3C_2-b^3}{C_1-a^3C_2+2b^3}$

上面的式子中邮编所有的内容都是已知的内容，所以我们可以直接获取对应的消息。

有兴趣的可以进一步阅读[A New Related Message Attack on RSA](https://www.iacr.org/archive/pkc2005/33860001/33860001.pdf) 以及[paper](https://www.cs.unc.edu/~reiter/papers/1996/Eurocrypt.pdf)这里暂不做过多的讲解。

## 例子

这里我们以SCTF rsa3中的level3为例进行介绍。首先，跟踪TCP流可以知道，加密方式是将明文加上用户的user id进行加密，而且还存在多组。这里我们选择第0组和第9组，他们的模数一样，解密脚本如下

```python
import gmpy2
id1 = 1002
id2 = 2614

c1 = 0x547995f4e2f4c007e6bb2a6913a3d685974a72b05bec02e8c03ba64278c9347d8aaaff672ad8460a8cf5bffa5d787c5bb724d1cee07e221e028d9b8bc24360208840fbdfd4794733adcac45c38ad0225fde19a6a4c38e4207368f5902c871efdf1bdf4760b1a98ec1417893c8fce8389b6434c0fee73b13c284e8c9fb5c77e420a2b5b1a1c10b2a7a3545e95c1d47835c2718L
c2 = 0x547995f4e2f4c007e6bb2a6913a3d685974a72b05bec02e8c03ba64278c9347d8aaaff672ad8460a8cf5bffa5d787c72722fe4fe5a901e2531b3dbcb87e5aa19bbceecbf9f32eacefe81777d9bdca781b1ec8f8b68799b4aa4c6ad120506222c7f0c3e11b37dd0ce08381fabf9c14bc74929bf524645989ae2df77c8608d0512c1cc4150765ab8350843b57a2464f848d8e08L
n = 25357901189172733149625332391537064578265003249917817682864120663898336510922113258397441378239342349767317285221295832462413300376704507936359046120943334215078540903962128719706077067557948218308700143138420408053500628616299338204718213283481833513373696170774425619886049408103217179262264003765695390547355624867951379789924247597370496546249898924648274419164899831191925127182066301237673243423539604219274397539786859420866329885285232179983055763704201023213087119895321260046617760702320473069743688778438854899409292527695993045482549594428191729963645157765855337481923730481041849389812984896044723939553
a = 1
b = id1 - id2


def getmessage(a, b, c1, c2, n):
    b3 = gmpy2.powmod(b, 3, n)
    part1 = b * (c1 + 2 * c2 - b3) % n
    part2 = a * (c1 - c2 + 2 * b3) % n
    part2 = gmpy2.invert(part2, n)
    return part1 * part2 % n


message = getmessage(a, b, c1, c2, n) - id2
message = hex(message)[2:]
if len(message) % 2 != 0:
    message = '0' + message

print message.decode('hex')

```

得到明文

```shell
➜  sctf-rsa3-level3 git:(master) ✗ python exp.py
F4An8LIn_rElT3r_rELa53d_Me33Age_aTtaCk_e_I2_s7aLL
```

当然，我们也可以直接使用sage来做，会更加简单一点。

```python
import binascii

def attack(c1, c2, b, e, n):
    PR.<x>=PolynomialRing(Zmod(n))
    g1 = x^e - c1
    g2 = (x+b)^e - c2

    def gcd(g1, g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic()
    return -gcd(g1, g2)[0]

c1 = 0x547995f4e2f4c007e6bb2a6913a3d685974a72b05bec02e8c03ba64278c9347d8aaaff672ad8460a8cf5bffa5d787c5bb724d1cee07e221e028d9b8bc24360208840fbdfd4794733adcac45c38ad0225fde19a6a4c38e4207368f5902c871efdf1bdf4760b1a98ec1417893c8fce8389b6434c0fee73b13c284e8c9fb5c77e420a2b5b1a1c10b2a7a3545e95c1d47835c2718L
c2 = 0x547995f4e2f4c007e6bb2a6913a3d685974a72b05bec02e8c03ba64278c9347d8aaaff672ad8460a8cf5bffa5d787c72722fe4fe5a901e2531b3dbcb87e5aa19bbceecbf9f32eacefe81777d9bdca781b1ec8f8b68799b4aa4c6ad120506222c7f0c3e11b37dd0ce08381fabf9c14bc74929bf524645989ae2df77c8608d0512c1cc4150765ab8350843b57a2464f848d8e08L
n = 25357901189172733149625332391537064578265003249917817682864120663898336510922113258397441378239342349767317285221295832462413300376704507936359046120943334215078540903962128719706077067557948218308700143138420408053500628616299338204718213283481833513373696170774425619886049408103217179262264003765695390547355624867951379789924247597370496546249898924648274419164899831191925127182066301237673243423539604219274397539786859420866329885285232179983055763704201023213087119895321260046617760702320473069743688778438854899409292527695993045482549594428191729963645157765855337481923730481041849389812984896044723939553
e=3
a = 1
id1 = 1002
id2 = 2614
b = id2 - id1
m1 = attack(c1,c2, b,e,n)
print binascii.unhexlify("%x" % int(m1 - id1))
```

结果如下

```shell
➜  sctf-rsa3-level3 git:(master) ✗ sage exp.sage
sys:1: RuntimeWarning: not adding directory '' to sys.path since everybody can write to it.
Untrusted users could put files in this directory which might then be imported by your Python code. As a general precaution from similar exploits, you should not execute Python code from this directory
F4An8LIn_rElT3r_rELa53d_Me33Age_aTtaCk_e_I2_s7aLL
```

## 题目

- hitcon 2014 rsaha

# Coppersmith’s short-pad attack

## 攻击条件

目前在大部分消息加密之前都会进行padding，但是如果padding的长度过短，也有**可能**被很容易地攻击。

## 攻击原理

我们假设爱丽丝要给鲍勃发送消息，首先爱丽丝对要加密的消息M进行随机padding，然后加密得到密文C1，发送给鲍勃。这时，中间人皮特截获了密文。一段时间后，爱丽丝没有收到鲍勃的回复，再次对要加密的消息M进行随机padding，然后加密得到密文C2，发送给Bob。皮特再一次截获。这时，皮特就**可能**可以利用如下原理解密。

这里我们假设模数N的长度为k，并且padding的长度为$m=\lfloor \frac{k}{e^2} \rfloor$ 。此外，假设要加密的消息的长度最多为k-m比特，padding的方式如下

$M_1=2^mM+r_1, 0\leq r_1\leq 2^m$ 

消息M2的padding方式类似。

那么我们可以利用如下的方式来解密。

首先定义

$g_1(x,y)=x^e-C_1$

$g_2(x,y)=(x+y)^e-C_2$

其中$y=r_2-r_1$ 。显然这两个方程具有相同的根M1。然后还有一系列的推导。。。

# Known High Bits Message Attack

## 攻击条件

这里我们假设我们首先加密了消息m，如下

$C\equiv m^d \bmod N$

并且我们假设我们知道消息m的很大的一部分$m_0$ ，即$m=m_0+x$ ，但是我们不知道$x$ 。那么我们就有可能通过该方法进行恢复消息。

## 例子1

可以参考https://github.com/mimoo/RSA-and-LLL-attacks。

## 例子2

# Factoring with High Bits Known

## 攻击条件

当我们知道一个公钥中模数N的一个因子的较高位时，我们就有一定几率来分解N。

## 攻击工具

请参考https://github.com/mimoo/RSA-and-LLL-attacks。上面有使用教程。

## 例子1

参考https://github.com/mimoo/RSA-and-LLL-attacks 。这里我们关注下面的代码

```python
beta = 0.5
dd = f.degree()
epsilon = beta / 7
mm = ceil(beta**2 / (dd * epsilon))
tt = floor(dd * mm * ((1/beta) - 1))
XX = ceil(N**((beta**2/dd) - epsilon)) + 1000000000000000000000000000000000
roots = coppersmith_howgrave_univariate(f, N, beta, mm, tt, XX)
```

其中，

- 必须满足 $q\geq N^{beta}$ ，所以这里给出了$beta=0.5$ ，显然两个因数中必然有一个是大于的。
- XX是$f(x)=q'+x $ 在模q意义下的根的上界，自然我们可以选择调整它，这里其实也表明了我们已知的$q'$ 与因数q之间可能的差距。

# Boneh and Durfee attack

## 攻击条件

当d较小时，满足$d\leq N^{0.292}$ 时，我们可以利用该工具，在一定程度上该工具要比wiener attack要强一些。

## 攻击原理

这里简单说一下原理

首先我们有

$ed \equiv 1 \bmod  \varphi(N)$

进而我们有

$ed =k\varphi(N)+1$ 即 $k \varphi(N) +1 \equiv 0 \bmod e$ 。

又

$\varphi(N)=(p-1)(q-1)=qp-p-q+1=N-p-q+1$

所以

$k(N-p-q+1)+1 \equiv 0 \bmod e$ 

我们假设$A=N+1$，$y=-p-q$ 那么

原式可化为

$f(k,y)=k(A+y)+1 \equiv 0 \bmod e$

如果我们求得了该二元方程的根，那么我们自然也就可以解一元二次方程($N=pq,p+q=-y$)来得到p与q。

## 攻击工具

请参考https://github.com/mimoo/RSA-and-LLL-attacks。上面有使用教程。

## 例子

这里我们以2015年PlaidCTF-CTF-Curious为例进行介绍。

首先题目给了一堆N，e，c。简单看一下可以发现该e比较大。这时候我们可以考虑使用wiener attack，这里我们使用更强的目前介绍的攻击。

核心代码如下

```python
    nlist = list()
    elist = list()
    clist = list()
    with open('captured') as f:
        # read the line {N : e : c} and do nothing with it
        f.readline()
        for i in f.readlines():
            (N, e, c) = i[1:-2].split(" : ")
            nlist.append(long(N,16))
            elist.append(long(e,16))
            clist.append(long(c,16))
    
    for i in range(len(nlist)):
        print 'index i'
        n = nlist[i]
        e = elist[i]
        c = clist[i]
        d = solve(n,e)
        if d==0:
            continue
        else:
            m = power_mod(c, d, n)
            hex_string = "%x" % m
            import binascii
            print "the plaintext:", binascii.unhexlify(hex_string)
            return
```

结果如下

```shell
=== solution found ===
private key found: 23974584842546960047080386914966001070087596246662608796022581200084145416583
the plaintext: flag_S0Y0UKN0WW13N3R$4TT4CK!
```





