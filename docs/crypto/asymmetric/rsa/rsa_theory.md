RSA 加密算法是一种非对称加密算法。在公开密钥加密和电子商业中 RSA 被广泛使用。RSA 是 1977 年由罗纳德·李维斯特（Ron Rivest）、阿迪·萨莫尔（Adi Shamir）和伦纳德·阿德曼（Leonard Adleman）一起提出的。RSA 就是他们三人姓氏开头字母拼在一起组成的。

RSA 算法的可靠性由极大整数因数分解的难度决定。换言之，对一极大整数做因数分解愈困难，RSA 算法愈可靠。假如有人找到一种快速因数分解的算法的话，那么用 RSA 加密的信息的可靠性就肯定会极度下降。但找到这样的算法的可能性是非常小的。如今，只有短的 RSA 秘钥才可能被强力方式解破。到 2017 年为止，还没有任何可靠的攻击 RSA 算法的方式。

## 基本原理

### 公钥与私钥的产生

1. 随机选择两个不同大质数 $p$ 和 $q$，计算 $N = p \times q$
2. 根据欧拉函数，求得 $r=\varphi (N)=\varphi (p)\varphi (q)=(p-1)(q-1)$
3. 选择一个小于 $r$ 的整数 $e$，使 $e$ 和 $r$ 互质。并求得 $e$ 关于 $r$ 的模反元素，命名为 $d$，有 $ed\equiv 1 \pmod r$
4. 将 $p$ 和 $q$ 的记录销毁

此时，$(N,e)$ 是公钥，$(N,d)$ 是私钥。

### 消息加密

首先需要将消息 $m$ 以一个双方约定好的格式转化为一个小于 $N$，且与 $N$ 互质的整数 $n$。如果消息太长，可以将消息分为几段，这也就是我们所说的块加密，后对于每一部分利用如下公式加密：

$$
n^{e}\equiv c\pmod N
$$

### 消息解密

利用密钥 $d$ 进行解密。

$$
c^{d}\equiv n\pmod N
$$

### 正确性证明

即我们要证$n^{ed} \equiv n \bmod N$，已知$ed \equiv 1 \bmod \phi(N)$，那么 $ed=k\phi(N)+1$，即需要证明

$$
n^{k\phi(N)+1}  \equiv n \bmod N
$$

这里我们分两种情况证明

第一种情况 $gcd(n,N)=1$，那么 $n^{\phi(N)} \equiv 1 \bmod N$，因此原式成立。

第二种情况 $gcd(n,N)!=1$，那么 n 必然是 p 或者 q 的倍数，并且 n 小于 N。我们假设

$$
n=xp
$$

那么 x 必然小于 q，又由于 q 是素数。那么

$$
n^{\phi(q)} \equiv 1 \bmod q
$$

进而

$$
n^{k\phi(N)}=n^{k(p-1)(q-1)}=(n^{\phi(q)})^{k(p-1)} \equiv 1 \bmod q
$$

那么

$$
n^{k\phi(N)+1}=n+uqn
$$

进而

$$
n^{k\phi(N)+1}=n+uqxp=n+uxN
$$

所以原式成立。

## 基本工具

### RSAtool

-   安装

    ```bash
    git clone https://github.com/ius/rsatool.git
    cd rsatool
    python rsatool.py -h
    ```

-   生成私钥

    ```bash
    python rsatool.py -f PEM -o private.pem -p 1234567 -q 7654321
    ```

### RSA Converter

- 根据给定密钥对，生成 pem 文件
- 根据 n，e，d 得出 p，q

### openssl

-   查看公钥文件

    ```shell
    openssl rsa -pubin -in pubkey.pem -text -modulus
    ```

-   解密

    ```shell
    rsautl -decrypt -inkey private.pem -in flag.enc -out flag
    ```

更加具体的细节请参考 `openssl --help`。

### 分解整数工具

- 网站分解，[factor.db](http://factordb.com/)
- 命令行分解，[factordb-pycli](https://github.com/ryosan-470/factordb-pycli)，借用 factordb 数据库。
- [yafu](https://sourceforge.net/projects/yafu/)

### python 库

#### primefac

整数分解库，包含了很多整数分解的算法。

#### gmpy

- `gmpy.root(a, b)`，返回一个元组 `(x, y)`，其中 `x` 为 `a` 开 `b` 次方的值，`y` 是判断 `x` 是否为整数的布尔型变量

#### gmpy2

安装时，可能会需要自己另行安装 mfpr 与 mpc 库。

- `gmpy2.iroot(a, b)`，类似于 `gmpy.root(a,b)`

#### pycrypto

-   安装

    ```bash
    sudo pip install pycrypto
    ```

-   使用

    ```python
    import gmpy
    from Crypto.Util.number import *
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5

    msg = 'crypto here'
    p = getPrime(128)
    q = getPrime(128)
    n = p*q
    e = getPrime(64)
    pubkey = RSA.construct((long(n), long(e)))
    privatekey = RSA.construct((long(n), long(e), long(d), long(p), long(q)))
    key = PKCS1_v1_5.new(pubkey)
    enc = key.encrypt(msg).encode('base64')
    key = PKCS1_v1_5.new(privatekey)
    msg = key.decrypt(enc.decode('base64'), e)
    ```

## Jarvis OJ - Basic - veryeasyRSA

> p = 3487583947589437589237958723892346254777 q = 8767867843568934765983476584376578389
>
> e = 65537
>
> 求 d = 
>
> 请提交 `PCTF{d}`

直接根据 $ed\equiv 1 \pmod r$，其中 $r=\varphi (N)=\varphi (p)\varphi (q)=(p-1)(q-1)$，可得 d。

```python
import gmpy2
p = 3487583947589437589237958723892346254777
q = 8767867843568934765983476584376578389
e = 65537
phin = (p - 1) * (q - 1)
print gmpy2.invert(e, phin)
```

```shell
➜  Jarvis OJ-Basic-veryeasyRSA git:(master) ✗ python exp.py       
19178568796155560423675975774142829153827883709027717723363077606260717434369
```

## 2018 CodeGate CTF Rsababy

程序就是一个简单的 RSA，不过程序还生成了两个奇怪的数

```python
e = 65537
n = p * q
pi_n = (p-1)*(q-1)
d = mulinv(e, pi_n)
h = (d+p)^(d-p)
g = d*(p-0xdeadbeef)
```

所以，问题应该出自这里，所以我们就从此下手，不放这里先假设 `const = 0xdeadbeef`。那么

$$
eg = ed*(p-const)
$$

进而，根据 RSA 可知

$$
2^{eg}=2^{ed*(p-const)}=2^{p-const} \pmod n
$$

$$
2^{p-const}*2^{const-1} = 2^{p-1} \pmod n
$$

所以

$$
2^{p-1} = 2^{eg}*2^{const-1}+kn
$$

而与此同时根据费马小定理，我们知道

$$
2^{p-1} \equiv 1 \pmod p
$$

所以

$$
p|2^{p-1}-1 | 2^{eg+const-1}-1+kn
$$

进而

$$
p|2^{eg+const-1}-1
$$

所以

$$
p|gcd(2^{eg+const-1}-1,n)
$$

因此，代码如下

```python
tmp = gmpy2.powmod(2,e*g+const-1,n)-1
p = gmpy2.gcd(tmp,n)
q = n/p
phin = (p-1)*(q-1)
d =gmpy2.invert(e,phin)
plain = gmpy2.powmod(data,d,n)
print hex(plain)[2:].decode('hex')
```
