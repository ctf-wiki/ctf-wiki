# 原理

## 公钥与私钥的产生

1. 随机选择两个不同大质数 $p$ 和 $q$，计算 $N=p \times q$。
2. 根据欧拉函数，求得 $r=\varphi (N)=\varphi (p)\varphi (q)=(p-1)(q-1)$。
3. 选择一个小于 $r$ 的整数 $e$，使 $e$ 和 $r$ 互质。并求得 $e$ 关于 $r$ 的模反元素，命名为 $d$（ $ed\equiv 1 \pmod r$）。
4. 将 $p$ 和 $q$ 的记录销毁。

此时，$(N,e)$ 是公钥，$(N,d)$ 是私钥。

## 消息加密

首先需要将消息 $m$ 以一个双方约定好的格式转化为一个小于 $N$，且与 $N$ 互质的整数 $n$。如果消息太长，可以将消息分为几段，这也就是我们所说的块加密，后对于每一部分利用如下公式加密：
$$
n^{e}\equiv c\pmod N
$$

## 消息解密

利用密钥 $d$ 进行解密。
$$
c^{d}\equiv n\pmod N
$$


# 基本工具

## RSAtool

- 安装

  ```bash
  git clone https://github.com/ius/rsatool.git
  cd rsatool
  python rsatool.py -h
  ```

功能：

- 生成私钥

  ```bash
  python rsatool.py -f PEM -o private.pem -p 1234567 -q 7654321
  ```

关于更多的功能请参考readme。

## RSA Converter

- 根据给定密钥对，生成 pem 文件
- **根据 n，e，d 得出p，q**

## openssl

- 查看公钥文件

  ```bash
  openssl rsa -pubin -in pubkey.pem -text -modulus
  ```

- 解密

  ```bash
  rsautl -decrypt -inkey private.pem -in flag.enc -out flag
  ```

更加具体的细节请参考 `openssl --help`。

## 分解整数工具

- [factor.db](http://factordb.com/)
- [yafu](https://sourceforge.net/projects/yafu/)

## python 库

### gmpy

常见用法

- `gmpy.root(a, b)`，返回一个元组 `(x, y)`，其中 `x` 为 `a` 开 `b` 次方的值，`y`是判断 `x` 是否为整数的布尔型变量。

### gmpy2

安装时，可能会需要自己另行安装mfpr与mpc库。

常见用法

- `gmpy2.iroot(a, b)`， 类似于gmpy.root(a,b)

### pycrypto

- 安装

  ```bash
  sudo pip install pycrypto
  ```

- 使用

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

更多的细节请参考readme。

# 简单练手

这里我们以Jarvis OJ - Basic - veryeasyRSA为例进行介绍，题目如下

> p = 3487583947589437589237958723892346254777 q = 8767867843568934765983476584376578389
>
> e = 65537
>
> 求d = 
>
> 请提交PCTF{d}

直接根据$ed\equiv 1 \pmod r$ ，其中 $r=\varphi (N)=\varphi (p)\varphi (q)=(p-1)(q-1)$， 可得d。exp在example/Jarvis OJ-Basic-veryeasyRSA目录下，其结果如下

```shell
➜  Jarvis OJ-Basic-veryeasyRSA git:(master) ✗ python exp.py       
19178568796155560423675975774142829153827883709027717723363077606260717434369
```



