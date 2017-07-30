# 私钥d

# d泄露攻击

## 攻击原理

首先当d泄露之后，我们自然可以解密所有加密的消息。我们甚至还可以对模数N进行分解。其基本原理如下

我们知道$ed \equiv 1 \bmod \varphi(n)$，那么$ \varphi(n) | k=ed-1$。显然k是一个偶数，我们可以令$k=2^tr$ ，其中r为奇数，t不小于1。那么对于任何的与N互素的数g，我们都有$g^k \equiv 1 \bmod n$ 。那么$z=g^{\frac{k}{2}}$ 是模N的二次方根。那么我们有

$z^2 \equiv 1 \bmod p$

$z^2 \equiv 1 \bmod q$

进而我们我们知道方程有以下四个解，前两个是

$x \equiv \pm1 \bmod N$ 

后两个是$\pm x$ ，其中x满足以下条件

$x \equiv 1 \bmod p$

$x \equiv -1 \bmod q$

显然，$z=g^{\frac{k}{2}}$ 满足的是后面那个条件，我们可以计算$gcd(z-1,N)$ 来对N进行分解。

## 工具

利用以下工具可以直接进行计算

- RsaConverter.exe



# Wiener's Attack

## 攻击条件

在d比较小( $d<\frac{1}{3}N^{\frac{1}{4}}$ )时，攻击者可以使用**wiener's attack** 来获得RSA的私钥。

## 攻击原理

- https://en.wikipedia.org/wiki/Wiener%27s_attack
- https://sagi.io/2016/04/crypto-classics-wieners-rsa-attack/

## 工具

- https://github.com/pablocelayes/rsa-wiener-attack

