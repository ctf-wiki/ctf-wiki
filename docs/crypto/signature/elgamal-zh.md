[EN](./elgamal.md) | [ZH](./elgamal-zh.md)
# ElGamal

RSA的数字签名方案几乎与其加密方案完全一致，只是利用私钥进行了签名。但是，对于ElGamal来说，其签名方案与相应的加密方案具有很大区别。

## 基本原理

### 密钥生成

基本步骤如下

1. 选取一个足够大的素数p（十进制位数不低于160），以便于在$Z_p$ 上求解离散对数问题是困难的。
2. 选取$Z_p^*$ 的生成元g。
3. 随机选取整数d,$0\leq d \leq p-2$ ，并计算$g^d \equiv y \bmod p$ 。

其中私钥为{d}，公钥为{p,g,y} 。

### 签名

A选取随机数$k \in Z_{p-1}$ ，并且gcd(k,p-1)=1，对消息进行签名

$ sig_d(m,k)=(r,s)$ 

其中$r \equiv g^k \bmod p$ ，$s \equiv (m-dr)k^{-1} \bmod p-1$ 。

### 验证

如果 $g^m \equiv y^rr^s \bmod p$ ，那么验证成功，否则验证失败。这里验证成功的原理如下，首先我们有

$$
y^rr^s \equiv g^{dr}g^{ks} \equiv g^{dr+ks}
$$

又因为

$$
s \equiv (m-dr)k^{-1} \bmod p-1
$$

所以

$$
ks \equiv m-dr \bmod p-1
$$

进而

$$
ks+dr=a*(p-1)+m
$$

所以

$$
g^{ks+dr}=g^{a*(p-1)+m}=(g^{p-1})^a*g^m
$$

所以根据费马定理，可得

$$
g^{ks+dr} \equiv g^m \bmod p
$$

### 难点

虽然我们知道了r,但是我们却没有办法知道其对应的k。

## 常见攻击

### p太小

### 随机数k复用

#### 原理

如果签名者复用了随机数k，那么攻击者就可以轻而易举地计算出私钥。具体的原理如下：

假设目前有两个签名都是使用同一个随机数进行签名的。那么我们有

$$
r \equiv g^k \bmod p \\\\ s _1\equiv (m_1-dr)k^{-1} \bmod p-1\\\\ r \equiv g^k \bmod p \\\\ s_2 \equiv (m_2-dr)k^{-1} \bmod p-1
$$

进而有

$$
s_1k \equiv m_1-dr \bmod p-1 \\\\ s_2k \equiv m_2-dr \bmod p-1
$$

两式相减

$$
k(s_1-s_2) \equiv m_1-m_2 \bmod p-1
$$

这里，$s_1,s_2,m_1,m_2,p-1$ 均已知，所以我们可以很容易算出k。当然，如果$gcd(s_1-s_2,p-1)!=1$ 的话，可能会存在多个解，这时我们只需要多试一试。进而，我们可以根据s的计算方法得到私钥d，如下

$$
d \equiv \frac{m-ks}{r}
$$

#### 题目

2016 LCTF Crypto 450

### 通用伪造签名

#### 原理

在攻击者知道了某个人Alice的公钥之后，他可以伪造Alice的签名信息。具体原理如下

这里我们假设，Alice的公钥为{p,g,y}。攻击者可以按照如下方式伪造

1. 选择整数 i，j，其中$gcd(j,p-1)=1$ 。

2. 计算签名，$r \equiv g^iy^j \bmod p$ ，$s\equiv -rj^{-1} \bmod p-1$

3. 计算消息，$m\equiv si \bmod p-1$

那么此时生成的签名与消息就是可以被正常通过验证，具体推导如下

$y^rr^s \equiv g^{dr}g^{is}y^{js} \equiv g^{dr}g^{djs}g^{is} \equiv g^{dr+s(i+dj)} \equiv g^{dr} g^{-rj^{-1}(i+dj)} \equiv g^{dr-dr-rij^{-1}} \equiv g^{si} \bmod p$

又由于消息m的构造方式，所以

$$
g^{si} \equiv g^m \bmod p-1
$$

需要注意的是，攻击者可以伪造通过签名验证的消息，但是他却无法伪造指定格式的消息。而且，一旦消息进行了哈希操作，这一攻击就不再可行。

### 已知签名伪造

参考pdf。

### 选择签名伪造

#### 攻击条件

如果我们可以选择我们消息进行签名，并且可以得到签名，那么我们可以对一个新的但是我们不能够选择签名的消息伪造签名。

#### 攻击原理

我们知道，最后验证的过程如下

 $g^m \equiv y^rr^s \bmod p$ 

那么只要我们选择一个消息m使其和我们所要伪造的消息m‘模p-1同余，然后同时使用消息m的签名即可绕过。

#### 例子

这里以2017年国赛mailbox为例，**i春秋有复现**。

首先，我们来分析一下程序，我们首先需要进行proof of work


```python
	proof = b64.b64encode(os.urandom(12))
	req.sendall(
        "Please provide your proof of work, a sha1 sum ending in 16 bit's set to 0, it must be of length %d bytes, starting with %s\n" % (
        len(proof) + 5, proof))

    test = req.recv(21)
    ha = hashlib.sha1()
    ha.update(test)

    if (test[0:16] != proof or ord(ha.digest()[-1]) != 0 or ord(ha.digest()[-2]) != 0): # or ord(ha.digest()[-3]) != 0 or ord(ha.digest()[-4]) != 0):
        req.sendall("Check failed")
        req.close()
        return 
```
我们需要生成一个以proof开头的长度为proof长度加5的字符串，并且其sha1的值以16比特的0结束。

这里我们直接使用如下的方式来绕过。

```python
def f(x):
    return sha1(prefix + x).digest()[-2:] == '\0\0'


sh = remote('106.75.66.195', 40001)
# bypass proof
sh.recvuntil('starting with ')
prefix = sh.recvuntil('\n', drop=True)
print string.ascii_letters
s = util.iters.mbruteforce(f, string.ascii_letters + string.digits, 5, 'fixed')
test = prefix + s
sh.sendline(test)
```

这里使用了pwntools中的util.iters.mbruteforce，这是一个利用给定字符集合以及指定长度进行多线程爆破的函数。其中，第一个参数为爆破函数，这里是sha1，第二个参数是字符集，第三个参数是字节数，第四个参数指的是我们只尝试字节数为第三个参数指定字节数的排列，即长度是固定的。更加具体的信息请参考pwntools。

绕过之后，我们继续分析程序，简单看下generate_keys函数，可以知道该函数是ElGamal生成公钥的过程，然后看了看verify函数，就是验证签名的过程。

继续分析

```python
            if len(msg) > MSGLENGTH:
                req.sendall("what r u do'in?")
                req.close()
                return
            if msg[:4] == "test":
                r, s = sign(digitalize(msg), sk, pk, p, g)
                req.sendall("Your signature is" + repr((hex(r), hex(s))) + "\n")
            else:
                if msg == "Th3_bery_un1que1i_ChArmIng_G3nji" + test:
                    req.sendall("Signature:")
                    sig = self.rfile.readline().strip()
                    if len(sig) > MSGLENGTH:
                        req.sendall("what r u do'in?")
                        req.close()
                        return
                    sig_rs = sig.split(",")
                    if len(sig_rs) < 2:
                        req.sendall("yo what?")
                        req.close()
                        return
                    # print "Got sig", sig_rs
                    if verify(digitalize(msg), int(sig_rs[0]), int(sig_rs[1]), pk, p, g):
                        req.sendall("Login Success.\nDr. Ziegler has a message for you: " + FLAG)
                        print "shipped flag"
                        req.close()
                        return
                    else:
                        req.sendall("You are not the Genji I knew!\n")
```

根据这三个if条件可以知道

- 我们的消息长度不能超过MSGLENGTH，40000。
- 我们可以对消息开头为test的消息进行签名。
- 我们需要使得以Th3_bery_un1que1i_ChArmIng_G3nji开头，以我们绕过proof的test为结尾的消息通过签名验证，其中，我们可以自己提供签名的值。

分析到这里，其实就知道了，我们就是在选择指定签名进行伪造，这里我们自然要充分利用第二个if条件，只要我们确保我们输入的消息的开头为‘test’，并且该消息与以Th3_bery_un1que1i_ChArmIng_G3nji开头的固定消息模p-1同余，我们即可以通过验证。

那我们如何构造呢？既然消息的长度可以足够长，那么我们可以将'test'对应的16进制先左移得到比p-1大的数字a，然后用a对p-1取模，用a再减去余数，此时a模p-1余0了。这时再加上以Th3_bery_un1que1i_ChArmIng_G3nji开头的固定消息的值，即实现了模p-1同余。

具体如下

```python
# construct the message begins with 'test'
target = "Th3_bery_un1que1i_ChArmIng_G3nji" + test
part1 = (digitalize('test' + os.urandom(51)) << 512) // (p - 1) * (p - 1)
victim = part1 + digitalize(target)
while 1:
    tmp = hex(victim)[2:].decode('hex')
    if tmp.startswith('test') and '\n' not in tmp:
        break
    else:
        part1 = (digitalize('test' + os.urandom(51)) << 512) // (p - 1) * (
            p - 1)
        victim = part1 + digitalize(target)
```

最后的脚本如下

```python
from pwn import *
from hashlib import sha1
import string
import ast
import os
import binascii
context.log_level = 'debug'


def f(x):
    return sha1(prefix + x).digest()[-2:] == '\0\0'


def digitalize(m):
    return int(m.encode('hex'), 16)


sh = remote('106.75.66.195', 40001)
# bypass proof
sh.recvuntil('starting with ')
prefix = sh.recvuntil('\n', drop=True)
print string.ascii_letters
s = util.iters.mbruteforce(f, string.ascii_letters + string.digits, 5, 'fixed')
test = prefix + s
sh.sendline(test)

sh.recvuntil('Current PK we are using: ')
pubkey = ast.literal_eval(sh.recvuntil('\n', drop=True))
p = pubkey[0]
g = pubkey[1]
pk = pubkey[2]

# construct the message begins with 'test'
target = "Th3_bery_un1que1i_ChArmIng_G3nji" + test
part1 = (digitalize('test' + os.urandom(51)) << 512) // (p - 1) * (p - 1)
victim = part1 + digitalize(target)
while 1:
    tmp = hex(victim)[2:].decode('hex')
    if tmp.startswith('test') and '\n' not in tmp:
        break
    else:
        part1 = (digitalize('test' + os.urandom(51)) << 512) // (p - 1) * (
            p - 1)
        victim = part1 + digitalize(target)

assert (victim % (p - 1) == digitalize(target) % (p - 1))

# get victim signature
sh.sendline(hex(victim)[2:].decode('hex'))
sh.recvuntil('Your signature is')
sig = ast.literal_eval(sh.recvuntil('\n', drop=True))
sig = [int(sig[0], 0), int(sig[1], 0)]

# get flag
sh.sendline(target)
sh.sendline(str(sig[0]) + "," + str(sig[1]))
sh.interactive()
```

这里还要说几个有意思的点就是

- int(x,0)只的是将x按照其字面对应的进制转换为对应的数字，比如说int('0x12',0)=18，这里相应的字面必须有对应标志开头，比如说十六进制是0x,8进制是0，二进制是0b。因为如果没有的话，就不知道该如何识别了。
- python(python2) 里面到底多大的数，计算出来最后才会带有L呢？正常情况下，大于int都会有L。但是这个里面的victim确实是没有的，， **一个问题，待解决。。**
