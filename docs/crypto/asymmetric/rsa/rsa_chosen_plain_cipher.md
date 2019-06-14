# RSA 选择明密文攻击

## 选择明文攻击

这里给出一个例子，假如我们有一个加密 oracle ，但是我们不知道 n 和 e，那

1. 我们可以通过加密 oracle 获取 n。
2. 在 e 比较小（ $e<2^{64}$）时，我们可以利用 *Pollard’s kangaroo algorithm* 算法获取 e。这一点比较显然。

我们可以加密 2，4，8，16。那么我们可以知道

$c_2=2^{e} \bmod n$

$c_4=4^{e} \bmod n$

$c_8=8^{e} \bmod n$

那么

$c_2^2 \equiv c_4 \bmod n$

$c_2^3 \equiv c_8 \bmod n$

故而

$c_2^2-c_4=kn$

$c_2^3-c_8=tn$

我们可以求出 kn 和 tn 的最大公因数，很大概率就是 n 了。我们还可以构造更多的例子从来更加确定性地找 n。

## 任意密文解密

假设爱丽丝创建了密文 $C = P^e \bmod n$ 并且把 C 发送给鲍勃，同时假设我们要对爱丽丝加密后的任意密文解密，而不是只解密 C，那么我们可以拦截 C，并运用下列步骤求出 P：

1. 选择任意的 $X\in Z_n^{*}$，即 X 与 N 互素
2. 计算 $Y=C \times X^e \bmod n$ 
3. 由于我们可以进行选择密文攻击，那么我们求得 Y 对应的解密结果 $Z=Y^d$
4. 那么，由于 $Z=Y^d=(C \times X^e)^d=C^d X=P^{ed} X= P X\bmod n$，由于 X 与 N 互素，我们很容易求得相应的逆元，进而可以得到 P

## RSA parity oracle

假设目前存在一个 Oracle，它会对一个给定的密文进行解密，并且会检查解密的明文的奇偶性，并根据奇偶性返回相应的值，比如 1 表示奇数，0 表示偶数。那么给定一个加密后的密文，我们只需要 log(N) 次就可以知道这个密文对应的明文消息。

### 原理

假设

$C=P^e \bmod N$

第一次时，我们可以给服务器发送

$C*2^e=(2P)^e \bmod N$

服务器会计算得到

$2P \bmod N$

这里

- 2P 是偶数，它的幂次也是偶数。
- N 是奇数，因为它是由两个大素数相乘得到。

那么


- 服务器返回奇数，即 $2P \bmod N$ 为奇数，则说明 2P 大于 N，且减去了奇数个 N，又因为 $2P<2N$，因此减去了一个N， 即 $\frac{N}{2} \leq P < N$，我们还可以考虑向下取整。
- 服务器返回偶数，则说明 2P 小于 N。即 $0\leq P < \frac{N}{2}$，我们还可以向下取整。

这里我们使用数学归纳法，即假设在第 i 次时，$\frac{xN}{2^{i}} \leq P < \frac{xN+N}{2^{i}}$


进一步，在第 i+1 次时，我们可以发送

$C*2^{(i+1)e}$

服务器会计算得到

$2^{i+1}P \bmod N=2^{i+1}P-kN$

$0 \leq 2^{i+1}P-kN<N$ 

$\frac{kN}{2^{i+1}} \leq P < \frac{kN+N}{2^{i+1}}$

根据第 i 次的结果

$\frac{2xN}{2^{i+1}} \leq P < \frac{2xN+2N}{2^{i+1}}$

那么

- 服务器返回奇数，则 k 必然是一个奇数，k=2y+1， 那么 $\frac{2yN+N}{2^{i+1}} \leq P < \frac{2yN+2N}{2^{i+1}}$。与此同时，由于 P 必然存在，所以第 i+1 得到的这个范围和第 i 次得到的范围必然存在交集。所以 y 必然与 x 相等。
- 服务器返回偶数，则 k 必然是一个偶数，k=2y，此时 y 必然也与 x 相等，那么 $\frac{2xN}{2^{i+1}} \leq P < \frac{2xN+N}{2^{i+1}}$

进一步我们可以这么归纳

```c
lb = 0
ub = N
if server returns 1
	lb = (lb+ub)/2
else:
	ub = (lb+ub)/2
```

这里虽然是整除， 即下取整，但是无所谓我们在最初时已经分析了这个问题。

### 2018 Google CTF Perfect Secrecy

这里以 2018 年 Google CTF 的题目为例进行分析

```python
#!/usr/bin/env python3
import sys
import random

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def ReadPrivateKey(filename):
  return serialization.load_pem_private_key(
      open(filename, 'rb').read(), password=None, backend=default_backend())


def RsaDecrypt(private_key, ciphertext):
  assert (len(ciphertext) <=
          (private_key.public_key().key_size // 8)), 'Ciphertext too large'
  return pow(
      int.from_bytes(ciphertext, 'big'),
      private_key.private_numbers().d,
      private_key.public_key().public_numbers().n)


def Challenge(private_key, reader, writer):
  try:
    m0 = reader.read(1)
    m1 = reader.read(1)
    ciphertext = reader.read(private_key.public_key().key_size // 8)
    dice = RsaDecrypt(private_key, ciphertext)
    for rounds in range(100):
      p = [m0, m1][dice & 1]
      k = random.randint(0, 2)
      c = (ord(p) + k) % 2
      writer.write(bytes((c,)))
    writer.flush()
    return 0

  except Exception as e:
    return 1


def main():
  private_key = ReadPrivateKey(sys.argv[1])
  return Challenge(private_key, sys.stdin.buffer, sys.stdout.buffer)


if __name__ == '__main__':
  sys.exit(main())
```

可以看出

- 我们可以给服务器两个数，服务器会根据解密后的密文内容来决定使用哪一个。
- 服务器会使用 `random.randint(0, 2)` 来生成随机数，并输出相关的随机 01 字节 c。

乍一看，似乎是完全随机的，仔细查一下 `random.randint(0, 2)` 可以知道其生成随机数是包括边界的，因此其生成偶数的概率大于生成奇数的概率，那么 c 与 p 同奇偶的概率为 2/3。进而我们通过设置 m0 和 m1 就可以知道解密后的密文的最后一位是 0 还是 1 。这其实就是 RSA parity oracle。

exp 如下

```python
import gmpy2
from pwn import *
encflag = open('./flag.txt').read()
encflag = encflag.encode('hex')
encflag = int(encflag, 16)
#context.log_level = 'debug'
m = ['\x00', '\x07']
n = 0xDA53A899D5573091AF6CC9C9A9FC315F76402C8970BBB1986BFE8E29CED12D0ADF61B21D6C281CCBF2EFED79AA7DD23A2776B03503B1AF354E35BF58C91DB7D7C62F6B92C918C90B68859C77CAE9FDB314F82490A0D6B50C5DC85F5C92A6FDF19716AC8451EFE8BBDF488AE098A7C76ADD2599F2CA642073AFA20D143AF403D1
e = 65537
flag = ""



def guessvalue(cnt):
    if cnt[0] > cnt[1]:
        return 0
    return 1


i = 0
while True:
    cnt = dict()
    cnt[0] = cnt[1] = 0
    p = remote('perfect-secrecy.ctfcompetition.com', 1337)
    p.send(m[0])
    p.send(m[1])
    tmp = pow(2, i)
    two_inv = gmpy2.invert(tmp, n)
    two_cipher = gmpy2.powmod(two_inv, e, n)
    tmp = encflag * two_cipher % n
    tmp = hex(tmp)[2:].strip('L')
    tmp = '0' * (256 - len(tmp)) + tmp
    tmp = tmp.decode('hex')
    assert (len(tmp) == 128)
    p.send(tmp)
    #print tmp
    data = ""
    while (len(data) != 100):
        data += p.recv()
    for c in data:
        cnt[u8(c)] += 1
    p.close()
    flag = str(guessvalue(cnt)) + flag
    print i, flag
    i += 1
```

结果如下

```shell
6533021797450432625003726192285181680054061843303961161444459679874621880787893445342698029728203298974356255732086344166897556918532195998159983477294838449903429031335408290610431938507208444225296242342845578895553611385588996615744823221415296689514934439749745119968629875229882861818946483594948270 6533021797450432625003726192285181680054061843303961161444459679874621880787893445342698029728203298974356255732086344166897556918532195998159983477294838449903429031335408290610431938507208444225296242342845578895553611385588996615744823221415296689514934439749745119968629875229882861818946483594948270
```

解码后就可以得到 flag

```shell
CTF{h3ll0__17_5_m3_1_w45_w0nd3r1n6_1f_4f73r_4ll_7h353_y34r5_y0u_d_l1k3_70_m337}
```

### 题目

- 2016 Plaid CTF rabit
- 2016 sharif CTF lsb-oracle-150
- 2018 Backdoor CTF  BIT-LEAKER
- 2018 XMAN 选拔赛 baby RSA

## RSA Byte Oracle

假设目前存在一个 Oracle，它会对一个给定的密文进行解密，并且会给出明文的最后一个字节。那么给定一个加密后的密文，我们只需要 $\log_{256}n$ 次就可以知道这个密文对应的明文消息。

### 原理

这个其实算作 RSA parity Oracle 的扩展，既然可以泄露出最后一个字节，那么按道理我们获取密文对应明文的次数应该可以减少。

假设

$C=P^e \bmod N$

第一次时，我们可以给服务器发送

$C*256^e=(256P)^e \bmod N$

服务器会计算得到

$256P \bmod N$

这里

- 256P 是偶数。
- N 是奇数，因为它是由两个大素数相乘得到。

由于 P 一般是小于 N 的，那么$256P \bmod N=256P-kn, k<256$。而且对于两个不同的 $k_1,k_2$，我们有

$256P-k_1n \not\equiv 256P-k_2n \bmod 256$

我们可以利用反证法来证明上述不等式。同时 $256P-kn$ 的最后一个字节其实就是 $-kn$ 在模 256 的情况下获取的。那么，其实我们可以首先枚举出 0~255 情况下的最后一个字节，构造一个 k 和最后一个字节的映射表 map

当服务器返回最后一个字节 b，那么我们可以根据上述构造的映射表得知 k，即减去了 k 个N， 即 $kN \leq 256 P \leq (k+1)N$。

此后，我们使用数学归纳法来获取 P 的范围，即假设在第 i 次时，$\frac{xN}{256^{i}} \leq P < \frac{xN+N}{256^{i}}$

进一步，在第 i+1 次时，我们可以发送

$C*256^{(i+1)e}$

服务器会计算得到

$256^{i+1}P \bmod N=256^{i+1}P-kN$

$0 \leq 256^{i+1}P-kN<N$ 

$\frac{kN}{256^{i+1}} \leq P < \frac{kN+N}{256^{i+1}}$

根据第 i 次的结果

$\frac{256xN}{256^{i+1}} \leq P < \frac{256xN+256N}{256^{i+1}}$

我们这里可以假设 $k=256y+t$， 而这里的 t 就是我们可以通过映射表获取的。

 $\frac{256yN+tN}{256^{i+1}} \leq P < \frac{256yN+(t+1)N}{256^{i+1}}$

与此同时，由于 P 必然存在，所以第 i+1 得到的这个范围和第 i 次得到的范围必然存在交集。

所以 y 必然与 x 相等。

进一步我们可以这么归纳，初始情况下

```
lb = 0
ub = N
```

假设服务器返回了 b，那么

```c
k = mab[b]
interval = (ub-lb)/256
lb = lb + interval * k
ub = lb + interval
```

### 2018 HITCON lost key

这是一个综合题目，首先没有给出 n，我们可以使用选择明文攻击的方式获取 n，当然我们也可以进一步获取 e，最后利用代码如下

```python
from pwn import *
import gmpy2
from fractions import Fraction
p = process('./rsa.py')
#p = remote('18.179.251.168', 21700)
#context.log_level = 'debug'
p.recvuntil('Here is the flag!\n')
flagcipher = int(p.recvuntil('\n', drop=True), 16)


def long_to_hex(n):
    s = hex(n)[2:].rstrip('L')
    if len(s) % 2: s = '0' + s
    return s


def send(ch, num):
    p.sendlineafter('cmd: ', ch)
    p.sendlineafter('input: ', long_to_hex(num))
    data = p.recvuntil('\n')
    return int(data, 16)


if __name__ == "__main__":
    # get n
    cipher2 = send('A', 2)
    cipher4 = send('A', 4)
    nset = []
    nset.append(cipher2 * cipher2 - cipher4)

    cipher3 = send('A', 3)
    cipher9 = send('A', 9)
    nset.append(cipher3 * cipher3 - cipher9)
    cipher5 = send('A', 5)
    cipher25 = send('A', 25)
    nset.append(cipher5 * cipher5 - cipher25)
    n = nset[0]
    for item in nset:
        n = gmpy2.gcd(item, n)

    # get map between k and return byte
    submap = {}
    for i in range(0, 256):
        submap[-n * i % 256] = i

    # get cipher256
    cipher256 = send('A', 256)

    back = flagcipher

    L = Fraction(0, 1)
    R = Fraction(1, 1)
    for i in range(128):
        print i
        flagcipher = flagcipher * cipher256 % n
        b = send('B', flagcipher)
        k = submap[b]
        L, R = L + (R - L) * Fraction(k, 256
                                     ), L + (R - L) * Fraction(k + 1, 256)
    low = int(L * n)
    print long_to_hex(low - low % 256 + send('B', back)).decode('hex')
```

## 参考

- https://crypto.stackexchange.com/questions/11053/rsa-least-significant-bit-oracle-attack
- https://pastebin.com/KnEUSMxp
