# RSA 選擇明密文攻擊

## 選擇明文攻擊

這裏給出一個例子，假如我們有一個加密 oracle ，但是我們不知道 n 和 e，那

1. 我們可以通過加密 oracle 獲取 n。
2. 在 e 比較小（ $e<2^{64}$）時，我們可以利用 *Pollard’s kangaroo algorithm* 算法獲取 e。這一點比較顯然。

我們可以加密 2，4，8，16。那麼我們可以知道

$c_2=2^{e} \bmod n$

$c_4=4^{e} \bmod n$

$c_8=8^{e} \bmod n$

那麼

$c_2^2 \equiv c_4 \bmod n$

$c_2^3 \equiv c_8 \bmod n$

故而

$c_2^2-c_4=kn$

$c_2^3-c_8=tn$

我們可以求出 kn 和 tn 的最大公因數，很大概率就是 n 了。我們還可以構造更多的例子從來更加確定性地找 n。

## 任意密文解密

假設愛麗絲創建了密文 $C = P^e \bmod n$ 並且把 C 發送給鮑勃，同時假設我們要對愛麗絲加密後的任意密文解密，而不是隻解密 C，那麼我們可以攔截 C，並運用下列步驟求出 P：

1. 選擇任意的 $X\in Z_n^{*}$，即 X 與 N 互素
2. 計算 $Y=C \times X^e \bmod n$ 
3. 由於我們可以進行選擇密文攻擊，那麼我們求得 Y 對應的解密結果 $Z=Y^d$
4. 那麼，由於 $Z=Y^d=(C \times X^e)^d=C^d X=P^{ed} X= P X\bmod n$，由於 X 與 N 互素，我們很容易求得相應的逆元，進而可以得到 P

## RSA parity oracle

假設目前存在一個 Oracle，它會對一個給定的密文進行解密，並且會檢查解密的明文的奇偶性，並根據奇偶性返回相應的值，比如 1 表示奇數，0 表示偶數。那麼給定一個加密後的密文，我們只需要 log(N) 次就可以知道這個密文對應的明文消息。

### 原理

假設

$C=P^e \bmod N$

第一次時，我們可以給服務器發送

$C*2^e=(2P)^e \bmod N$

服務器會計算得到

$2P \bmod N$

這裏

- 2P 是偶數，它的冪次也是偶數。
- N 是奇數，因爲它是由兩個大素數相乘得到。

那麼


- 服務器返回奇數，即 $2P \bmod N$ 爲奇數，則說明 2P 大於 N，且減去了奇數個 N，又因爲 $2P<2N$，因此減去了一個N， 即 $\frac{N}{2} \leq P < N$，我們還可以考慮向下取整。
- 服務器返回偶數，則說明 2P 小於 N。即 $0\leq P < \frac{N}{2}$，我們還可以向下取整。

這裏我們使用數學歸納法，即假設在第 i 次時，$\frac{xN}{2^{i}} \leq P < \frac{xN+N}{2^{i}}$


進一步，在第 i+1 次時，我們可以發送

$C*2^{(i+1)e}$

服務器會計算得到

$2^{i+1}P \bmod N=2^{i+1}P-kN$

$0 \leq 2^{i+1}P-kN<N$ 

$\frac{kN}{2^{i+1}} \leq P < \frac{kN+N}{2^{i+1}}$

根據第 i 次的結果

$\frac{2xN}{2^{i+1}} \leq P < \frac{2xN+2N}{2^{i+1}}$

那麼

- 服務器返回奇數，則 k 必然是一個奇數，k=2y+1， 那麼 $\frac{2yN+N}{2^{i+1}} \leq P < \frac{2yN+2N}{2^{i+1}}$。與此同時，由於 P 必然存在，所以第 i+1 得到的這個範圍和第 i 次得到的範圍必然存在交集。所以 y 必然與 x 相等。
- 服務器返回偶數，則 k 必然是一個偶數，k=2y，此時 y 必然也與 x 相等，那麼 $\frac{2xN}{2^{i+1}} \leq P < \frac{2xN+N}{2^{i+1}}$

進一步我們可以這麼歸納

```c
lb = 0
ub = N
if server returns 1
	lb = (lb+ub)/2
else:
	ub = (lb+ub)/2
```

這裏雖然是整除， 即下取整，但是無所謂我們在最初時已經分析了這個問題。

### 2018 Google CTF Perfect Secrecy

這裏以 2018 年 Google CTF 的題目爲例進行分析

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

- 我們可以給服務器兩個數，服務器會根據解密後的密文內容來決定使用哪一個。
- 服務器會使用 `random.randint(0, 2)` 來生成隨機數，並輸出相關的隨機 01 字節 c。

乍一看，似乎是完全隨機的，仔細查一下 `random.randint(0, 2)` 可以知道其生成隨機數是包括邊界的，因此其生成偶數的概率大於生成奇數的概率，那麼 c 與 p 同奇偶的概率爲 2/3。進而我們通過設置 m0 和 m1 就可以知道解密後的密文的最後一位是 0 還是 1 。這其實就是 RSA parity oracle。

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

結果如下

```shell
6533021797450432625003726192285181680054061843303961161444459679874621880787893445342698029728203298974356255732086344166897556918532195998159983477294838449903429031335408290610431938507208444225296242342845578895553611385588996615744823221415296689514934439749745119968629875229882861818946483594948270 6533021797450432625003726192285181680054061843303961161444459679874621880787893445342698029728203298974356255732086344166897556918532195998159983477294838449903429031335408290610431938507208444225296242342845578895553611385588996615744823221415296689514934439749745119968629875229882861818946483594948270
```

解碼後就可以得到 flag

```shell
CTF{h3ll0__17_5_m3_1_w45_w0nd3r1n6_1f_4f73r_4ll_7h353_y34r5_y0u_d_l1k3_70_m337}
```

### 題目

- 2016 Plaid CTF rabit
- 2016 sharif CTF lsb-oracle-150
- 2018 Backdoor CTF  BIT-LEAKER
- 2018 XMAN 選拔賽 baby RSA

## RSA Byte Oracle

假設目前存在一個 Oracle，它會對一個給定的密文進行解密，並且會給出明文的最後一個字節。那麼給定一個加密後的密文，我們只需要 $\log_{256}n$ 次就可以知道這個密文對應的明文消息。

### 原理

這個其實算作 RSA parity Oracle 的擴展，既然可以泄露出最後一個字節，那麼按道理我們獲取密文對應明文的次數應該可以減少。

假設

$C=P^e \bmod N$

第一次時，我們可以給服務器發送

$C*256^e=(256P)^e \bmod N$

服務器會計算得到

$256P \bmod N$

這裏

- 256P 是偶數。
- N 是奇數，因爲它是由兩個大素數相乘得到。

由於 P 一般是小於 N 的，那麼$256P \bmod N=256P-kn, k<256$。而且對於兩個不同的 $k_1,k_2$，我們有

$256P-k_1n \not\equiv 256P-k_2n \bmod 256$

我們可以利用反證法來證明上述不等式。同時 $256P-kn$ 的最後一個字節其實就是 $-kn$ 在模 256 的情況下獲取的。那麼，其實我們可以首先枚舉出 0~255 情況下的最後一個字節，構造一個 k 和最後一個字節的映射表 map

當服務器返回最後一個字節 b，那麼我們可以根據上述構造的映射表得知 k，即減去了 k 個N， 即 $kN \leq 256 P \leq (k+1)N$。

此後，我們使用數學歸納法來獲取 P 的範圍，即假設在第 i 次時，$\frac{xN}{256^{i}} \leq P < \frac{xN+N}{256^{i}}$

進一步，在第 i+1 次時，我們可以發送

$C*256^{(i+1)e}$

服務器會計算得到

$256^{i+1}P \bmod N=256^{i+1}P-kN$

$0 \leq 256^{i+1}P-kN<N$ 

$\frac{kN}{256^{i+1}} \leq P < \frac{kN+N}{256^{i+1}}$

根據第 i 次的結果

$\frac{256xN}{256^{i+1}} \leq P < \frac{256xN+256N}{256^{i+1}}$

我們這裏可以假設 $k=256y+t$， 而這裏的 t 就是我們可以通過映射表獲取的。

 $\frac{256yN+tN}{256^{i+1}} \leq P < \frac{256yN+(t+1)N}{256^{i+1}}$

與此同時，由於 P 必然存在，所以第 i+1 得到的這個範圍和第 i 次得到的範圍必然存在交集。

所以 y 必然與 x 相等。

進一步我們可以這麼歸納，初始情況下

```
lb = 0
ub = N
```

假設服務器返回了 b，那麼

```c
k = mab[b]
interval = (ub-lb)/256
lb = lb + interval * k
ub = lb + interval
```

### 2018 HITCON lost key

這是一個綜合題目，首先沒有給出 n，我們可以使用選擇明文攻擊的方式獲取 n，當然我們也可以進一步獲取 e，最後利用代碼如下

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

## RSA parity oracle variant
### 原理
如果oracle的參數會在一定時間、運行週期後改變，或者網絡不穩定導致會話斷開、重置，二分法就不再適用了，爲了減少錯誤，應當考慮逐位恢復。
要恢復明文的第2低位，考慮

$$\{(c(2^{-1*e_1}\mod N_1))^{d_1}\mod N_1\}\pmod2\equiv m*2^{-1}$$

$$
\begin{aligned}
&m*(2^{-1}\mod N_1)\mod2\\
&=(\displaystyle\sum_{i=0}^{logm-1}a_i*2^i)*2^{-1}\mod2\\
&=[2(\displaystyle\sum_{i=1}^{logm-1}a_i*2^{i-1})+a_0*2^0]*2^{-1}\mod 2\\
&=\displaystyle\sum_{i=1}^{logm-1}a_i*2^{i-1}+a_0*2^0*2^{-1}\mod2\\
&\equiv a_1+a_0*2^0*2^{-1}\equiv y\pmod2
\end{aligned}
$$

$$
y-(a_0*2^0)*2^{-1}=(m*2^{-1}\mod2)-(a_0*2^0)*2^{-1}\equiv a_1\pmod2
$$

類似的

$$\{(c(2^{-2*e_2}\mod N_2))^{d_2}\mod N_2\}\pmod2\equiv m*2^{-2}$$

$$
\begin{aligned}
&m*(2^{-2}\mod N_2)\mod2\\
&=(\displaystyle\sum_{i=0}^{logm-1}a_i*2^i)*2^{-2}\mod2\\
&=[2^2(\displaystyle\sum_{i=2}^{logm-1}a_i*2^{i-2})+a_1*2^1+a_0*2^0]*2^{-2}\mod 2\\
&=\displaystyle\sum_{i=2}^{logm-1}a_i*2^{i-1}+(a_1*2^1+a_0*2^0)*2^{-2}\mod2\\
&\equiv a_2+(a_1*2^1+a_0*2^0)*2^{-2}\equiv y\pmod2
\end{aligned}
$$

$$
\begin{aligned}
    &y-(a_1*2^1+a_0*2^0)*2^{-2}\\
    &=(m*2^{-2}\mod2)-(a_1*2^1+a_0*2^0)*2^{-2}\equiv a_2\pmod2
\end{aligned}
$$

我們就可以使用前i-1位與oracle的結果來得到第i位。注意這裏的$2^{-1}$是$2^1$模$N_1$的逆元。所以對剩下的位，有

$$
\begin{aligned}
    &\{(c(2^{-i*e_i}\mod N_i))^{d_i}\mod N_i\}\pmod2\equiv m*2^{-i}\\
    &a_i\equiv (m*2^{-i}\mod2) -\sum_{j=0}^{i-1}a_j*2^j\pmod2,i=1,2,...,logm-1
\end{aligned}
$$

其中$2^{-i}$是$2^i$模$N_i$的逆元。

就可以逐步恢復原文所有的位信息了。這樣的時間複雜度爲$O(logm)$。

exp:
```python
from Crypto.Util.number import *
mm = bytes_to_long(b'12345678')
l = len(bin(mm)) - 2

def genkey():
    while 1:
        p = getPrime(128)
        q = getPrime(128)
        e = getPrime(32)
        n = p * q
        phi = (p - 1) * (q - 1)
        if GCD(e, phi) > 1:
            continue
        d = inverse(e, phi)
        return e, d, n

e, d, n = genkey()
cc = pow(mm, e, n)
f = str(pow(cc, d, n) % 2)

for i in range(1, l):
    e, d, n = genkey()
    cc = pow(mm, e, n)
    ss = inverse(2**i, n)
    cs = (cc * pow(ss, e, n)) % n
    lb = pow(cs, d, n) % 2
    bb = (lb - (int(f, 2) * ss % n)) % 2
    f = str(bb) + f
    assert(((mm >> i) % 2) == bb)
print(long_to_bytes(int(f, 2)))
```

## 參考

- https://crypto.stackexchange.com/questions/11053/rsa-least-significant-bit-oracle-attack
- https://pastebin.com/KnEUSMxp
- https://github.com/ashutosh1206/Crypton
