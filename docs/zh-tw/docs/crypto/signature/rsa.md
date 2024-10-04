# RSA 數字簽名

## 原理

原理類似於 RSA 加密，只是這裏使用私鑰進行加密，將加密後的結果作爲簽名。

## 2018 Backdoor Awesome mix1

首先，可以簡單分析源碼，這裏程序使用 PKCS1_V1.5 進行了 RSA 簽名，這會對明文消息進行擴展，具體擴展規則請參考 https://www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf 。這裏給出對應擴展腳本，對應於題目中的 `from Util import PKCS1_pad as pad` 

```python
def PKCS1_pad(data):
    asn1 = "3021300906052b0e03021a05000414"
    ans = asn1 + data
    n = len(ans)
    return int(('00' + '01' + 'ff' * (1024 / 8 - n / 2 - 3) + '00' + ans), 16)
```

程序希望我們給出 `n,e` 使得程序滿足 

$h(m)^e mod \ n=pad(m)$

這裏我們已經知道 `h(m)，pad(m)`。顯然如果我們控制 `e=1`的話，那麼

$h(m)-pad(m)=kn$

那麼如果我們可以設置 k=1，既可以得到 n。

本地部署 `socat TCP4-LISTEN:12345,fork EXEC:./mix1.py`。

exp 如下

```python
from Crypto.Hash import SHA
from pwn import *

from Util import PKCS1_pad

#context.log_level = 'debug'


def main():
    port = 12345
    host = "127.0.0.1"
    p = remote(host, port)
    p.recvuntil('Message   -> ')
    message = p.recvuntil('\n\nSignature -> ', drop=True)
    log.info('message: ' + message)
    signature = p.recvuntil('\n', drop=True)
    log.info('signature: ' + signature)

    h = SHA.new(message)

    m = PKCS1_pad(h.hexdigest())

    e = 1
    n = int(signature, 16) - m

    p.sendlineafter('Enter n:', str(n))
    p.sendlineafter('Enter e:', str(e))

    p.interactive()


main()

```

效果如下

```shell
➜  2018-BackdoorCTF-Awesome-mix1 git:(master) python exp.py
[+] Opening connection to 127.0.0.1 on port 12345: Done
[*] message: super important information for admin only
[*] signature: 721af5bd401b5f2aff8e86bf811b827cdb5877ef12202f24fa914a26f235523f80c45fdbf0d3c9fa77278828ddd8ca0551a941bd57c97dd38654692568d1357a49e7a2a284d296508602ead24c91e5aa7f517b9e48422575f0dd373d00f267a206ba164ab104c488268b5f95daf490a048407773d4b1016de8ef508bf1aa678f
[*] Switching to interactive mode
CTF{cryp70_5ur3_15_w13rd}
[*] Got EOF while reading in interactive
```

## 2018 Backdoor Awesome mix2

本地部署 `socat TCP4-LISTEN:12345,fork EXEC:./service.py`。

題目類似於上面的題目，唯一的區別在於對於 e 有約束，必須大於 3，所以我們不能使用 1 了。

$h(m)^e mod \ n=pad(m)$

這裏我們已經知道 `h(m)，pad(m)`。我們只需要構造剩下的數即可，這裏我們構造 n 爲素數，使得 n-1是一個光滑數，這樣就可以使用 pohlig_hellman 算法了。

```python
from Crypto.Hash import SHA
from pwn import *
import gmpy2
from gmpy2 import is_prime
import random


def PKCS1_pad(data):
    asn1 = "3021300906052b0e03021a05000414"
    ans = asn1 + data
    n = len(ans)
    return int(('00' + '01' + 'ff' * (1024 / 8 - n / 2 - 3) + '00' + ans), 16)


#context.log_level = 'debug'
def gen_smooth_num(plist, minnum=pow(2, 1020)):
    lenp = len(plist)
    while True:
        n = 1
        factors = dict()
        while n + 1 < minnum:
            tmp = random.randint(0, lenp - 1)
            n *= plist[tmp]
            if plist[tmp] in factors:
                factors[plist[tmp]] += 1
            else:
                factors[plist[tmp]] = 1
        if n.bit_length() > 1024:
            continue
        if is_prime(n + 1):
            return n + 1, factors


# http://pythonexample.com/snippet/pohligpy_neuratron_python
# solve g^x=h mod m
def log_prime_power(g, h, pf, pe, M):

    powers = [pf**k for k in range(pe)]

    gamma = gmpy2.powmod(g, powers[-1], M)

    xk = gmpy2.mpz(0)
    for k in range(pe):
        if k == 0:
            hk = gmpy2.powmod(h, powers[pe - k - 1], M)
        else:
            gk = gmpy2.powmod(g, xk * (M - 2), M)
            hk = gmpy2.powmod(gk * h, powers[pe - k - 1], M)

        k_log_found = False
        for dk in range(pf):
            yk = gmpy2.powmod(gamma, dk, M)
            if yk == hk:
                k_log_found = True
                break

        if not k_log_found:
            raise Exception("can not solve")

        xk += gmpy2.mul(powers[k], dk)

    return xk


def pohlig_hellman(g, h, M, factors):
    M1 = M - 1
    xs = []
    for f in factors:
        pf = f
        pe = factors[f]

        subgroup_exponent = gmpy2.div(M1, gmpy2.powmod(pf, pe, M))
        gi = gmpy2.powmod(g, subgroup_exponent, M)
        hi = gmpy2.powmod(h, subgroup_exponent, M)

        xi = log_prime_power(gi, hi, pf, pe, M)
        xs.append(xi)
    crt_coeffs = []

    for f in factors:
        pf = f
        pe = factors[f]

        mi = pf**pe

        bi = gmpy2.div(M, mi)
        bi_inv = gmpy2.invert(bi, mi)
        crt_coeffs.append(gmpy2.mul(bi, bi_inv))
    x = 0
    for i in range(len(crt_coeffs)):
        x = gmpy2.t_mod(x + gmpy2.t_mod(xs[i] * crt_coeffs[i], M1), M1)
    return x


#context.log_level = 'debug'


def main():
    port = 12345
    host = "127.0.0.1"
    p = remote(host, port)
    p.recvuntil('Message   -> ')
    message = p.recvuntil('\n\nSignature -> ', drop=True)
    log.info('message: ' + message)
    signature = p.recvuntil('\n', drop=True)
    log.info('signature: ' + signature)
    signature = int(signature, 16)
    h = SHA.new(message)

    m = PKCS1_pad(h.hexdigest())
    print m, signature
    plist = []
    for i in range(2, 1000):
        if is_prime(i):
            plist.append(i)
    while True:
        try:
            n, factors = gen_smooth_num(plist, signature)
            e = pohlig_hellman(signature, m, n, factors)
        except Exception as e:
            continue
        else:
            break
    print n, e

    print m
    print gmpy2.powmod(signature, e, n)

    p.sendlineafter('Enter n:', str(n))
    p.sendlineafter('Enter e:', str(e))

    p.interactive()


main()
```

有兩點需要注意

1. 由於 $g^x=y$ 中的 g 和 y 都是給定的，我們新找到的 n，不一定 g 的冪次構成的羣會包含 y，所以可能求解失敗，所以需要多次求解。
2. 源代碼中雖然 `n.bit_length() <= 1025`，但是其實 n 在滿足不小於 signature 的條件時，必須滿足如下條件（pycrypto 源碼）

```python
        modBits = Crypto.Util.number.size(self._key.n)
        k = ceil_div(modBits,8) # Convert from bits to bytes
    
        # Step 1
        if len(S) != k:
            return 0
```

所以我們最好設置 n 爲1024 比特位。

