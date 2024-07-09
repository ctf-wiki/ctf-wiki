# Coppersmith 相關攻擊

## 基本原理

Coppersmith 相關攻擊與[Don Coppersmith](https://en.wikipedia.org/wiki/Don_Coppersmith) 緊密相關，他提出了一種針對於模多項式（單變量，二元變量，甚至多元變量）找所有小整數根的多項式時間的方法。

這裏我們以單變量爲主進行介紹，假設

- 模數爲 N ，N 具有一個因子 $b\geq N^{\beta},0< \beta \leq 1$
- 多項式 F 的次數爲 $\delta$

那麼該方法可以在$O(c\delta^5log^9(N))$ 的複雜度內找到該多項式所有的根$x_0$，這裏我們要求 $|x_0|<cN^{\frac{\beta^2}{\delta}}$ 。

在這個問題中，我們的目標是找到在模 N 意義下多項式所有的根，這一問題被認爲是複雜的。**Coppersmith method** 主要是通過 [Lenstra–Lenstra–Lovász lattice basis reduction algorithm](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm)（LLL）方法找到

- 與該多項式具有相同根 $x_0$
- 更小系數
- 定義域爲整數域

的多項式 g，由於在整數域上找多項式的根是簡單的（Berlekamp–Zassenhaus），從而我們就得到了原多項式在模意義下的整數根。

那麼問題的關鍵就是如何將 f 轉換到 g 呢？Howgrave-Graham 給出了一種思路

![image-20180717210921382](figure/coppersmith-howgrave-graham.png)

也就是說我們需要找到一個具有“更小系數”的多項式 g，也就是下面的轉換方式

![image-20180717211351350](figure/coppersmith-f2g.png)

在 LLL 算法中，有兩點是非常有用的

- 只對原來的基向量進行整數線性變換，這可以使得我們在得到 g 時，仍然以原來的 $x_0$ 爲根。
- 生成的新的基向量的模長是有界的，這可以使得我們利用 Howgrave-Graham 定理。

在這樣的基礎之上，我們再構造出多項式族 g 就可以了。

關於更加細節的內容，請自行搜索。同時這部分內容也會不斷更新。

需要注意的是，由於 Coppersmith 根的約束，在 RSA 中的應用時，往往只適用於 e 較小的情況。

## Basic Broadcast Attack

### 攻擊條件

如果一個用戶使用同一個加密指數 e 加密了同一個密文，併發送給了其他 e 個用戶。那麼就會產生廣播攻擊。這一攻擊由 Håstad 提出。

### 攻擊原理

這裏我們假設 e 爲 3，並且加密者使用了三個不同的模數 $n_1,n_2,n_3$ 給三個不同的用戶發送了加密後的消息 m，如下

$$
\begin{align*}
c_1&=m^3\bmod n_1 \\
c_2&=m^3\bmod n_2 \\
c_3&=m^3\bmod n_3
\end{align*}
$$

這裏我們假設 $n_1,n_2,n_3$ 互素，不然，我們就可以直接進行分解，然後得到 d，進而然後直接解密。

同時，我們假設 $m<n_i, 1\leq i \leq 3$。如果這個條件不滿足的話，就會使得情況變得比較複雜，這裏我們暫不討論。

既然他們互素，那麼我們可以根據中國剩餘定理，可得$m^3 \equiv C \bmod n_1n_2n_3$。

此外，既然 $m<n_i, 1\leq i \leq 3$，那麼我們知道 $m^3 < n_1n_2n_3$ 並且 $C<m^3 < n_1n_2n_3$，那麼 $m^3 = C$，我們對 C 開三次根即可得到 m 的值。

對於較大的 e 來說，我們只是需要更多的明密文對。

### SCTF RSA3 LEVEL4

參考 http://ohroot.com/2016/07/11/rsa-in-ctf。

這裏我們以 SCTF RSA3 中的 level4 爲例進行介紹，首先編寫代碼提取 cap 包中的數據，如下

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

其次，利用得到的數據直接使用中國剩餘定理求解。

```python
from functools import reduce
import gmpy
import json, binascii


def modinv(a, m):
    return int(gmpy.invert(gmpy.mpz(a), gmpy.mpz(m)))


def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a * b, n)
    # 並行運算
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

得到密文，然後再次解密即可得到 flag。

```shell
H1sTaDs_B40aDcadt_attaCk_e_are_same_and_smA9l
```

### 題目

- 2017 WHCTF OldDriver
- 2018 N1CTF easy_fs

## Broadcast Attack with Linear Padding

對於具有線性填充的情況下，仍然可以攻擊，這時候就會使用 **Coppersmith method** 的方法了，這裏暫不介紹。可以參考

- https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Generalizations

## Related Message Attack

### 攻擊條件

當 Alice 使用同一公鑰對兩個具有某種線性關係的消息 M1 與 M2 進行加密，並將加密後的消息 C1，C2 發送給了 Bob 時，我們就可能可以獲得對應的消息 M1 與 M2。這裏我們假設模數爲 N，兩者之間的線性關係如下

$$
M_1 \equiv f(M_2) \bmod N
$$

其中 f 爲一個線性函數，比如說 $f=ax+b$。

在具有較小錯誤概率下的情況下，其複雜度爲 $O(elog^2N)$。

這一攻擊由 Franklin，Reiter 提出。

### 攻擊原理

首先，我們知道 $C_1 \equiv M_1 ^e \bmod N$，並且 $M_1 \equiv f(M_2) \bmod N$，那麼我們可以知道 $M_2$ 是 $f(x)^e \equiv C_1 \bmod N$ 的一個解，即它是方程 $f(x)^e-C_1$ 在模 N 意義下的一個根。同樣的，$M_2$ 是 $x^e - C_2$ 在模 N 意義下的一個根。所以說 $x-M_2$ 同時整除以上兩個多項式。因此，我們可以求得兩個多項式的最大公因子，如果最大公因子恰好是線性的話，那麼我們就求得了 $M_2$。需要注意的是，在 $e=3$ 的情況下，最大公因子一定是線性的。

這裏我們關注一下 $e=3$，且 $f(x)=ax+b$ 的情況。首先我們有

$$
C_1 \equiv M_1 ^3 \bmod N,M_1 \equiv aM_2+b \bmod N
$$

那麼我們有

$$
C_1 \equiv (aM_2+b)^3 \bmod N,C_2 \equiv M_2^3 \bmod N
$$

我們需要明確一下我們想要得到的是消息 m，所以需要將其單獨構造出來。

首先，我們有式 1

$$
(aM_2+b)^3=a^3M_2^3+3a^2M^2b+3aM_2b^2+b^3
$$

再者我們構造如下式 2

$$
(aM_2)^3-b^3 \equiv (aM_2-b)(a^2M_2^2+aM_2b+b^2) \bmod N
$$

根據式 1 我們有

$$
a^3M_2^3-2b^3+3b(a^2M_2^2+aM_2b+b^2) \equiv C_1 \bmod N
$$

繼而我們有式 3

$$
3b(a^2M_2^2+aM_2b+b^2) \equiv C_1-a^3C_2+2b^3 \bmod N
$$

那麼我們根據式 2 與式 3 可得

$$
(a^3C_2-b^3)*3b \equiv (aM_2-b)( C_1-a^3C_2+2b^3 ) \bmod N
$$

進而我們有

$$
aM_2-b=\frac{3a^3bC_2-3b^4}{C_1-a^3C_2+2b^3}
$$

進而

$$
aM_2\equiv  \frac{2a^3bC_2-b^4+C_1b}{C_1-a^3C_2+2b^3}
$$

進而

$$
M_2 \equiv\frac{2a^3bC_2-b^4+C_1b}{aC_1-a^4C_2+2ab^3}=\frac{b}{a}\frac{C_1+2a^3C_2-b^3}{C_1-a^3C_2+2b^3}
$$

上面的式子中右邊所有的內容都是已知的內容，所以我們可以直接獲取對應的消息。

有興趣的可以進一步閱讀 [A New Related Message Attack on RSA](https://www.iacr.org/archive/pkc2005/33860001/33860001.pdf) 以及 [paper](https://www.cs.unc.edu/~reiter/papers/1996/Eurocrypt.pdf) 這裏暫不做過多的講解。

### SCTF RSA3

這裏我們以 SCTF RSA3 中的 level3 爲例進行介紹。首先，跟蹤 TCP 流可以知道，加密方式是將明文加上用戶的 user id 進行加密，而且還存在多組。這裏我們選擇第 0 組和第 9 組，他們的模數一樣，解密腳本如下

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

當然，我們也可以直接使用 sage 來做，會更加簡單一點。

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

結果如下

```shell
➜  sctf-rsa3-level3 git:(master) ✗ sage exp.sage
sys:1: RuntimeWarning: not adding directory '' to sys.path since everybody can write to it.
Untrusted users could put files in this directory which might then be imported by your Python code. As a general precaution from similar exploits, you should not execute Python code from this directory
F4An8LIn_rElT3r_rELa53d_Me33Age_aTtaCk_e_I2_s7aLL
```

### 題目

- hitcon 2014 rsaha
- N1CTF 2018 rsa_padding

## Coppersmith’s short-pad attack

### 攻擊條件

目前在大部分消息加密之前都會進行 padding，但是如果 padding 的長度過短，也有**可能**被很容易地攻擊。

這裏所謂 padding 過短，其實就是對應的多項式的根會過小。

### 攻擊原理

我們假設愛麗絲要給鮑勃發送消息，首先愛麗絲對要加密的消息 M 進行隨機 padding，然後加密得到密文 C1，發送給鮑勃。這時，中間人皮特截獲了密文。一段時間後，愛麗絲沒有收到鮑勃的回覆，再次對要加密的消息 M 進行隨機 padding，然後加密得到密文 C2，發送給 Bob。皮特再一次截獲。這時，皮特就**可能**可以利用如下原理解密。

這裏我們假設模數 N 的長度爲 k，並且 padding 的長度爲 $m=\lfloor \frac{k}{e^2} \rfloor$。此外，假設要加密的消息的長度最多爲 k-m 比特，padding 的方式如下

$$
M_1=2^mM+r_1, 0\leq r_1\leq 2^m
$$

消息 M2 的 padding 方式類似。

那麼我們可以利用如下的方式來解密。

首先定義

$$
g_1(x,y)=x^e-C_1
g_2(x,y)=(x+y)^e-C_2
$$

其中 $y=r_2-r_1$。顯然這兩個方程具有相同的根 M1。然後還有一系列的推導。

## Known High Bits Message Attack

### 攻擊條件

這裏我們假設我們首先加密了消息 m，如下

$$
C\equiv m^d \bmod N
$$

並且我們假設我們知道消息 m 的很大的一部分 $m_0$，即 $m=m_0+x$，但是我們不知道 $x$。那麼我們就有可能通過該方法進行恢復消息。這裏我們不知道的 x 其實就是多項式的根，需要滿足 Coppersmith 的約束。

可以參考 https://github.com/mimoo/RSA-and-LLL-attacks。

## Factoring with High Bits Known

### 攻擊條件

當我們知道一個公鑰中模數 N 的一個因子的較高位時，我們就有一定幾率來分解 N。

### 攻擊工具

請參考 https://github.com/mimoo/RSA-and-LLL-attacks。上面有使用教程。關注下面的代碼

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

- 必須滿足 $q\geq N^{beta}$，所以這裏給出了$beta=0.5$，顯然兩個因數中必然有一個是大於的。
- XX 是 $f(x)=q'+x$ 在模 q 意義下的根的上界，自然我們可以選擇調整它，這裏其實也表明了我們已知的 $q'$ 與因數 q 之間可能的差距。

### 2016 HCTF RSA2

這裏我們以 2016 年 HCTF 中的 RSA2 爲例進行介紹。

首先程序的開頭是一個繞過驗證的，繞過即可，代碼如下

```python
from pwn import *
from hashlib import sha512
sh = remote('127.0.0.1', 9999)
context.log_level = 'debug'
def sha512_proof(prefix, verify):
    i = 0
    pading = ""
    while True:
        try:
            i = randint(0, 1000)
            pading += str(i)
            if len(pading) > 200:
                pading = pading[200:]
            #print pading
        except StopIteration:
            break
        r = sha512(prefix + pading).hexdigest()
        if verify in r:
            return pading


def verify():
    sh.recvuntil("Prefix: ")
    prefix = sh.recvline()
    print len(prefix)
    prefix = prefix[:-1]
    prefix = prefix.decode('base64')
    proof = sha512_proof(prefix, "fffffff")
    sh.send(proof.encode('base64'))
if __name__ == '__main__':
    verify()
    print 'verify success'
    sh.recvuntil("token: ")
    token = "5c9597f3c8245907ea71a89d9d39d08e"
    sh.sendline(token)

    sh.recvuntil("n: ")
    n = sh.readline().strip()
    n = int(n[2:], 16)

    sh.recvuntil("e: ")
    e = sh.readline().strip()
    e = int(e[2:], 16)

    sh.recvuntil("e2: ")
    e2 = sh.readline().strip()
    e2 = int(e2[2:], 16)

    sh.recvuntil("is: ")
    enc_flag = sh.readline().strip()
    enc_flag = int(enc_flag[2:-1], 16)
    print "n: ", hex(n)
    print "e: ", hex(e)
    print "e2: ", hex(e2)
    print "flag: ", hex(enc_flag)
```

這裏我們也已經得到 n，e，e2，加密後的 flag 了，如下

```python
n:  0x724d41149e1bd9d2aa9b333d467f2dfa399049a5d0b4ee770c9d4883123be11a52ff1bd382ad37d0ff8d58c8224529ca21c86e8a97799a31ddebd246aeeaf0788099b9c9c718713561329a8e529dfeae993036921f036caa4bdba94843e0a2e1254c626abe54dc3129e2f6e6e73bbbd05e7c6c6e9f44fcd0a496f38218ab9d52bf1f266004180b6f5b9bee7988c4fe5ab85b664280c3cfe6b80ae67ed8ba37825758b24feb689ff247ee699ebcc4232b4495782596cd3f29a8ca9e0c2d86ea69372944d027a0f485cea42b74dfd74ec06f93b997a111c7e18017523baf0f57ae28126c8824bd962052623eb565cee0ceee97a35fd8815d2c5c97ab9653c4553f
e:  0x10001
e2:  0xf93b
flag:  0xf11e932fa420790ca3976468dc4df1e6b20519ebfdc427c09e06940e1ef0ca566d41714dc1545ddbdcae626eb51c7fa52608384a36a2a021960d71023b5d0f63e6b38b46ac945ddafea42f01d24cc33ce16825df7aa61395d13617ae619dca2df15b5963c77d6ededf2fe06fd36ae8c5ce0e3c21d72f2d7f20cd9a8696fbb628df29299a6b836c418cbfe91e2b5be74bdfdb4efdd1b33f57ebb72c5246d5dce635529f1f69634d565a631e950d4a34a02281cbed177b5a624932c2bc02f0c8fd9afd332ccf93af5048f02b8bd72213d6a52930b0faa0926973883136d8530b8acf732aede8bb71cb187691ebd93a0ea8aeec7f82d0b8b74bcf010c8a38a1fa8
```

接下來我們來分析主程序。可以看出

```python
	p, q, e = gen_key()
	n = p * q
	phi_n = (p-1)*(q-1)
	d = invmod(e, phi_n)
	while True:
		e2 = random.randint(0x1000, 0x10000)
		if gcd(e2, phi_n) == 1:
			break
```

我們得到的 $n=p \times q$。而 p，q 以及我們已知的 e 都在 `gen_key` 函數中生成。看一看 `gen_key` 函數

```python
def gen_key():
	while True:
		p = getPrime(k/2)
		if gcd(e, p-1) == 1:
			break
	q_t = getPrime(k/2)
	n_t = p * q_t
	t = get_bit(n_t, k/16, 1)
	y = get_bit(n_t, 5*k/8, 0)
	p4 = get_bit(p, 5*k/16, 1)
	u = pi_b(p4, 1)
	n = bytes_to_long(long_to_bytes(t) + long_to_bytes(u) + long_to_bytes(y))
	q = n / p
	if q % 2 == 0:
		q += 1
	while True:
		if isPrime(q) and gcd(e, q-1) == 1:
			break
		m = getPrime(k/16) + 1
		q ^= m
	return (p, q, e)
```

其中我們已知如下參數

$$
k=2048
e=0x10001
$$

首先，程序先得到了 1024 比特位的素數 p，並且 `gcd(2,p-1)=1`。

然後，程序又得到了一個 1024 比特位的素數 $q_t$，並且計算 $n_t=p \times q_t$。

下面多次調用了 `get_bit` 函數，我們來簡單分析一下

```python
def get_bit(number, n_bit, dire):
	'''
	dire:
		1: left
		0: right
	'''

	if dire:
		sn = size(number)
		if sn % 8 != 0:
			sn += (8 - sn % 8)
		return number >> (sn-n_bit)
	else:
		return number & (pow(2, n_bit) - 1)
```

可以看出根據 `dire(ction)` 的不同，會得到不同的數

- `dire=1` 時，程序首先計算 `number` 的二進制位數 `sn`，如果不是 8 的整數倍的話，就將 `sn` 增大爲 8 的整數倍，然後返回 `number` 右移 `sn-n_bit` 的數字。其實 就是最多保留 `number` 的 `n_bit` 位。
- `dire=0` 時，程序直接獲取 `number` 的低 `n_bit` 位。

然後我們再來看程序

```python
	t = get_bit(n_t, k/16, 1)
	y = get_bit(n_t, 5*k/8, 0)
	p4 = get_bit(p, 5*k/16, 1)
```

這三個操作分別做了如下的事情

- `t` 爲 `n_t` 的最多高 k/16 位，即 128 位，位數不固定。
- `y` 爲 `n_t` 的低 5*k/8 位，即 1280 位，位數固定。
- `p4` 爲 p 的最多高 5*k/16 位，即 640 位，位數不固定。

此後，程序有如下操作

```python
	u = pi_b(p4, 1)
```

利用 `pi_b` 對 `p4` 進行了加密

```python
def pi_b(x, m):
	'''
	m:
		1: encrypt
		0: decrypt
	'''
	enc = DES.new(key)
	if m:
		method = enc.encrypt
	else:
		method = enc.decrypt
	s = long_to_bytes(x)
	sp = [s[a:a+8] for a in xrange(0, len(s), 8)]
	r = ""
	for a in sp:
		r += method(a)
	return bytes_to_long(r)
```

其中，我們已知了密鑰 key，所以只要我們有密文就可以解密。此外，可以看到的是程序是對傳入的消息進行 8 字節分組，採用密碼本方式加密，所以密文之間互不影響。

下面

```python
	n = bytes_to_long(long_to_bytes(t) + long_to_bytes(u) + long_to_bytes(y))
	q = n / p
	if q % 2 == 0:
		q += 1
	while True:
		if isPrime(q) and gcd(e, q-1) == 1:
			break
		m = getPrime(k/16) + 1
		q ^= m
	return (p, q, e)
```

程序將 t，u，y 拼接在一起得到 n，進而，程序得到了 q，並對 q 的低 k/16 位做了抑或，然後返回 `q'`。

在主程序裏，再一次得到了 `n'=p*q'`。這裏我們仔細分析一下

```
n'=p * ( q + random(2^{k/16}))
```

而 p 是 k/2 位的，所以說，random 的部分最多可以影響原來的 n 的最低的 $k/2+k/16=9k/16$ 比特位。

而，我們還知道 n 的最低的 5k/8=10k/16 比特爲其實就是 y，所以其並沒有影響到 u，即使影響到也就最多影響到一位。

所以我們首先可以利用我們得到的 n 來獲取 u，如下

```
u=hex(n)[2:-1][-480:-320]
```

雖然，這樣可能會獲得較多位數的 u，但是這樣並不影響，我們對 u 解密的時候每一分組都互不影響，所以我們只可能影響最高位數的 p4。而 p4 的的高 8 位也有可能是填充的。但這也並不影響，我們已經得到了因子 p 的的很多部分了，我們可以去嘗試着解密了。如下

```python
if __name__=="__main__":
	n = 0x724d41149e1bd9d2aa9b333d467f2dfa399049a5d0b4ee770c9d4883123be11a52ff1bd382ad37d0ff8d58c8224529ca21c86e8a97799a31ddebd246aeeaf0788099b9c9c718713561329a8e529dfeae993036921f036caa4bdba94843e0a2e1254c626abe54dc3129e2f6e6e73bbbd05e7c6c6e9f44fcd0a496f38218ab9d52bf1f266004180b6f5b9bee7988c4fe5ab85b664280c3cfe6b80ae67ed8ba37825758b24feb689ff247ee699ebcc4232b4495782596cd3f29a8ca9e0c2d86ea69372944d027a0f485cea42b74dfd74ec06f93b997a111c7e18017523baf0f57ae28126c8824bd962052623eb565cee0ceee97a35fd8815d2c5c97ab9653c4553f
	u = hex(n)[2:-1][-480:-320]
	u = int(u,16)
	p4 = pi_b(u,0)
	print hex(p4)
```

解密結果如下

```python
➜  2016-HCTF-RSA2 git:(master) ✗ python exp_p4.py
0xa37302107c17fb4ef5c3443f4ef9e220ac659670077b9aa9ff7381d11073affe9183e88acae0ab61fb75a3c7815ffcb1b756b27c4d90b2e0ada753fa17cc108c1d0de82c747db81b9e6f49bde1362693L
```

下面，我們直接使用 sage 來解密，這裏 sage 裏面已經實現了這個攻擊，我們直接拿來用就好

```python
from sage.all import *
import binascii
n = 0x724d41149e1bd9d2aa9b333d467f2dfa399049a5d0b4ee770c9d4883123be11a52ff1bd382ad37d0ff8d58c8224529ca21c86e8a97799a31ddebd246aeeaf0788099b9c9c718713561329a8e529dfeae993036921f036caa4bdba94843e0a2e1254c626abe54dc3129e2f6e6e73bbbd05e7c6c6e9f44fcd0a496f38218ab9d52bf1f266004180b6f5b9bee7988c4fe5ab85b664280c3cfe6b80ae67ed8ba37825758b24feb689ff247ee699ebcc4232b4495782596cd3f29a8ca9e0c2d86ea69372944d027a0f485cea42b74dfd74ec06f93b997a111c7e18017523baf0f57ae28126c8824bd962052623eb565cee0ceee97a35fd8815d2c5c97ab9653c4553f
p4 =0xa37302107c17fb4ef5c3443f4ef9e220ac659670077b9aa9ff7381d11073affe9183e88acae0ab61fb75a3c7815ffcb1b756b27c4d90b2e0ada753fa17cc108c1d0de82c747db81b9e6f49bde1362693
cipher = 0xf11e932fa420790ca3976468dc4df1e6b20519ebfdc427c09e06940e1ef0ca566d41714dc1545ddbdcae626eb51c7fa52608384a36a2a021960d71023b5d0f63e6b38b46ac945ddafea42f01d24cc33ce16825df7aa61395d13617ae619dca2df15b5963c77d6ededf2fe06fd36ae8c5ce0e3c21d72f2d7f20cd9a8696fbb628df29299a6b836c418cbfe91e2b5be74bdfdb4efdd1b33f57ebb72c5246d5dce635529f1f69634d565a631e950d4a34a02281cbed177b5a624932c2bc02f0c8fd9afd332ccf93af5048f02b8bd72213d6a52930b0faa0926973883136d8530b8acf732aede8bb71cb187691ebd93a0ea8aeec7f82d0b8b74bcf010c8a38a1fa8
e2 = 0xf93b
pbits = 1024
kbits = pbits - p4.nbits()
print p4.nbits()
p4 = p4 << kbits
PR.<x> = PolynomialRing(Zmod(n))
f = x + p4
roots = f.small_roots(X=2^kbits, beta=0.4)
if roots:
    p = p4+int(roots[0])
    print "p: ", hex(int(p))
    assert n % p == 0
    q = n/int(p)
    print "q: ", hex(int(q))
    print gcd(p,q)
    phin = (p-1)*(q-1)
    print gcd(e2,phin)
    d = inverse_mod(e2,phin)
    flag = pow(cipher,d,n)
    flag = hex(int(flag))[2:-1]
    print binascii.unhexlify(flag)
```

關於 `small_roots` 的使用，可以參考 [SAGE 說明](http://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/polynomial_modn_dense_ntl.html#sage.rings.polynomial.polynomial_modn_dense_ntl.small_roots)。

結果如下

```shell
➜  2016-HCTF-RSA2 git:(master) ✗ sage payload.sage
sys:1: RuntimeWarning: not adding directory '' to sys.path since everybody can write to it.
Untrusted users could put files in this directory which might then be imported by your Python code. As a general precaution from similar exploits, you should not execute Python code from this directory
640
p:  0xa37302107c17fb4ef5c3443f4ef9e220ac659670077b9aa9ff7381d11073affe9183e88acae0ab61fb75a3c7815ffcb1b756b27c4d90b2e0ada753fa17cc108c1d0de82c747db81b9e6f49bde13626933aa6762057e1df53d27356ee6a09b17ef4f4986d862e3bb24f99446a0ab2385228295f4b776c1f391ab2a0d8c0dec1e5L
q:  0xb306030a7c6ace771db8adb45fae597f3c1be739d79fd39dfa6fd7f8c177e99eb29f0462c3f023e0530b545df6e656dadb984953c265b26f860b68aa6d304fa403b0b0e37183008592ec2a333c431e2906c9859d7cbc4386ef4c4407ead946d855ecd6a8b2067ad8a99b21111b26905fcf0d53a1b893547b46c3142b06061853L
1
1
hctf{d8e8fca2dc0f896fd7cb4cb0031ba249}
```

### 題目

- 2016 湖湘杯 簡單的 RSA
- 2017 WHCTF Untitled

## Boneh and Durfee attack

### 攻擊條件

當 d 較小時，滿足 $d < N^{0.292}$ 時，我們可以利用該攻擊，比 Wiener's Attack 要強一些。

### 攻擊原理

這裏簡單說一下原理。

首先

$$
ed \equiv 1 \bmod  \varphi(N)/2
$$

進而有

$$
ed +k\varphi(N)/2=1
$$

即

$$
k \varphi(N)/2 \equiv 1 \bmod e
$$


又

$$
\varphi(N)=(p-1)(q-1)=qp-p-q+1=N-p-q+1
$$

所以

$$
k(N-p-q+1)/2 \equiv 1 \bmod e
$$

假設 $A=\frac{N+1}{2}$，$y=\frac{-p-q}{2}$ ，原式可化爲

$$
f(k,y)=k(A+y) \equiv 1 \bmod e
$$

其中

$|k|<\frac{2ed}{\varphi(N)}<\frac{3ed}{N}=3*\frac{e}{N}*d<3*\frac{e}{N}*N^{delta}$

$|y|<2*N^{0.5}$

y 的估計用到了 p、q 比較均勻的假設。這裏 delta 爲預估的小於 0.292 的值。

如果我們求得了該二元方程的根，那麼我們自然也就可以解一元二次方程 $N=pq,p+q=-2y$ 來得到 p 與 q。

更加具體的推導，參考 New Results on the Cryptanalysis of Low Exponent RSA.

### 攻擊工具

請參考 https://github.com/mimoo/RSA-and-LLL-attacks 。上面有使用教程。

### 2015 PlaidCTF Curious

這裏我們以 2015 年 PlaidCTF Curious 爲例進行介紹。

首先題目給了一堆 N，e，c。簡單看一下可以發現該 e 比較大。這時候我們可以考慮使用 Wiener's Attack，這裏我們使用更強的目前介紹的攻擊。

核心代碼如下

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

結果如下

```shell
=== solution found ===
private key found: 23974584842546960047080386914966001070087596246662608796022581200084145416583
the plaintext: flag_S0Y0UKN0WW13N3R$4TT4CK!
```

### 2019 Defcon Quals ASRybaB

題目大概意思是，我們接收三對 RSA ，然後需要求出 d，然後對給定的數字 v[i] 加密，發送給服務器，只要時間在一定範圍內，940s，即可。那難點自然在 create_key 函數了。

```python
def send_challenges():

    code = marshal.loads("63000000000d000000070000004300000073df010000740000721d0064010064020015000000000100640200157d00006e00007401007d01007c0100640300157d02006402007d0300786f007c03006a02008300007c01006b030072a400784c007403007296007404006a05007c02008301007d04007404006a05007c02008301007d05007406007c04007c0500188301006a02008300007c0100640400146b0400724b0050714b00714b00577c04007c0500147d0300713600577c0400640500187c050064050018147d06006406007d07006407007d080078090174030072ce017404006a07007408006403007409007c01007c0700148301008302007408006403007409007c01007c070014830100640500178302008302007d09007871007c09006a02008300007c01007c0800146b0000727b016402007d0a007844007404006a0a007c0a00830100736d017404006a0700740800640300640800830200740800640300640800830200740800640300640900830200178302007d0a00712a01577c09007c0a00397d0900710b01577404006a0b007c09007c06008302006405006b0300729a0171c6006e00007404006a0c007c09007c06008302007d0b007404006a0b007c0b007c06008302006405006b030072ca0171c6006e00005071c60057640a007d0c007c03007c0b0066020053280b0000004e690700000069000000006902000000675839b4c876bedf3f6901000000674e62105839b4d03f678d976e1283c0d23f692d000000690c0000006903000000280d000000740500000046616c736574050000004e53495a45740a0000006269745f6c656e67746874040000005472756574060000006e756d626572740e0000006765745374726f6e675072696d657403000000616273740e00000067657452616e646f6d52616e67657403000000706f777403000000696e74740700000069735072696d6574030000004743447407000000696e7665727365280d00000074010000007874050000004e73697a657406000000707173697a6574010000004e740100000070740100000071740300000070686974060000006c696d69743174060000006c696d697432740100000064740300000070707074010000006574030000007a7a7a2800000000280000000073150000002f6f726967696e616c6368616c6c656e67652e7079740a0000006372656174655f6b657917000000733e000000000106010a010d0206010a010601150109010f010f04200108010e0112020601060109013c0119010601120135020e011801060112011801060105020604".decode("hex"))
    create_key = types.FunctionType(code, globals(), "create_key")
    
    ck = create_key
```

我們可以簡單看看這個到底是在幹啥

```python
>>> import marshal
>>> data="63000000000d000000070000004300000073df010000740000721d0064010064020015000000000100640200157d00006e00007401007d01007c0100640300157d02006402007d0300786f007c03006a02008300007c01006b030072a400784c007403007296007404006a05007c02008301007d04007404006a05007c02008301007d05007406007c04007c0500188301006a02008300007c0100640400146b0400724b0050714b00714b00577c04007c0500147d0300713600577c0400640500187c050064050018147d06006406007d07006407007d080078090174030072ce017404006a07007408006403007409007c01007c0700148301008302007408006403007409007c01007c070014830100640500178302008302007d09007871007c09006a02008300007c01007c0800146b0000727b016402007d0a007844007404006a0a007c0a00830100736d017404006a0700740800640300640800830200740800640300640800830200740800640300640900830200178302007d0a00712a01577c09007c0a00397d0900710b01577404006a0b007c09007c06008302006405006b0300729a0171c6006e00007404006a0c007c09007c06008302007d0b007404006a0b007c0b007c06008302006405006b030072ca0171c6006e00005071c60057640a007d0c007c03007c0b0066020053280b0000004e690700000069000000006902000000675839b4c876bedf3f6901000000674e62105839b4d03f678d976e1283c0d23f692d000000690c0000006903000000280d000000740500000046616c736574050000004e53495a45740a0000006269745f6c656e67746874040000005472756574060000006e756d626572740e0000006765745374726f6e675072696d657403000000616273740e00000067657452616e646f6d52616e67657403000000706f777403000000696e74740700000069735072696d6574030000004743447407000000696e7665727365280d00000074010000007874050000004e73697a657406000000707173697a6574010000004e740100000070740100000071740300000070686974060000006c696d69743174060000006c696d697432740100000064740300000070707074010000006574030000007a7a7a2800000000280000000073150000002f6f726967696e616c6368616c6c656e67652e7079740a0000006372656174655f6b657917000000733e000000000106010a010d0206010a010601150109010f010f04200108010e0112020601060109013c0119010601120135020e011801060112011801060105020604"
>>> code=marshal.loads(data)
>>> code=marshal.loads(data.decode('hex'))
>>> import dis
>>> dis.dis(code)
 24           0 LOAD_GLOBAL              0 (False)
              3 POP_JUMP_IF_FALSE       29

 25           6 LOAD_CONST               1 (7)
              9 LOAD_CONST               2 (0)
             12 BINARY_DIVIDE
             13 STOP_CODE
             14 STOP_CODE
             15 STOP_CODE
...
 56         428 LOAD_GLOBAL              4 (number)
            431 LOAD_ATTR               11 (GCD)
            434 LOAD_FAST               11 (e)
            437 LOAD_FAST                6 (phi)
            440 CALL_FUNCTION            2
            443 LOAD_CONST               5 (1)
            446 COMPARE_OP               3 (!=)
            449 POP_JUMP_IF_FALSE      458
...
```

基本可以猜出來這是在生成 n，e，d，其實和我們最初的預期也差不多。我們來直接反編譯一下

```python
>>> from uncompyle6 import code_deparse
>>> code_deparse(code)
Instruction context:

  25       6  LOAD_CONST            1  7
              9  LOAD_CONST            2  0
             12  BINARY_DIVIDE
->           13  STOP_CODE
             14  STOP_CODE
             15  STOP_CODE
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/local/lib/python2.7/site-packages/uncompyle6/semantics/pysource.py", line 2310, in code_deparse
    deparsed.ast = deparsed.build_ast(tokens, customize, isTopLevel=isTopLevel)
  File "/usr/local/lib/python2.7/site-packages/uncompyle6/semantics/pysource.py", line 2244, in build_ast
    raise ParserError(e, tokens)
uncompyle6.semantics.parser_error.ParserError: --- This code section failed: ---
...
 64     469  LOAD_FAST             3  'N'
         472  LOAD_FAST            11  'e'
         475  BUILD_TUPLE_2         2  None
         478  RETURN_VALUE
          -1  RETURN_LAST

Parse error at or near `STOP_CODE' instruction at offset 13
```

可以發現 STOP_CODE，有點貓膩，如果仔細看最初的反彙編的話，我們可以發現最前面的那部分代碼是在混淆

```python
>>> dis.dis(code)
 24           0 LOAD_GLOBAL              0 (False)
              3 POP_JUMP_IF_FALSE       29

 25           6 LOAD_CONST               1 (7)
              9 LOAD_CONST               2 (0)
             12 BINARY_DIVIDE
             13 STOP_CODE
             14 STOP_CODE
             15 STOP_CODE

 26          16 STOP_CODE
             17 POP_TOP
             18 STOP_CODE
             19 LOAD_CONST               2 (0)
             22 BINARY_DIVIDE
             23 STORE_FAST               0 (x)
             26 JUMP_FORWARD             0 (to 29)

 28     >>   29 LOAD_GLOBAL              1 (NSIZE)
             32 STORE_FAST               1 (Nsize)

 29          35 LOAD_FAST                1 (Nsize)
             38 LOAD_CONST               3 (2)
             41 BINARY_DIVIDE
             42 STORE_FAST               2 (pqsize)
```

一直到

```python
 29          35 LOAD_FAST                1 (Nsize)
```

前面的都沒有什麼作用，感覺是出題者故意修改了代碼。仔細分析一下這部分代碼，感覺像是兩部分

```python
# part 1
 25           6 LOAD_CONST               1 (7)
              9 LOAD_CONST               2 (0)
             12 BINARY_DIVIDE
             13 STOP_CODE
             14 STOP_CODE
             15 STOP_CODE
# part 2
 26          16 STOP_CODE
             17 POP_TOP
             18 STOP_CODE
             19 LOAD_CONST               2 (0)
             22 BINARY_DIVIDE
             23 STORE_FAST               0 (x)
             26 JUMP_FORWARD             0 (to 29)
```

正好是第 25 行和第 26 行，大概猜一猜，感覺兩個都是 x=7/0，所以就想辦法把這部分的代碼修復一下，接下來就是定位這部分代碼了。根據手冊可以知道 STOP_CODE 是 0，從而我們可以定位第 25 行語句到 26 行語句爲 t[6:26]，他們分別都是 10 字節(6-15,16-25)。

```python
>>> t=code.co_code
>>> t
't\x00\x00r\x1d\x00d\x01\x00d\x02\x00\x15\x00\x00\x00\x00\x01\x00d\x02\x00\x15}\x00\x00n\x00\x00t\x01\x00}\x01\x00|\x01\x00d\x03\x00\x15}\x02\x00d\x02\x00}\x03\x00xo\x00|\x03\x00j\x02\x00\x83\x00\x00|\x01\x00k\x03\x00r\xa4\x00xL\x00t\x03\x00r\x96\x00t\x04\x00j\x05\x00|\x02\x00\x83\x01\x00}\x04\x00t\x04\x00j\x05\x00|\x02\x00\x83\x01\x00}\x05\x00t\x06\x00|\x04\x00|\x05\x00\x18\x83\x01\x00j\x02\x00\x83\x00\x00|\x01\x00d\x04\x00\x14k\x04\x00rK\x00PqK\x00qK\x00W|\x04\x00|\x05\x00\x14}\x03\x00q6\x00W|\x04\x00d\x05\x00\x18|\x05\x00d\x05\x00\x18\x14}\x06\x00d\x06\x00}\x07\x00d\x07\x00}\x08\x00x\t\x01t\x03\x00r\xce\x01t\x04\x00j\x07\x00t\x08\x00d\x03\x00t\t\x00|\x01\x00|\x07\x00\x14\x83\x01\x00\x83\x02\x00t\x08\x00d\x03\x00t\t\x00|\x01\x00|\x07\x00\x14\x83\x01\x00d\x05\x00\x17\x83\x02\x00\x83\x02\x00}\t\x00xq\x00|\t\x00j\x02\x00\x83\x00\x00|\x01\x00|\x08\x00\x14k\x00\x00r{\x01d\x02\x00}\n\x00xD\x00t\x04\x00j\n\x00|\n\x00\x83\x01\x00sm\x01t\x04\x00j\x07\x00t\x08\x00d\x03\x00d\x08\x00\x83\x02\x00t\x08\x00d\x03\x00d\x08\x00\x83\x02\x00t\x08\x00d\x03\x00d\t\x00\x83\x02\x00\x17\x83\x02\x00}\n\x00q*\x01W|\t\x00|\n\x009}\t\x00q\x0b\x01Wt\x04\x00j\x0b\x00|\t\x00|\x06\x00\x83\x02\x00d\x05\x00k\x03\x00r\x9a\x01q\xc6\x00n\x00\x00t\x04\x00j\x0c\x00|\t\x00|\x06\x00\x83\x02\x00}\x0b\x00t\x04\x00j\x0b\x00|\x0b\x00|\x06\x00\x83\x02\x00d\x05\x00k\x03\x00r\xca\x01q\xc6\x00n\x00\x00Pq\xc6\x00Wd\n\x00}\x0c\x00|\x03\x00|\x0b\x00f\x02\x00S'
>>> t[6:26]
'd\x01\x00d\x02\x00\x15\x00\x00\x00\x00\x01\x00d\x02\x00\x15}\x00\x00'
>>> t[-3:]
'\x02\x00S'
>>> t='d\x01\x00d\x02\x00\x15\x00\x00\x00\x00\x01\x00d\x02\x00\x15}\x00\x00'
>>> t[-3:]
'}\x00\x00'
>>> t[:7]+t[-3:]
'd\x01\x00d\x02\x00\x15}\x00\x00'
>>> _.encode('hex')
'640100640200157d0000'
```

從而我們可以修復原 code

```python
>>> data.find('640100')
56
>>> data1=data[:56]+'640100640200157d0000640100640200157d0000'+data[56+40:]
>>> code1=marshal.loads(data1.decode('hex'))
>>> code_deparse(code1)
if False:
    x = 7 / 0
    x = 7 / 0
Nsize = NSIZE
pqsize = Nsize / 2
N = 0
while N.bit_length() != Nsize:
    while True:
        p = number.getStrongPrime(pqsize)
        q = number.getStrongPrime(pqsize)
        if abs(p - q).bit_length() > Nsize * 0.496:
            break

    N = p * q

phi = (p - 1) * (q - 1)
limit1 = 0.261
limit2 = 0.293
while True:
    d = number.getRandomRange(pow(2, int(Nsize * limit1)), pow(2, int(Nsize * limit1) + 1))
    while d.bit_length() < Nsize * limit2:
        ppp = 0
        while not number.isPrime(ppp):
            ppp = number.getRandomRange(pow(2, 45), pow(2, 45) + pow(2, 12))

        d *= ppp

    if number.GCD(d, phi) != 1:
        continue
    e = number.inverse(d, phi)
    if number.GCD(e, phi) != 1:
        continue
    break

zzz = 3
return (
 N, e)<uncompyle6.semantics.pysource.SourceWalker object at 0x10a0ea110>
```

可以看到生成的 d 是故意超了 0.292 的，不過我們可以發現 ppp 範圍很小，實際上我們可以測試得到這個範圍的素數爲 125 個。並且

```python
1280*0.261+45=379.08000000000004>375.03999999999996=1280*0.293
```

所以其實這裏就乘了一個數，那麼我們其實就可以枚舉一下乘了什麼，並修改 e1=e*ppp，其實就回歸到標準的 Boneh and Durfee attack。

但是，如果我們直接使用 https://github.com/mimoo/RSA-and-LLL-attacks 的腳本也不行，必須得提高 m，基本得提到 8，這樣仍然不是很穩定。

如果仔細嘗試嘗試的話，就會發現 e1>N，這看起來問題不大，但是原腳本里假設的數值是 e<N 的，所以我們需要進行適當的修改預估的上下界

```python
    X = 2*floor(N^delta)  # this _might_ be too much
    Y = floor(N^(1/2))    # correct if p, q are ~ same size
```

根據上述推導，上下界應該爲

$|k|<\frac{2ed}{\varphi(N)}<\frac{3ed}{N}=3*\frac{e}{N}*d<3*\frac{e}{N}*N^{delta}$

$|y|<2*N^{0.5}$

最後主要修改了 m 和 X 的上界

```python
    delta = .262 # this means that d < N^delta

    #
    # Lattice (tweak those values)
    #

    # you should tweak this (after a first run), (e.g. increment it until a solution is found)
    m = 8 # size of the lattice (bigger the better/slower)

    # you need to be a lattice master to tweak these
    t = int((1-2*delta) * m)  # optimization from Herrmann and May
    X = floor(3*e/N*N^delta) #4*floor(N^delta)  # this _might_ be too much
    Y = floor(2*N^(1/2))    # correct if p, q are ~ same size
```

最後可以得到結果

```shell
[DEBUG] Received 0x1f bytes:
    'Succcess!\n'
    'OOO{Br3akingL!mits?}\n'
OOO{Br3akingL!mits?}
```

不得不說這個題目，真的是需要**多**核服務器。。


## 參考資料

- Survey: Lattice Reduction Attacks on RSA
- An Introduction to Coppersmith’s method and Applications in Cryptology
