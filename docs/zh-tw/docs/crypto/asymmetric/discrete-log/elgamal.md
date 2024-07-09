# ElGamal

## 概述

ElGamal算法的安全性是基於求解離散對數問題的困難性，於1984年提出，也是一種雙鑰密碼體制，既可以用於加密又可用於數字簽名。

如果我們假設p是至少是160位的十進制素數，**並且p-1有大素因子**，此外g是 $Z_p^*$  的生成元，並且 $y \in Z_p^*$  。那麼如何找到一個唯一的整數x($0\leq x \leq p-2$) ，滿足$g^x \equiv y \bmod p$ 在算法上是困難的，這裏將x記爲$x=log_gy$ 。

## 基本原理

這裏我們假設A要給B發送消息m。

### 密鑰生成

基本步驟如下

1. 選取一個足夠大的素數p，以便於在$Z_p$ 上求解離散對數問題是困難的。
2. 選取$Z_p^*$ 的生成元g。
3. 隨機選取整數k,$0\leq k \leq p-2$ ，並計算$g^k \equiv y \bmod p$ 。

其中私鑰爲{k}，公鑰爲{p,g,y} 。

### 加密

A選取隨機數$r \in Z_{p-1}$ ，對明文加密$E_k(m,r)=(y_1,y_2)$ 。其中$y_1 \equiv g^r \bmod p$ ，$y_2 \equiv my^r \bmod p$ 。

### 解密

$D_k(y_1,y_2)=y_2(y_1^k)^{-1} \bmod p \equiv m(g^k)^r(g^{rk})^{-1} \equiv m \bmod p$ 。

### 難點

雖然我們知道了y1,但是我們卻沒有辦法知道其對應的r。

## 2015 MMA CTF Alicegame

這裏我們以2015年 MMA-CTF-2015 中的 Alicegame 爲例進行介紹。這題最初在沒有給出源碼的時候卻是比較難做，因爲這個給一個 m，給一個 r 就得到加密結果，，這太難想。

我們來簡單分析一下源碼，首先程序最初生成了 pk 與 sk

```python
    (pk, sk) = genkey(PBITS)
```

其中genkey函數如下

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

p爲k位的素數，g爲(2,p)範圍內的書，x在(1,p-1)範圍內。並且計算了$h \equiv g^x \bmod p$ 。看到這裏，差不多就知道，這應該是一個數域上的ElGamal加密了。其中pk爲公鑰，sk爲私鑰。

接下來 程序輸出了10次m和r。並且，利用如下函數加密

```python
def encrypt(pk, m, r = None):
    (p, g, h) = pk
    if r is None:
        r = random.randrange(1, p-1)
    c1 = pow(g, r, p)
    c2 = (m * pow(h, r, p)) % p
    return (c1, c2)
```

其加密方法確實是ElGamal方式的加密。

最後程序對flag進行了加密。此時的r是由程序自己random的。

分析一下，這裏我們在十輪循環中可以控制m和r，並且

$c_1 \equiv g^r \bmod p$

$c_2 \equiv m * h^{r} \bmod p$

如果我們設置

1. r=1，m=1，那麼我們就可以獲得$c_1=g,c_2=h$ 。
2. r=1，m=-1，那麼我們就可以獲得$c_1=g, c_2 = p-h$ 。進而我們就可以得到素數p。

我們得到素數p有什麼用呢?p的位數在201位左右，很大啊。

但是啊，它生成素數p之後，沒有進行檢查啊。我們在之前說過p-1必須有大素因子，如果有小的素因子的話，那我們就可以攻擊了。其攻擊主要是使用到了baby step-giant step 與 Pohlig-Hellman algorithm 算法，有興趣的可以看看，這裏sage本身自帶的計算離散對數的函數已經可以處理這樣的情況了，參見[discrete_log](http://doc.sagemath.org/html/en/reference/groups/sage/groups/generic.html) 。

具體代碼如下，需要注意的是，，這個消耗內存比較大，，不要隨便拿虛擬機跑。。。還有就是這尼瑪交互讓我頭疼啊，，，

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

最後迫於計算機內存不夠，，沒計算出來，，，有時候會崩，多運行幾次。。

## 2018 Code Blue lagalem

題目描述如下

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

可以看出，該算法就是一個 ElGamal 加密，給了同一個明文兩組加密後的結果，其特點在於使用的隨機數 r 是通過線性同餘生成器生成的，則我們知道

$c2 \equiv m * h^{r} \bmod p$

$c2\_ \equiv m*h^{(Ar+B) \bmod q} \equiv m*h^{Ar+B}\bmod p$

則

$c2^A*h^B/c2\_ \equiv m^{A-1}\bmod p$

其中，c2，c2_，A，B，h 均知道。則我們知道

$m^{A-1} \equiv t \bmod p$

我們假設已知 p 的一個原根 g，則我們可以假設

$g^x \equiv t$

$g^y \equiv m$

則

$g^{y(A-1)}\equiv g^x \bmod p$

則

$y(A-1) \equiv x \bmod p-1$

進而我們知道

$y(A-1)-k(p-1)=x$

這裏我們知道 A，p，x，則我們可以利用擴展歐幾裏得定理求得

$s(A-1)+w(p-1)=gcd(A-1,p-1)$

如果gcd(A-1,p-1)=d，則我們直接計算

$t^s \equiv m^{s(A-1)} \equiv m^d \bmod p$

如果 d=1，則直接知道 m。

如果 d 不爲1，則就有點麻煩了。。

這裏這道題目中恰好 d=1，因此可以很容易進行求解。

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

## 參考

- https://www.math.auckland.ac.nz/~sgal018/crypto-book/solns.pdf，20.4.1
