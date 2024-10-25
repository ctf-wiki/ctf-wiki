# ElGamal

RSA的數字簽名方案几乎與其加密方案完全一致，只是利用私鑰進行了簽名。但是，對於ElGamal來說，其簽名方案與相應的加密方案具有很大區別。

## 基本原理

### 密鑰生成

基本步驟如下

1. 選取一個足夠大的素數p（十進制位數不低於160），以便於在$Z_p$ 上求解離散對數問題是困難的。
2. 選取$Z_p^*$ 的生成元g。
3. 隨機選取整數d,$0\leq d \leq p-2$ ，並計算$g^d \equiv y \bmod p$ 。

其中私鑰爲{d}，公鑰爲{p,g,y} 。

### 簽名

A選取隨機數$k \in Z_{p-1}$ ，並且$gcd(k,p-1)=1$，對消息進行簽名


$$
sig_d(m,k)=(r,s)
$$


其中$r \equiv g^k \bmod p$ ，$s \equiv (m-dr)k^{-1} \bmod p-1$ 。

### 驗證

如果 $g^m \equiv y^rr^s \bmod p$ ，那麼驗證成功，否則驗證失敗。這裏驗證成功的原理如下，首先我們有

$$
y^rr^s \equiv g^{dr}g^{ks} \equiv g^{dr+ks}
$$

又因爲

$$
s \equiv (m-dr)k^{-1} \bmod p-1
$$

所以

$$
ks \equiv m-dr \bmod p-1
$$

進而

$$
ks+dr=a*(p-1)+m
$$

所以

$$
g^{ks+dr}=g^{a*(p-1)+m}=(g^{p-1})^a*g^m
$$

所以根據費馬定理，可得

$$
g^{ks+dr} \equiv g^m \bmod p
$$

## 常見攻擊

### 完全破譯攻擊

#### 攻擊條件

- p太小或無大素因子

如果$p$太小我們可以直接用大部小步算法分解, 或者如果其無大的素因子, 我們可以採用$Pohling\: Hellman$算法計算離散對數即可進而求出私鑰。

- 隨機數k複用

如果簽名者複用了隨機數k，那麼攻擊者就可以輕而易舉地計算出私鑰。具體的原理如下：

假設目前有兩個簽名都是使用同一個隨機數進行簽名的。那麼我們有

$$
r \equiv g^k \bmod p \\\\ s _1\equiv (m_1-dr)k^{-1} \bmod p-1\\\\ r \equiv g^k \bmod p \\\\ s_2 \equiv (m_2-dr)k^{-1} \bmod p-1
$$

進而有

$$
s_1k \equiv m_1-dr \bmod p-1 \\\\ s_2k \equiv m_2-dr \bmod p-1
$$

兩式相減

$$
k(s_1-s_2) \equiv m_1-m_2 \bmod p-1
$$

這裏，$s_1,s_2,m_1,m_2,p-1$ 均已知，所以我們可以很容易算出k。當然，如果$gcd(s_1-s_2,p-1)!=1$ 的話，可能會存在多個解，這時我們只需要多試一試。進而，我們可以根據s的計算方法得到私鑰d，如下

$$
d \equiv \frac{m-ks}{r}
$$

#### 題目

2016 LCTF Crypto 450

### 通用僞造簽名

#### 攻擊條件

如果消息$m$沒有取哈希，或者消息$m$沒有指定消息格式的情況下攻擊成立。

#### 原理

在攻擊者知道了某個人Alice的公鑰之後，他可以僞造Alice的簽名信息。具體原理如下:

這裏我們假設，Alice的公鑰爲{p,g,y}。攻擊者可以按照如下方式僞造

1. 選擇整數 $i$，$j$，其中$gcd(j,p-1)=1$

2. 計算簽名，$r \equiv g^iy^j \bmod p$ ，$s\equiv -rj^{-1} \bmod p-1$

3. 計算消息，$m\equiv si \bmod p-1$

那麼此時生成的簽名與消息就是可以被正常通過驗證，具體推導如下:

$y^rr^s \equiv g^{dr}g^{is}y^{js} \equiv g^{dr}g^{djs}g^{is} \equiv g^{dr+s(i+dj)} \equiv g^{dr} g^{-rj^{-1}(i+dj)} \equiv g^{dr-dr-rij^{-1}} \equiv g^{si} \bmod p$

又由於消息m的構造方式，所以

$$
g^{si} \equiv g^m \bmod p-1
$$

需要注意的是，攻擊者可以僞造通過簽名驗證的消息，但是他卻無法僞造指定格式的消息。而且，一旦消息進行了哈希操作，這一攻擊就不再可行。

### 已知簽名僞造

#### 攻擊條件

假設攻擊者知道$(r, s)$是消息$M$的簽名，則攻擊者可利用它來僞造其它消息的簽名。

#### 原理

1. 選擇整數$h, i, j \in[0, p-2]$且滿足$\operatorname{gcd}(h r-j s, \varphi(p))=1$
2. 計算下式
   $\begin{array}{l}
   r^{\prime}=r^{h} \alpha^{i} y_{A}^{j} \bmod p \\
   s^{\prime}=\operatorname{sr}(h r-j s)^{-1} \bmod \varphi(p) \\
   m^{\prime}=r^{\prime}(h m+i s)(h r-j s)^{-1} \bmod \varphi(p)
   \end{array}$

可得到$(r',s')$是$m'$的有效簽名

證明如下:

已知Alice對消息$x$的簽名$(\gamma,\delta)$滿足$\beta^{\gamma} \gamma^{\delta} \equiv \alpha^{x}(\bmod p)$，所以我們目的爲構造出$\left(x^{\prime}, \lambda, \mu\right)$滿足


$$
\beta^{\lambda} \lambda^{\mu} \equiv \alpha^{x'}(\bmod p)
$$




那麼，首先我們把$\lambda$表示爲三個已知底$\alpha, \beta, \gamma$的形式: $\lambda=\alpha^{i} \beta^{j} \gamma^{h} \bmod p$,由條件可得


$$
\beta^{\gamma} \gamma^{\delta} \equiv \alpha^{x}(\bmod p) \Leftrightarrow \gamma=\left(\beta^{-\gamma} \alpha^{x}\right)^{\delta-1} \bmod p
$$

那麼我們可以得到


$$
\lambda=\alpha^{i+x \delta^{-1} h} \beta^{j-\gamma \delta^{-1} h} \bmod p
$$


我們把$\lambda$的表達式代入一式中


$$
\begin{aligned}& \beta^{\lambda}\left(\alpha^{i+x \delta^{-1} h} \beta^{j-\gamma \delta^{-1} h}\right)^{\mu} \equiv \alpha^{x^{\prime}}(\bmod p) \\\Leftrightarrow & \beta^{\lambda+\left(j-\gamma \delta^{-1} h\right) \mu} \equiv \alpha^{x^{\prime}-\left(i+x \delta^{-1} h\right) \mu}(\bmod p)\end{aligned}
$$


我們令兩邊指數爲$0$, 即


$$
\left\{\begin{matrix}\lambda+\left(j-\gamma \delta^{-1} h\right) \mu \equiv 0 \bmod p-1 \\ x^{\prime}-\left(i+x \delta^{-1} h\right) \mu \equiv 0 \bmod p-1 \end{matrix}\right.
$$


可以得到


$$
\mu=\delta \lambda(h \gamma-j \delta)^{-1} \quad(\bmod p-1)  \\
x^{\prime}=\lambda(h x+i \delta)(h \gamma-j \delta)^{-1}(\bmod p-1)
$$


其中


$$
\lambda=\alpha^{i} \beta^{j} \gamma^{h} \bmod p
$$


所以我們得到$(\lambda, \mu)$是 $x'$ 的有效簽名。

此外,我們還可以藉助CRT構造$m'$, 原理如下:

1. $u=m^{\prime} m^{-1} \bmod \varphi(p), \quad s^{\prime}=s u \bmod \varphi(p)$
2. 再計算$r^{\prime}, \quad r^{\prime} \equiv r u \bmod \varphi(p), r^{\prime} \equiv r \bmod p$

顯然可以使用CRT求解$r'$, 注意到 $y_{A}^{r'} r'^{s^{\prime}}=y_{A}^{ru} r^{s u}=\left(y_{A}^{r} r^{s}\right)^{u}=\alpha^{m u} \equiv \alpha^{m} \bmod p$ 

所以$(r',s')$是消息$m'$的有效簽名。

抵抗措施:在驗證簽名時, 檢查$r < p$。

### 選擇簽名僞造

#### 攻擊條件

如果我們可以選擇我們消息進行簽名，並且可以得到簽名，那麼我們可以對一個新的但是我們不能夠選擇簽名的消息僞造簽名。

#### 原理

我們知道，最後驗證的過程如下

 $g^m \equiv y^rr^s \bmod p$ 

那麼只要我們選擇一個消息m使其和我們所要僞造的消息$m'$模p-1同餘，然後同時使用消息m的簽名即可繞過。

#### 題目

這裏以2017年國賽mailbox爲例，**i春秋有復現**。

首先，我們來分析一下程序，我們首先需要進行proof of work


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
我們需要生成一個以proof開頭的長度爲proof長度加5的字符串，並且其sha1的值以16比特的0結束。

這裏我們直接使用如下的方式來繞過。

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

這裏使用了pwntools中的util.iters.mbruteforce，這是一個利用給定字符集合以及指定長度進行多線程爆破的函數。其中，第一個參數爲爆破函數，這裏是sha1，第二個參數是字符集，第三個參數是字節數，第四個參數指的是我們只嘗試字節數爲第三個參數指定字節數的排列，即長度是固定的。更加具體的信息請參考pwntools。

繞過之後，我們繼續分析程序，簡單看下generate_keys函數，可以知道該函數是ElGamal生成公鑰的過程，然後看了看verify函數，就是驗證簽名的過程。

繼續分析

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

根據這三個if條件可以知道

- 我們的消息長度不能超過MSGLENGTH，40000。
- 我們可以對消息開頭爲test的消息進行簽名。
- 我們需要使得以Th3_bery_un1que1i_ChArmIng_G3nji開頭，以我們繞過proof的test爲結尾的消息通過簽名驗證，其中，我們可以自己提供簽名的值。

分析到這裏，其實就知道了，我們就是在選擇指定簽名進行僞造，這裏我們自然要充分利用第二個if條件，只要我們確保我們輸入的消息的開頭爲‘test’，並且該消息與以Th3_bery_un1que1i_ChArmIng_G3nji開頭的固定消息模p-1同餘，我們即可以通過驗證。

那我們如何構造呢？既然消息的長度可以足夠長，那麼我們可以將'test'對應的16進制先左移得到比p-1大的數字a，然後用a對p-1取模，用a再減去餘數，此時a模p-1餘0了。這時再加上以Th3_bery_un1que1i_ChArmIng_G3nji開頭的固定消息的值，即實現了模p-1同餘。

具體如下

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

最後的腳本如下

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

這裏還要說幾個有意思的點就是

- int(x,0)只的是將x按照其字面對應的進制轉換爲對應的數字，比如說int('0x12',0)=18，這裏相應的字面必須有對應標誌開頭，比如說十六進制是0x,8進制是0，二進制是0b。因爲如果沒有的話，就不知道該如何識別了。
- python(python2) 裏面到底多大的數，計算出來最後纔會帶有L呢？正常情況下，大於int都會有L。但是這個裏面的victim確實是沒有的，， **一個問題，待解決。。**
