# 離散對數

## 基本定義

在瞭解離散對數時，我們先來瞭解幾個基本定義。

**定義1**

在羣 G 中，g 爲 G 的生成元，也就是說羣 G 中每一個元素都可以寫成 $y=g^k$，我們稱 k 爲 y 在羣 G 中的對數。

**定義2**

設 $m\geq 1$，$(a,m)=1$ ，使得 $a^d \equiv 1\pmod m$ 成立的最小正整數 d 稱爲 a 對模 m 的指數或者階，我們一般將其記爲 $\delta_m(a)$。

**定義3**

當 $\delta_m(a)=\varphi(m)$ 時，稱 a 是模 m 的原根，簡稱 m 的原根。

## 一些性質

**性質1**

使得 $a^d \equiv 1\pmod m$ 成立的最小正整數 $d$ ，必有$d\mid\varphi(m)$。

**性質2**

模 $m$ 剩餘系存在原根的充要條件是 $m=2,4,p^{\alpha},2p^{\alpha}$ ，其中 $p$ 爲奇素數， $\alpha$ 爲正整數。

## 離散對數問題

已知 $g,p,y$ ，對於方程 $y\equiv g^x \pmod p$ ，求解 $x$ 是一個難解問題。但是當 $p$ 具有一定的特性時就可能可以求解，比如，這個羣的階是一個光滑數。

正是上述這個問題構成了目前很大一部分現代密碼學，包括 Diffie–Hellman 密鑰交換， ElGamal 算法，ECC 等。

## 離散對數求解方式

### 暴力破解

給定 $y\equiv g^x \pmod p$，我們可以暴力枚舉 $x$ 從而得到真正的 $x$ 的值。

### Baby-step giant-step

這一方法通常被稱爲小步大步法，這一方法使用了中間相遇攻擊的思想。

我們可以令 $x=im+j$，其中 $m= \lceil \sqrt n\rceil$ ，那麼整數 i 和 j 都在 0 到 m 的範圍內。

因此

$$y=g^x=g^{im+j}$$

也就是

$$y(g^{-m})^i=g^j$$

那麼我們就可以枚舉所有的 j 並進行計算，並將其存儲到一個集合 S 中，然後我們再次枚舉 i，計算 $y(g^{-m})^i$，一旦我們發現計算的結果在集合 S 中，則說明我們得到了一個碰撞，進而得到了 i 和 j。

這顯然是一個時間與空間的折中的方式，我們將一個 $O(n)$ 的時間複雜度，$O(1)$ 空間複雜度的算法轉換爲了一個$O(\sqrt n)$的時間複雜度和$O(\sqrt n)$ 的空間複雜度的算法。

其中

- 每一次 j 的增加表示“baby-step”，一次乘上 $g$。
- 每一次 i 的增加表示“giant-step”，一次乘上 $g^{-m}$ 。

```python
def bsgs(g, y, p):
    m = int(ceil(sqrt(p - 1)))
    S = {pow(g, j, p): j for j in range(m)}
    gs = pow(g, p - 1 - m, p)
    for i in range(m):
        if y in S:
            return i * m + S[y]
        y = y * gs % p
    return None
```

### Pollard’s ρ algorithm

我們可以以$O(\sqrt n)$的時間複雜度和$O(1)$ 的空間複雜度來解決上述問題。具體原理請自行谷歌。

### Pollard’s kangaroo algorithm

如果我們知道 x 的範圍爲 $a \leq x \leq b$，那麼我們可以以$O(\sqrt{b-a})$ 的時間複雜度解決上述問題。具體原理請自行谷歌。

### Pohlig-Hellman algorithm

不妨假設上述所提到的羣關於元素 $g$ 的階爲 $n$， $n$ 爲一個光滑數： $n=\prod\limits_{i=1}^r p_i^{e_i}$。

1. 對於每個 $i \in \{1,\ldots,r\}$ ：
    1. 計算 $g_i \equiv g^{n/p_i^{e_i}} \pmod m$。根據拉格朗日定理， $g_i$ 在羣中的階爲 $p_i^{e_i}$ 。
    2. 計算 $y_i \equiv y^{n/p_i^{e_i}} \equiv g^{xn/p_i^{e_i}} \equiv g_i^{x} \equiv g_i^{x \bmod p_i^{e_i}} \equiv g_i^{x_i} \pmod m$，這裏我們知道 $y_i,m,g_i$，而$x_i$ 的範圍爲$[0,p_i^{e_i})$，由 $n$ 是一個光滑數，可知其範圍較小，因此我們可以使用 *Pollard’s kangaroo algorithm* 等方法快速求得$x_i$。
2. 根據上述的推導，我們可以得到對於 $i \in \{1,\ldots,r\}$ ，$x \equiv x_i \pmod{p_i^{e_i}}$ ，該式可用中國剩餘定理求解。


上述過程可用下圖簡單描述：

<center>
![Pohlig Hellman Algorithm](figure/Pohlig-Hellman-Diagram.png)
</center>

其複雜度爲$O\left(\sum\limits _i e_i\left(\log n+\sqrt{p_i}\right)\right)$，可以看出複雜度還是很低的。

但當 $n$ 爲素數，$m=2n+1$，那麼複雜度和 $O(\sqrt m)$ 是幾乎沒有差別的。

## 2018 國賽 crackme java

代碼如下

```java
import java.math.BigInteger;
import java.util.Random;

public class Test1 {
    static BigInteger two =new BigInteger("2");
    static BigInteger p = new BigInteger("11360738295177002998495384057893129964980131806509572927886675899422214174408333932150813939357279703161556767193621832795605708456628733877084015367497711");
    static BigInteger h= new BigInteger("7854998893567208831270627233155763658947405610938106998083991389307363085837028364154809577816577515021560985491707606165788274218742692875308216243966916");

    /*
     Alice write the below algorithm for encryption.
     The public key {p, h} is broadcasted to everyone.
    @param val: The plaintext to encrypt.
        We suppose val only contains lowercase letter {a-z} and numeric charactors, and is at most 256 charactors in length.
    */
    public static String pkEnc(String val){
        BigInteger[] ret = new BigInteger[2];
        BigInteger bVal=new BigInteger(val.toLowerCase(),36);
        BigInteger r =new BigInteger(new Random().nextInt()+"");
        ret[0]=two.modPow(r,p);
        ret[1]=h.modPow(r,p).multiply(bVal);
        return ret[0].toString(36)+"=="+ret[1].toString(36);
    }

    /* Alice write the below algorithm for decryption. x is her private key, which she will never let you know.
    public static String skDec(String val,BigInteger x){
        if(!val.contains("==")){
            return null;
        }
        else {
            BigInteger val0=new BigInteger(val.split("==")[0],36);
            BigInteger val1=new BigInteger(val.split("==")[1],36);
            BigInteger s=val0.modPow(x,p).modInverse(p);
            return val1.multiply(s).mod(p).toString(36);
        }
    }
   */

    public static void main(String[] args) throws Exception {
        System.out.println("You intercepted the following message, which is sent from Bob to Alice:");
        BigInteger bVal1=new BigInteger("a9hgrei38ez78hl2kkd6nvookaodyidgti7d9mbvctx3jjniezhlxs1b1xz9m0dzcexwiyhi4nhvazhhj8dwb91e7lbbxa4ieco",36);
	BigInteger bVal2=new BigInteger("2q17m8ajs7509yl9iy39g4znf08bw3b33vibipaa1xt5b8lcmgmk6i5w4830yd3fdqfbqaf82386z5odwssyo3t93y91xqd5jb0zbgvkb00fcmo53sa8eblgw6vahl80ykxeylpr4bpv32p7flvhdtwl4cxqzc",36);
	BigInteger r =new BigInteger(new Random().nextInt()+"");
	System.out.println(r);
        System.out.println(bVal1);
	System.out.println(bVal2);
	System.out.println("a9hgrei38ez78hl2kkd6nvookaodyidgti7d9mbvctx3jjniezhlxs1b1xz9m0dzcexwiyhi4nhvazhhj8dwb91e7lbbxa4ieco==2q17m8ajs7509yl9iy39g4znf08bw3b33vibipaa1xt5b8lcmgmk6i5w4830yd3fdqfbqaf82386z5odwssyo3t93y91xqd5jb0zbgvkb00fcmo53sa8eblgw6vahl80ykxeylpr4bpv32p7flvhdtwl4cxqzc");
        System.out.println("Please figure out the plaintext!");
    }
}
```

基本功能爲計算

$r_0=2^r \bmod p$

$r_1 =b*h^r \bmod p$

可以發現，r 的範圍爲 $[0,2^{32})$，所以我們可以使用 BSGS 算法，如下

```python
from sage.all import *

c1 = int(
    'a9hgrei38ez78hl2kkd6nvookaodyidgti7d9mbvctx3jjniezhlxs1b1xz9m0dzcexwiyhi4nhvazhhj8dwb91e7lbbxa4ieco',
    36
)
c2 = int(
    '2q17m8ajs7509yl9iy39g4znf08bw3b33vibipaa1xt5b8lcmgmk6i5w4830yd3fdqfbqaf82386z5odwssyo3t93y91xqd5jb0zbgvkb00fcmo53sa8eblgw6vahl80ykxeylpr4bpv32p7flvhdtwl4cxqzc',
    36
)
print c1, c2
p = 11360738295177002998495384057893129964980131806509572927886675899422214174408333932150813939357279703161556767193621832795605708456628733877084015367497711
h = 7854998893567208831270627233155763658947405610938106998083991389307363085837028364154809577816577515021560985491707606165788274218742692875308216243966916
# generate the group
const2 = 2
const2 = Mod(const2, p)
c1 = Mod(c1, p)
c2 = Mod(c2, p)
h = Mod(h, p)
print '2', bsgs(const2, c1, bounds=(1, 2 ^ 32))

r = 152351913

num = long(c2 / (h**r))
print num
```

## 參考

- 初等數論，潘承洞，潘承彪
- https://ee.stanford.edu/~hellman/publications/28.pdf
- https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm#cite_note-Menezes97p108-2
- https://fortenf.org/e/crypto/2017/12/03/survey-of-discrete-log-algos.html
