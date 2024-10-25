# 線性反饋移位寄存器 - LFSR

## 介紹

線性反饋移位寄存器的反饋函數一般如下

$a_{i+n}=\sum\limits_{j=1}^{n}c_ja_{i+n-j}$

其中，$c_j$ 均在某個有限域 $F_q$ 中。

既然線性空間是一個線性變換，我們可以得知這個線性變換爲

$$ \begin{align*}
&\left[
  a_{i+1},a_{i+2},a_{i+3}, ...,a_{i+n}
\right]\\\\=&\left[
  a_{i},a_{i+1},a_{i+2}, ...,a_{i+n-1}
\right]\left[ \begin{matrix} 0   & 0      & \cdots & 0 & c_n     \\ 1   & 0      & \cdots & 0 & c_{n-1}  \\ 0   & 1      & \cdots & 0 & c_{n-2}\\\vdots & \vdots & \ddots & \vdots \\ 0   & 0      & \cdots & 1 & c_1     \\ \end{matrix} \right]\\\\=&\left[
  a_{0},a_{1},a_{2}, ...,a_{n-1}
\right]\left[ \begin{matrix} 0   & 0      & \cdots & 0 & c_n     \\ 1   & 0      & \cdots & 0 & c_{n-1}  \\ 0   & 1      & \cdots & 0 & c_{n-2}\\\vdots & \vdots & \ddots & \vdots \\ 0   & 0      & \cdots & 1 & c_1     \\ \end{matrix} \right]^{i+1}
\end{align*} $$

進而，我們可以求得其特徵多項式爲

$f(x)=x^n-\sum\limits_{i=1}^{n}c_ix^{n-i}$

同時，我們定義其互反多項式爲

$\overline f(x)=x^nf(\frac{1}{x})=1-\sum\limits_{i=1}^{n}c_ix^{i}$

我們也稱互反多項式爲線性反饋移位寄存器的聯結多項式。

這裏有一些定理需要我們記一下，感興趣的可以自行推導。

## 特徵多項式與生成函數

已知某個 n 級線性反饋移位寄存器的特徵多項式，那麼該序列對應的生成函數爲

$A(x)=\frac{p(x)}{\overline f(x)}$

其中，$p(x)=\sum\limits_{i=1}^{n}(c_{n-i}x^{n-i}\sum\limits_{j=1}^{i}a_jx^{j-1})$。可以看出 p(x) 完全由初始狀態和反饋函數的係數決定。

## 序列週期與生成函數

序列的的週期爲其生成函數的既約真分式的分母的週期。

對於 n 級線性反饋移位寄存器，最長週期爲 $2^{n}-1$（排除全零）。達到最長週期的序列一般稱爲 m 序列。

## 特殊性質

- 將兩個序列累加得到新的序列的週期爲這兩個序列的週期的和。
- 序列是 n 級 m 序列，當且僅當序列的極小多項式是 n 次本原多項式。

## B-M 算法

一般來說，我們可以從兩種角度來考慮 LFSR

- 密鑰生成角度，一般我們希望使用級數儘可能低的 LFSR 來生成周期大，隨機性好的序列。
- 密碼分析角度，給定一個長度爲 n 的序列 a，如何構造一個級數儘可能小的 LFSR 來生成它。其實這就是 B-M 算法的來源。

一般來說，我們定義一個序列的線性複雜度如下

- 若 s 爲一個全零序列，則線性複雜度爲0。
- 若沒有 LFSR 能生成 s，則線性複雜度爲無窮。
- 否則，s 的線性複雜度爲生成 L(s) 的最小級的 LFSR。

BM 算法的要求我們需要知道長度爲 2n 的序列。其複雜度

- 時間複雜度：O(n^2) 次比特操作
- 空間複雜度：O(n) 比特。

關於 BM 算法的細節，後續添加，目前處於學習過程中。

但是其實如果我們知道了長度爲 2n 的序列，我們也可以一種比較笨的方法來獲取原先的序列。不妨假設已知的序列爲$a_1,...,a_{2n}$，我們可以令

$S_1=(a_1,...,a_n)$

$S_2=(a_2,...,a_{n+1})$

....

$S_{n+1}=(a_{n+1},...,a_{2n})$

那麼我們可以構造矩陣 $X=(S_1,...,S_n)$，那麼

$S_{n+1}=(c_n,...,c_1)X$

所以

$(c_n,...,c_1)=S_{n+1}X^{-1}$

進而我們也就知道了 LFSR 的反饋表達式，進而我們就可以推出初始化種子。

## 2018 強網杯 streamgame1

簡單看一下題目

```python
from flag import flag
assert flag.startswith("flag{")
assert flag.endswith("}")
assert len(flag)==25

def lfsr(R,mask):
    output = (R << 1) & 0xffffff
    i=(R&mask)&0xffffff
    lastbit=0
    while i!=0:
        lastbit^=(i&1)
        i=i>>1
    output^=lastbit
    return (output,lastbit)



R=int(flag[5:-1],2)
mask    =   0b1010011000100011100

f=open("key","ab")
for i in range(12):
    tmp=0
    for j in range(8):
        (R,out)=lfsr(R,mask)
        tmp=(tmp << 1)^out
    f.write(chr(tmp))
f.close()
```

可以發現，flag 的長度爲25-5-1=19，所以可以暴力枚舉。結果

```shell
➜  2018-強網杯-streamgame1 git:(master) ✗ python exp.py
12
0b1110101100001101011
```

因此 flag 爲 flag{1110101100001101011}。

## 2018 CISCN 初賽 oldstreamgame

簡單看一下題目

```shell
flag = "flag{xxxxxxxxxxxxxxxx}"
assert flag.startswith("flag{")
assert flag.endswith("}")
assert len(flag)==14

def lfsr(R,mask):
    output = (R << 1) & 0xffffffff
    i=(R&mask)&0xffffffff
    lastbit=0
    while i!=0:
        lastbit^=(i&1)
        i=i>>1
    output^=lastbit
    return (output,lastbit)

R=int(flag[5:-1],16)
mask = 0b10100100000010000000100010010100

f=open("key","w")
for i in range(100):
    tmp=0
    for j in range(8):
        (R,out)=lfsr(R,mask)
        tmp=(tmp << 1)^out
    f.write(chr(tmp))
f.close()
```

程序很簡單，仍然是一個 LFSR，但是初態是 32 比特位，當然，我們也可以選擇爆破，但是這裏不選擇爆破。

這裏給出兩種做法。

第一種做法，程序輸出的第 32 個比特是由程序輸出的前 31 個比特和初始種子的第 1 個比特來決定的，因此我們可以知道初始種子的第一個比特，進而可以知道初始種子的第 2 個比特，依次類推。代碼如下

```python
mask = 0b10100100000010000000100010010100
b = ''
N = 32
with open('key', 'rb') as f:
    b = f.read()
key = ''
for i in range(N / 8):
    t = ord(b[i])
    for j in xrange(7, -1, -1):
        key += str(t >> j & 1)
idx = 0
ans = ""
key = key[31] + key[:32]
while idx < 32:
    tmp = 0
    for i in range(32):
        if mask >> i & 1:
            tmp ^= int(key[31 - i])
    ans = str(tmp) + ans
    idx += 1
    key = key[31] + str(tmp) + key[1:31]
num = int(ans, 2)
print hex(num)
```

運行

```shell
➜  2018-CISCN-start-oldstreamgame git:(master) ✗ python exp1.py
0x926201d7
```

第二種做法，我們可以考慮一下矩陣轉換的過程，如果進行了 32 次線性變換，那麼就可以得到輸出流前 32 個比特。而其實，我們只需要前 32 個比特就可以恢復初始狀態了。


```python
mask = 0b10100100000010000000100010010100

N = 32
F = GF(2)

b = ''
with open('key', 'rb') as f:
    b = f.read()

R = [vector(F, N) for i in range(N)]
for i in range(N):
    R[i][N - 1] = mask >> (31 - i) & 1
for i in range(N - 1):
    R[i + 1][i] = 1
M = Matrix(F, R)
M = M ^ N

vec = vector(F, N)
row = 0
for i in range(N / 8):
    t = ord(b[i])
    for j in xrange(7, -1, -1):
        vec[row] = t >> j & 1
        row += 1
print rank(M)
num = int(''.join(map(str, list(M.solve_left(vec)))), 2)
print hex(num)
```


運行腳本

```shell
➜  2018-CISCN-start-oldstreamgame git:(master) ✗ sage exp.sage
32
0x926201d7
```

從而 flag 爲 flag{926201d7}。

還有一種做法是 TokyoWesterns 的，可以參考對應的文件夾的文件。

## 題目



## 參考文獻

- 密碼學講義，李超，屈龍江編著
