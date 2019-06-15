[EN](./fnv.md) | [ZH](./fnv-zh.md)
# Fowler–Noll–Vo hash function

具体请参见 https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function。

## 2018 网鼎杯 hashcoll

其实这道题是从 NSU Crypto 抄过来的，https://nsucrypto.nsu.ru/archive/2017/problems_solution，具体的 wp 之前 hellman 也写了，https://gist.github.com/hellman/9bf8376cd04e7a8dd2ec7be1947261e9。

简单看一下题目

```python
h0 = 45740974929179720441799381904411404011270459520712533273451053262137196814399

# 2**168 + 355
g = 374144419156711147060143317175368453031918731002211L


def shitty_hash(msg):
    h = h0
    msg = map(ord, msg)
    for i in msg:
        h = (h + i) * g
        # This line is just to screw you up :))
        h = h & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

    return h - 0xe6168647f636
```

题目希望我们给出两个消息，其哈希值相同。如果我们将该函数展开的话，那么

$hash(m)=h_0g^n+x_1g^n+x_2g_{n-1}+...+x_ng \bmod 2^{256}$

假设两个消息的 hash 值相同那么

$h_0g^n+x_1g^n+x_2g_{n-1}+...+x_ng  \equiv h_0g^n+y_1g^n+y_2g_{n-1}+...+y_ng\bmod 2^{256}$

进而

$(x_1-y_1)g^{n-1}+(x_2-y_2)g^{n-2}+...+(x_n-y_n)g^0 \equiv 0 \bmod 2^{256}$

即我们只需要找到一个 n 维向量 $z_i=x_i-y_i$，满足上述等式即可，我们可以进一步将其化为

$z_1g^{n-1}+z_2g^{n-2}+...+z_ng^0-k*2^{256}=0$

即找到一组向量满足上述这个式子。这可以认为是 LLL Paper 中第二个例子的简单情况（参见格问题部分）。

那么我们可以快速构造矩阵，如下

$$ A = \left[ \begin{matrix} 1   & 0 & 0     & \cdots & 0 & Kg^{n-1}     \\ 0   & 1  & 0    & \cdots & 0 & Kg^{n-2}  \\ 0   & 0   & 1   & \cdots & 0 & Kg^{n-3} \\\vdots & \vdots & \vdots & \ddots & \vdots \\ 0   & 0   &0   & \cdots & 1 & K*mod     \\ \end{matrix} \right]$$

之后我们使用LLL 算法即可获得两个一样的哈希值

```python
from sage.all import *

mod = 2**256
h0 = 45740974929179720441799381904411404011270459520712533273451053262137196814399

g = 2**168 + 355


def shitty_hash(msg):
    h = h0
    msg = map(ord, msg)
    for i in msg:
        h = (h + i) * g
        # This line is just to screw you up :))
        h = h & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

    return h - 0xe6168647f636


K = 2**200
N = 50
base_str = 'a' * N
base = map(ord, base_str)
m = Matrix(ZZ, N + 1, N + 2)
for i in xrange(N + 1):
    ge = ZZ(pow(g, N - i, mod))
    m[i, i] = 1
    m[i, N + 1] = ZZ(ge * K)
m[i, N + 1] = ZZ(K * mod)

ml = m.LLL()
ttt = ml.rows()[0]
print "result:", ttt
if ttt[-1] != 0:
    print "Zero not reached, increase K"
    exit()
else:
    msg = []
    for i in xrange(N):
        msg.append(base[i] + ttt[i])
        if not (0 <= msg[i] <= 255):
            print "Need more bytes!"
            quit()
    print msg
    other = ''.join(map(chr, msg))

    print shitty_hash(base_str)
    print shitty_hash(other)
```

注意不能直接仅仅使用 pow(g, N - i, mod)，不然生成的数会在 mod 对应的域中，这真是个大坑。

如下

```shell
➜  hashcoll sage exp.sage
result: (15, -14, 17, 14, 6, 0, 12, 21, 8, 29, 6, -4, -9, 10, -2, -12, -6, 0, -12, 13, -28, -28, -24, -3, 6, -5, -16, 15, 17, -14, 3, -2, -16, -25, 3, -21, -27, -9, 16, 5, -1, 0, -3, -4, -4, -19, 6, 8, 0, 0, 0, 0)
[112, 83, 114, 111, 103, 97, 109, 118, 105, 126, 103, 93, 88, 107, 95, 85, 91, 97, 85, 110, 69, 69, 73, 94, 103, 92, 81, 112, 114, 83, 100, 95, 81, 72, 100, 76, 70, 88, 113, 102, 96, 97, 94, 93, 93, 78, 103, 105, 97, 97]
106025341237231370726407656306665079105509255639964756437758376184556498283725
106025341237231370726407656306665079105509255639964756437758376184556498283725
```

即成功。