# CVP

CVP是Lattice-based cryptography中尤爲重要的一個問題。

問題的基本定義如下：給定格$L$的一組基與向量$\mathbf{v}$，找到在$L$上離$\mathbf{v}$最近的一個向量。

<!--
TODO: Add more Lattice-based cryptography (CVP specifically) application intro here.
TODO: Make intro more descriptive and rigorous.
-->

## Algorithms

### Babai's nearest plane algorithm

<!--
TODO: Add intro
-->

該算法輸入一組格$L$(秩爲$n$)的基$B$和一個目標向量$\mathbf{t}$，輸出CVP問題的近似解。

* 近似因子爲$\gamma = 2^{\frac{n}{2}}$

具體算法：

![](figure/babai_1.png)

* 其中$c_j$爲Gram-schmidt正交化中的係數取整，也即$proj_{b_{j}}(b)$的取整。

對於該算法第二步的個人理解：在格基規約和正交化過後的基$B$中找到一個最靠近$\mathbf{t}$的線性組合。

### Babai’s Rounding Technique

該算法是`Babai's nearest plane algorithm`的一個變種。

步驟可以表示爲：

```
N = rank(B), w = target
- B' = LLL(B)
- Find a linear combination [l_0, ... l_N] such that w = sum(l_i * b'_i).
* (b'_i is the i-th vector in the LLL-reduced basis B')
- Round each l_i to it's closest integer l'_i.
- Result v = sum(l'_i * b'_i)
```

## 相關內容

### Hidden number problem

HNP的定義如下：

給定質數$p$、許多$t \in \mathbb{F}_p$以及每一個對應的$MSB_{l,p}(\alpha t)$，找出對應的$\alpha$。

* $MSB_{l,p}(x)$表示任一滿足 $\lvert (x \mod p) - u \rvert \le \frac{p}{2^{l+1}}$ 的整數 $u$，近似爲取$x \mod p$的$l$個最高有效位。

根據參考3中的描述，當$l \approx \log^{\frac{1}{2}}{p}$時，有如下算法可以解決HNP：

我們可以將此問題轉化爲一個由該矩陣生成的格上的CVP問題：

$\left[ \begin{matrix} p & 0 & \dots & 0 & 0 \\ 0 & p & \ddots & \vdots & \vdots \\ \vdots & \ddots & \ddots & 0 & \vdots \\ 0 & 0 & \dots & p & 0 \\ t_1 & t_2 & \dots & t_{n} & \frac{1}{2^{l+1}} \end{matrix} \right]$

我們需要找到在格上離$\mathbf{u}=(u_1, u_2, \dots, u_{n}, 0)$最近的向量，所以在這裏，我們可以採用`Babai's nearest plane algorithm`。最終我們可以得到一組向量 $\mathbf{v}=(\alpha \cdot t_1 \mod p, \alpha \cdot t_2 \mod p, \dots, \frac{\alpha}{2^{l+1}})$，從而算出 $\alpha$。

### BCTF 2018 - guess_number

題目提供了服務器端的代碼：
```python
import random, sys
from flag import FLAG
import gmpy2

def msb(k, x, p):
    delta = p >> (k + 1)
    ui = random.randint(x - delta, x + delta)
    return ui

def main():
    p = gmpy2.next_prime(2**160)
    for _ in range(5):
        alpha = random.randint(1, p - 1)
        # print(alpha)
        t = []
        u = []
        k = 10
        for i in range(22):
            t.append(random.randint(1, p - 1))
            u.append(msb(k, alpha * t[i] % p, p))
        print(str(t))
        print(str(u))
        guess = raw_input('Input your guess number: ')
        guess = int(guess)
        if guess != alpha:
            exit(0)

if __name__ == "__main__":
    main()
    print(FLAG)
```

可以看到，程序一共執行5輪。在每一輪，程序會生成一個隨機的$\alpha$和22個隨機的$t_i$。對於每一個$t_i$，程序會取$u_i = MSB_{10,p}(\alpha\cdot{t_i\mod{p}})$，隨後發送給客戶端。我們需要根據提供的$t_i$和$u_i$計算出對應的$\alpha$。可以看到，該問題是一個典型的Hidden number problem，於是可以使用上述算法解決：

```python
import socket
import ast
import telnetlib

#HOST, PORT = 'localhost', 9999
HOST, PORT = '60.205.223.220', 9999

s = socket.socket()
s.connect((HOST, PORT))
f = s.makefile('rw', 0)

def recv_until(f, delim='\n'):
    buf = ''
    while not buf.endswith(delim):
        buf += f.read(1)
    return buf

p = 1461501637330902918203684832716283019655932542983
k = 10

def solve_hnp(t, u):
    # http://www.isg.rhul.ac.uk/~sdg/igor-slides.pdf
    M = Matrix(RationalField(), 23, 23)
    for i in xrange(22):
        M[i, i] = p
        M[22, i] = t[i]

    M[22, 22] = 1 / (2 ** (k + 1))

    def babai(A, w):
        A = A.LLL(delta=0.75)
        G = A.gram_schmidt()[0]
        t = w
        for i in reversed(range(A.nrows())):
            c = ((t * G[i]) / (G[i] * G[i])).round()
            t -= A[i] * c
        return w - t

    closest = babai(M, vector(u + [0]))
    return (closest[-1] * (2 ** (k + 1))) % p

for i in xrange(5):
    t = ast.literal_eval(f.readline().strip())
    u = ast.literal_eval(f.readline().strip())
    alpha = solve_hnp(t, u)
    recv_until(f, 'number: ')
    s.send(str(alpha) + '\n')

t = telnetlib.Telnet()
t.sock = s
t.interact()
```

## 參考

* [Lecture 3 - CVP algorithm](https://cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/cvp.pdf)
* [Wikipedia](https://en.wikipedia.org/wiki/Lattice_problem)
* [Playing “Hide-and-Seek” in Finite Fields: Hidden Number Problem and Its Applications](http://www.isg.rhul.ac.uk/~sdg/igor-slides.pdf)
* https://www.math.auckland.ac.nz/~sgal018/crypto-book/ch18.pdf
