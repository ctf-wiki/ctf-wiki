# CVP

CVP是Lattice-based cryptography中尤为重要的一个问题。

问题的基本定义如下：给定格$L$的一组基与向量$\mathbf{v}$，找到在$L$上离$\mathbf{v}$最近的一个向量。

<!--
TODO: Add more Lattice-based cryptography (CVP specifically) application intro here.
TODO: Make intro more descriptive and rigorous.
-->

## Babai's nearest plane algorithm

<!--
TODO: Add intro
-->

该算法输入一组格$L$(秩为$n$)的基$B$和一个目标向量$\mathbf{t}$，输出CVP问题的近似解。具体请见参考。

对于该算法第二步的个人理解：在格基规约和正交化过后的基$\tilde{B}$中找到一个最靠近$\mathbf{t}$的线性组合。

### BCTF 2018 - guess\_number

题目提供了服务器端的代码：

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

可以看到，程序一共执行5轮。在每一轮，程序会生成一个随机的$\alpha$和22个随机的$t_i$。对于每一个$t_i$，程序会取$u_i = MSB_{10,p}(\alpha\cdot{t_i\mod{p}})$，随后发送给客户端。我们需要根据提供的$t_i$和$u_i$计算出对应的$\alpha$。

根据 http://www.isg.rhul.ac.uk/~sdg/igor-slides.pdf 中的描述，该问题是一个典型的Hidden number problem。我们可以将此问题转化为一个由该矩阵生成的格上的CVP问题：

$\left[ \begin{matrix} p & 0 & \dots & 0 & 0 \\ 0 & p & \ddots & \vdots & \vdots \\ \vdots & \ddots & \ddots & 0 & \vdots \\ 0 & 0 & \dots & p & 0 \\ t_1 & t_2 & \dots & t_{22} & \frac{1}{2^{l+1}} \end{matrix} \right]$

我们需要找到在格上离$\mathbf{u}=(u_1, u_2, \dots, u_{22}, 0)$最近的向量，所以在这里，我们可以采用`Babai's nearest plane algorithm`。最终我们可以得到一组向量 $\mathbf{v}=(\alpha \cdot t_1 \mod p, \alpha \cdot t_2 \mod p, \dots, \frac{\alpha}{2^{l+1}})$，从而算出 $\alpha$。

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

## 参考

* [Lecture 3 - CVP algorithm](https://cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/cvp.pdf)

