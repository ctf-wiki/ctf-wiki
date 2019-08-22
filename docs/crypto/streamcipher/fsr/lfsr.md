[EN](./lfsr.md) | [ZH](./lfsr-zh.md)
# Linear Feedback Shift Register - LFSR


## Introduction


The feedback function of the linear feedback shift register is generally as follows


$a_{i+n}=\sum\limits_{j=1}^{n}c_ja_{i+n-j}$



Where $c_j$ is in a finite field $F_q$.


Since the linear space is a linear transformation, we can know that this linear transformation is


$$ \left[ \begin{matrix} 0   & 0      & \cdots & 0 & c_n     \\ 1   & 0      & \cdots & 0 & c_{n-1}  \\ 0   & 1      & \cdots & 0 & c_{n-2}\\\vdots & \vdots & \ddots & \vdots \\ 0   & 0      & \cdots & 1 & c_1     \\ \end{matrix} \right] $$



Furthermore, we can find the characteristic polynomial as


$ f (x) = x ^ n- \ sum \ limit_ {i = 1} ^ {n} c_ix ^ {in} $


At the same time, we define its reciprocal polynomial as


$\overline f(x)=x^nf(\frac{1}{x})=1-\sum\limits_{i=1}^{n}c_ix^{i}$



We also call the reciprocal polynomial as the joint polynomial of the linear feedback shift register.


Here are some theorems that we need to remember. Interesting can be derived by ourselves.


## Characteristic Polynomial and Generator


Knowing the characteristic polynomial of an n-level linear feedback shift register, then the corresponding generation function of the sequence is


$A(x)=\frac{p(x)}{\overline f(x)}$



Where $p(x)=\sum\limits_{i=1}^{n}(c_{ni}x^{ni}\sum\limits_{j=1}^{i}a_jx^{j-1 })$. It can be seen that p(x) is completely determined by the initial state and the coefficient of the feedback function.


## Sequence cycle and generation function


The period of the sequence is the period of the denominator of the resulting true fraction of the function.


For n-level linear feedback shift registers, the longest period is $2^{n-1}$ (excluding all zeros). The sequence that reaches the longest period is generally referred to as the m sequence.


## Special nature


- The two sequences are accumulated to give a new sequence whose period is the sum of the periods of the two sequences.
- The sequence is an n-level m sequence if and only if the minimal polynomial of the sequence is n primitive polynomials.


## BM algorithm


In general, we can consider LFSR from two perspectives.


- Key generation angle. Generally, we want to use a LFSR with as low a level as possible to generate a sequence with a large period and good randomness.
- Cryptographic analysis, given a sequence a of length n, how to construct a LFSR with as few stages as possible to generate it. In fact, this is the source of the BM algorithm.


In general, we define the linear complexity of a sequence as follows


- If s is an all-zero sequence, the linear complexity is zero.
- If no LFSR can generate s, the linear complexity is infinite.
- Otherwise, the linear complexity of s is the minimum level of LFSR that generates L(s).


The requirements of the BM algorithm we need to know the sequence of length 2n. Complexity


- Time complexity: O(n^2) sub-bit operation
- Space complexity: O(n) bits.


Details about the BM algorithm, added later, are currently in the learning process.


But in fact, if we know the sequence of length 2n, we can also get a stupid way to get the original sequence. Let&#39;s assume that the known sequence is $a_1,...,a_{2n}$, we can make


$S_1=(a_1,...,a_n)$



$S_2=(a_2,...,a_{n+1})$



....



$S_{n+1}=(a_{n+1},...,a_{2n})$



Then we can construct the matrix $X=(S_1,...,S_n)$, then


$S_{n+1}=(c_n,...,c_1)X$



and so


$(c_n,...,c_1)=S_{n+1}X^{-1}$



Then we also know the feedback expression of the LFSR, and then we can introduce the initialization seed.


## 2018 强网杯streamgame1


Simply look at the topic


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



It can be found that the length of the flag is 25-5-1=19, so it can be violently enumerated. result


```shell

➜ 2018-Strong Net Cup-streamgame1 git:(master) ✗ python exp.py
12

0b1110101100001101011

```


Therefore flag is flag{1110101100001101011}.


## 2018 CISCN preliminary match oldstreamgame


Simply look at the topic


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



The program is very simple, it is still an LFSR, but the initial state is 32 bits. Of course, we can also choose to blast, but here we do not choose blasting.


Here are two approaches.


In the first method, the 32th bit of the program output is determined by the first 31 bits of the program output and the first bit of the initial seed, so we can know the first bit of the initial seed, and then we can know the initial seed. The second bit, and so on. code show as below


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

ans = &quot;&quot;
key = key[31] + key[:32]

while idx < 32:

    tmp = 0

    for i in range(32):

        if mask >> i & 1:

            tmp ^= int(key[31 - i])

ans = str (tmp) + years
    idx += 1

    key = key[31] + str(tmp) + key[1:31]

Surely = int (ans, 2)
Print Hex (whether)
```



run


```shell

➜  2018-CISCN-start-oldstreamgame git:(master) ✗ python exp1.py

0x926201d7

```



In the second approach, we can consider the process of matrix conversion. If 32 linear transformations are performed, the first 32 bits of the output stream can be obtained. In fact, we only need the first 32 bits to restore the initial state.




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

Print Hex (whether)
```





Running script


```shell

➜  2018-CISCN-start-oldstreamgame git:(master) ✗ sage exp.sage

32

0x926201d7

```



Thus flag is flag{926201d7}.


Another way is for TokyoWesterns, you can refer to the corresponding folder file.


## topic






## references

- Cryptography handouts, edited by Li Chao, Qu Longjiang