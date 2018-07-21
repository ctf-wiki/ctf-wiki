# Add-Rotate-Xor

## 概述

ARX运算是如下3种基本运算的统称，
- Add 有限域上的模加
- Rotate 循环移位
- Xor 异或

有许多常见的块加密算法在轮函数中只用到了这3种基本运算，典型例子如Salsa20、Speck等。另外[IDEA](./idea.md)也采用了类似的基本运算来构建加揭解密操作，不过以乘法代替了移位。

## 优缺点

### 优点

- 操作简单，运算速度快
- 执行时间为常数，可以避免基于时间的测信道攻击
- 组合后的函数表达能力足够强（参见下方例题）

### 缺点

- 在三种基本运算当中，Rotate、Xor对于单个bit来说均是完全线性的运算，可能会带来一定的脆弱性(参见[Rotational cryptanalysis](https://en.wikipedia.org/wiki/Rotational_cryptanalysis))

## 题目

### 2018 *ctf primitive

#### 分析

本题要求我们组合一定数目以内的Add-Rotate-Xor运算，使得获得的加密算法能够将固定明文加密成指定的随机密文，即通过基础运算来构建任意置换函数。成功构建3次之后即可获得flag。

#### 解题思路

对于模256下的运算，一种典型的基于ARX的换位操作可以表示为如下组合
```
RotateLeft_1(Add_255(RotateLeft_7(Add_2(x))))
```

上述函数对应了一个将254和255进行交换，同时保持其它数字不变的置换运算。

直觉上来说，由于在第一步的模加2运算中，仅有输入为254、255时会发生进位，该组合函数得以区别对待这一情况。

利用上述原子操作，我们可以构造出任意两个数字`a,b`的置换，结合Xor操作，我们可以减少所需的基本操作数目，使其满足题目给出的限制。一种可能的操作步骤如下：

1. 对于`a,b`，通过模加操作使得`a`为0
2. 通过右移使得b的最低位为1
3. 若`b`不为1，进行`Xor 1, Add 255`操作，保持`a`仍然为0，同时`b`的数值减小
4. 重复操作2-3直至`b`为1
5. 进行`Add 254`及换位操作，交换`a,b`
6. 对于换位以外的所有操作，加入对应的逆运算，确保`a,b`以外的数值不变

完整的解题脚本如下：

```python
from pwn import *
import string
from hashlib import sha256

#context.log_level='debug'
def dopow():
    chal = c.recvline()
    post = chal[12:28]
    tar = chal[33:-1]
    c.recvuntil(':')
    found = iters.bruteforce(lambda x:sha256(x+post).hexdigest()==tar, string.ascii_letters+string.digits, 4)
    c.sendline(found)

#c = remote('127.0.0.1',10001)
c = remote('47.75.4.252',10001)
dopow()
pt='GoodCipher'

def doswap(a,b):
    if a==b:
        return
    if a>b:
        tmp=b
        b=a
        a=tmp
    ans=[]
    ans.append((0,256-a))
    b-=a
    a=0
    while b!=1:
        tmp=0
        lo=1
        while b&lo==0:
            lo<<=1
            tmp+=1
        if b==lo:
            ans.append((1,8-tmp))
            break
        if tmp!=0:
            ans.append((1,8-tmp))
        b>>=tmp
        ans.append((2,1))
        b^=1
        ans.append((0,255))
        b-=1
    ans.append((0,254))

    for a,b in ans:
        c.sendline('%d %d'%(a,b))
        c.recvline()
    for a,b in [(0,2),(1,7),(0,255),(1,1)]:
        c.sendline('%d %d'%(a,b))
        c.recvline()
    for a,b in ans[::-1]:
        if a==0:
            c.sendline('%d %d'%(a,256-b))
        elif a==1:
            c.sendline('%d %d'%(a,8-b))
        elif a==2:
            c.sendline('%d %d'%(a,b))
        c.recvline()

for i in range(3):
    print i
    m=range(256)
    c.recvuntil('ciphertext is ')
    ct=c.recvline().strip()
    ct=ct.decode('hex')
    assert len(ct)==10
    for i in range(10):
        a=ord(ct[i])
        b=ord(pt[i])
        #print m[a],b
        doswap(m[a],b)
        for j in range(256):
            if m[j]==b:
                m[j]=m[a]
                m[a]=b
                break
    c.sendline('-1')

c.recvuntil('Your flag here.\n')
print c.recvline()
```
