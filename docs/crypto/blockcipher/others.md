# 2018 Plaid CTF transducipher

题目如下

```python
#!/usr/bin/env python3.6
import os

BLOCK_SIZE = 64

T = [
    ((2, 1), 1),
    ((5, 0), 0),
    ((3, 4), 0),
    ((1, 5), 1),
    ((0, 3), 1),
    ((4, 2), 0),
]


def block2bin(b, length=BLOCK_SIZE):
    return list(map(int, bin(b)[2:].rjust(length, '0')))


def bin2block(b):
    return int("".join(map(str, b)), 2)


def transduce(b, s=0):
    if len(b) == 0:
        return b
    d, t = T[s]
    b0, bp = b[0], b[1:]
    return [b0 ^ t] + transduce(bp, s=d[b0])


def transduceblock(b):
    return bin2block(transduce(block2bin(b)))


def swap(b):
    l = BLOCK_SIZE // 2
    m = (1 << l) - 1
    return (b >> l) | ((b & m) << l)


class Transducipher:

    def __init__(self, k):
        self.k = [k]
        for i in range(1, len(T)):
            k = swap(transduceblock(k))
            self.k.append(k)

    def encrypt(self, b):
        for i in range(len(T)):
            b ^= self.k[i]
            b = transduceblock(b)
            b = swap(b)
        return b


if __name__ == "__main__":
    flag = bytes.hex(os.urandom(BLOCK_SIZE // 8))
    k = int(flag, 16)
    C = Transducipher(k)
    print("Your flag is PCTF{%s}" % flag)
    with open("data1.txt", "w") as f:
        for i in range(16):
            pt = int(bytes.hex(os.urandom(BLOCK_SIZE // 8)), 16)
            ct = C.encrypt(pt)
            f.write(str((pt, ct)) + "\n")

```

题目给了 16 组明密文对

- 明文大小 8 个字节
- 密文大小 8 个字节
- 密钥大小也是 8 个字节

我们所需要求解的就是密钥。

可以看到这里主要有两种基本操作

- swap

```python
def swap(b):
    l = BLOCK_SIZE // 2
    m = (1 << l) - 1
    return (b >> l) | ((b & m) << l)
```

将给定的数据的高 32 位与低 32 位交换。

- transduce

```python
T = [
    ((2, 1), 1),
    ((5, 0), 0),
    ((3, 4), 0),
    ((1, 5), 1),
    ((0, 3), 1),
    ((4, 2), 0),
]
def transduce(b, s=0):
    if len(b) == 0:
        return b
    d, t = T[s]
    b0, bp = b[0], b[1:]
    return [b0 ^ t] + transduce(bp, s=d[b0])
```

其中，

- b 是一个 01 数组，初始时刻大小为 64。
- s 是一个下标。

基本流程如下

1. 根据 s 选择使用 T 的哪个元素，进而将其分为 d 和 t。
2. 将 b 分为两部分，一部分只包含头元素，另一部分包含其它的元素。
3. 将头元素与 t 异或作为当前的头元素，然后继续转换剩下的部分。

其实我们可以将该函数转换为迭代函数

```python
def transduce_iter(b, s=0):
    ans = []
    for c in b:
        d, t = T[s]
        ans += [c ^ t]
        s = d[c]
    return ans
```

进而由于每次处理的是列表的第一个元素，其实该函数是可逆的，如下

```python
def invtransduce(b, s=0):
    if len(b) == 0:
        return b
    d, t = T[s]
    b0, bp = b[0], b[1:]
    return [b0 ^ t] + transduce(bp, s=d[b0 ^ t])
```

下面分析程序的核心流程，首先是生成密钥部分，该加密算法生成了 6 个密钥，每次生成的方法

1. transduce 先前的密钥得到中间值 t
2. 对 t 进行 swap
3. 连续迭代 5 次

```python
    def __init__(self, k):
        self.k = [k]
        for i in range(1, len(T)):
            k = swap(transduceblock(k))
            self.k.append(k)
```

加密算法如下，一共迭代 6 轮，基本流程

1. 异或密钥 transduce
2. 交换

```python
    def encrypt(self, b):
        for i in range(len(T)):
            b ^= self.k[i]
            b = transduceblock(b)
            b = swap(b)
        return b
```

