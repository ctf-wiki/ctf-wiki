# 比特攻击

## 概述

简单地说，就是利用比特位之间的关系进行攻击。

## 2018 Plaid CTF tranducipher

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

通过分析程序，可知该加密算法是一个块加密，基本信息如下

- 块大小为 8 个字节
- 轮数为 6 轮
- 加密算法的每轮的基本操作为 trandcue 和 swap。
- 密钥的扩展也是与 trandcue 和 swap 相关。

更具体的

1. swap 是将 8 字节的高 32 位与低 32 位进行调换。
2. trandduce 是对于 8 字节的每个比特，逐比特与某个值进行异或。这个值与 T 有关。

通过进一步地分析，我们可以发现这两个函数都是可逆的。也就是说，如果我们知道了最后的密文，那么我们其实可以将原来的轮数缩短为差不多 5 轮，因为最后一轮的 `transduce` 和`swap` 没有作用了。

我们可以定义如下变量

| 名字      | 含义                        |
| --------- | --------------------------- |
| $k_{i,0}$ | 第 i 轮使用的密钥的高 32 位 |
| $k_{i,1}$ | 第 i 轮使用的密钥的低 32 位 |
| $d_{i,0}$ | 第 i 轮使用的输入的高 32 位 |
| $d_{i,1}$ | 第 i 轮使用的输入的低 32 位 |

由于其中有一个核心操作是 swap，只会操纵高或低 32 位，所以我们可以分为两部分考虑。简化定义如下

- Transduce 简化为 T，这里虽然与源代码里冲突，不过我们可以暂时理解一下。
- Swap 简化为 S。

则每一轮的明密文，密钥如下

| 轮数 | 左侧密钥               | 左侧密文                               | 右侧密钥             | 右侧密文                            |
| ---- | ---------------------- | -------------------------------------- | -------------------- | ----------------------------------- |
| 0    | $k_{0,0}$              | $d_{1,0}=T(k_{0,1} \oplus d_{0,1} ,s)$ | $k_{0,1}$            | $d_{1,1}=T(k_{0,0} \oplus d_{0,0})$ |
| 1    | $k_{1,0}=T(k_{0,1},s)$ | $d_{2,0}=T(k_{1,1} \oplus d_{1,1} ,s)$ | $k_{1,1}=T(k_{0,0})$ | $d_{2,1}=T(k_{1,0} \oplus d_{1,0})$ |
| 2    | $k_{2,0}=T(k_{1,1},s)$ | $d_{3,0}=T(k_{2,1} \oplus d_{2,1} ,s)$ | $k_{2,1}=T(k_{1,0})$ | $d_{3,1}=T(k_{2,0} \oplus d_{2,0})$ |
| 3    | $k_{3,0}=T(k_{2,1},s)$ | $d_{4,0}=T(k_{3,1} \oplus d_{3,1} ,s)$ | $k_{3,1}=T(k_{2,0})$ | $d_{4,1}=T(k_{3,0} \oplus d_{3,0})$ |
| 4    | $k_{4,0}=T(k_{3,1},s)$ | $d_{5,0}=T(k_{4,1} \oplus d_{4,1} ,s)$ | $k_{4,1}=T(k_{3,0})$ | $d_{5,1}=T(k_{4,0} \oplus d_{4,0})$ |
| 5    | $k_{5,0}=T(k_{4,1},s)$ | $d_{6,0}=T(k_{5,1} \oplus d_{5,1} ,s)$ | $k_{5,1}=T(k_{4,0})$ | $d_{6,1}=T(k_{5,0} \oplus d_{5,0})$ |

那么，我们可以逐比特位枚举 k 的高 32 位，同时枚举在进行 T 操作时的可能的 s 状态位，这样就可以获取高 32 位密钥。在进行逐位爆破之后，我们可以从获取两个可能结果

```
[2659900894, 2659900895]
```

再根据左边的结果，可以去获取右边可能的结果，利用 2659900894 获取的可能的结果如下

```
# 第一组明密文对对应的密钥可能太多。
# 第二组一共 6 个。
[2764038144, 2764038145, 2764038152, 2764038153, 2764038154, 2764038155]
# 第三组
[2764038144, 2764038145]
```

然后其实我们就可以手工试一下加密所有的明密文，如果不对，就直接判断错误即可了。这样其实可以很快可以过滤。最后可以发现密钥是

```
2659900894|2764038145
```

也就是11424187353095200769。也就拿到了 flag。

当然，本题目也可以使用中间相遇的攻击方法，也就是说分别枚举第 0 轮使用的密钥和最后一轮使用的密钥使其在第三轮相遇产生碰撞。

## 参考

- http://blog.rb-tree.xyz/2018/05/07/plaidctf-2018-transducipher/