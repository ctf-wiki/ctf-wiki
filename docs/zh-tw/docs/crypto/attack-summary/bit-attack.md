# 比特攻擊

## 概述

簡單地說，就是利用比特位之間的關係進行攻擊。

## 2018 Plaid CTF transducipher

題目如下

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

題目給了 16 組明密文對

- 明文大小 8 個字節
- 密文大小 8 個字節
- 密鑰大小也是 8 個字節

我們所需要求解的就是密鑰。

可以看到這裏主要有兩種基本操作

- swap

```python
def swap(b):
    l = BLOCK_SIZE // 2
    m = (1 << l) - 1
    return (b >> l) | ((b & m) << l)
```

將給定的數據的高 32 位與低 32 位交換。

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

- b 是一個 01 數組，初始時刻大小爲 64。
- s 是一個下標。

基本流程如下

1. 根據 s 選擇使用 T 的哪個元素，進而將其分爲 d 和 t。
2. 將 b 分爲兩部分，一部分只包含頭元素，另一部分包含其它的元素。
3. 將頭元素與 t 異或作爲當前的頭元素，然後繼續轉換剩下的部分。

其實我們可以將該函數轉換爲迭代函數

```python
def transduce_iter(b, s=0):
    ans = []
    for c in b:
        d, t = T[s]
        ans += [c ^ t]
        s = d[c]
    return ans
```

進而由於每次處理的是列表的第一個元素，其實該函數是可逆的，如下

```python
def invtransduce(b, s=0):
    if len(b) == 0:
        return b
    d, t = T[s]
    b0, bp = b[0], b[1:]
    return [b0 ^ t] + transduce(bp, s=d[b0 ^ t])
```

下面分析程序的核心流程，首先是生成密鑰部分，該加密算法生成了 6 個密鑰，每次生成的方法

1. transduce 先前的密鑰得到中間值 t
2. 對 t 進行 swap
3. 連續迭代 5 次

```python
    def __init__(self, k):
        self.k = [k]
        for i in range(1, len(T)):
            k = swap(transduceblock(k))
            self.k.append(k)
```

加密算法如下，一共迭代 6 輪，基本流程

1. 異或密鑰 transduce
2. 交換

```python
    def encrypt(self, b):
        for i in range(len(T)):
            b ^= self.k[i]
            b = transduceblock(b)
            b = swap(b)
        return b
```

通過分析程序，可知該加密算法是一個塊加密，基本信息如下

- 塊大小爲 8 個字節
- 輪數爲 6 輪
- 加密算法的每輪的基本操作爲 transduce 和 swap。
- 密鑰的擴展也是與 transduce 和 swap 相關。

更具體的

1. swap 是將 8 字節的高 32 位與低 32 位進行調換。
2. transduce 是對於 8 字節的每個比特，逐比特與某個值進行異或。這個值與 T 有關。

通過進一步地分析，我們可以發現這兩個函數都是可逆的。也就是說，如果我們知道了最後的密文，那麼我們其實可以將原來的輪數縮短爲差不多 5 輪，因爲最後一輪的 `transduce` 和`swap` 沒有作用了。

我們可以定義如下變量

| 名字      | 含義                        |
| --------- | --------------------------- |
| $k_{i,0}$ | 第 i 輪使用的密鑰的高 32 位 |
| $k_{i,1}$ | 第 i 輪使用的密鑰的低 32 位 |
| $d_{i,0}$ | 第 i 輪使用的輸入的高 32 位 |
| $d_{i,1}$ | 第 i 輪使用的輸入的低 32 位 |

由於其中有一個核心操作是 swap，只會操縱高或低 32 位，所以我們可以分爲兩部分考慮。簡化定義如下

- Transduce 簡化爲 T，這裏雖然與源代碼裏衝突，不過我們可以暫時理解一下。
- Swap 簡化爲 S。

則每一輪的明密文，密鑰如下

| 輪數 | 左側密鑰               | 左側密文                               | 右側密鑰             | 右側密文                            |
| ---- | ---------------------- | -------------------------------------- | -------------------- | ----------------------------------- |
| 0    | $k_{0,0}$              | $d_{1,0}=T(k_{0,1} \oplus d_{0,1} ,s)$ | $k_{0,1}$            | $d_{1,1}=T(k_{0,0} \oplus d_{0,0})$ |
| 1    | $k_{1,0}=T(k_{0,1},s)$ | $d_{2,0}=T(k_{1,1} \oplus d_{1,1} ,s)$ | $k_{1,1}=T(k_{0,0})$ | $d_{2,1}=T(k_{1,0} \oplus d_{1,0})$ |
| 2    | $k_{2,0}=T(k_{1,1},s)$ | $d_{3,0}=T(k_{2,1} \oplus d_{2,1} ,s)$ | $k_{2,1}=T(k_{1,0})$ | $d_{3,1}=T(k_{2,0} \oplus d_{2,0})$ |
| 3    | $k_{3,0}=T(k_{2,1},s)$ | $d_{4,0}=T(k_{3,1} \oplus d_{3,1} ,s)$ | $k_{3,1}=T(k_{2,0})$ | $d_{4,1}=T(k_{3,0} \oplus d_{3,0})$ |
| 4    | $k_{4,0}=T(k_{3,1},s)$ | $d_{5,0}=T(k_{4,1} \oplus d_{4,1} ,s)$ | $k_{4,1}=T(k_{3,0})$ | $d_{5,1}=T(k_{4,0} \oplus d_{4,0})$ |
| 5    | $k_{5,0}=T(k_{4,1},s)$ | $d_{6,0}=T(k_{5,1} \oplus d_{5,1} ,s)$ | $k_{5,1}=T(k_{4,0})$ | $d_{6,1}=T(k_{5,0} \oplus d_{5,0})$ |

那麼，我們可以逐比特位枚舉 k 的高 32 位，同時枚舉在進行 T 操作時的可能的 s 狀態位，這樣就可以獲取高 32 位密鑰。在進行逐位爆破之後，我們可以從獲取兩個可能結果

```
[2659900894, 2659900895]
```

再根據左邊的結果，可以去獲取右邊可能的結果，利用 2659900894 獲取的可能的結果如下

```
# 第一組明密文對對應的密鑰可能太多。
# 第二組一共 6 個。
[2764038144, 2764038145, 2764038152, 2764038153, 2764038154, 2764038155]
# 第三組
[2764038144, 2764038145]
```

然後其實我們就可以手工試一下加密所有的明密文，如果不對，就直接判斷錯誤即可了。這樣其實可以很快可以過濾。最後可以發現密鑰是

```
2659900894|2764038145
```

也就是11424187353095200769。也就拿到了 flag。

當然，本題目也可以使用中間相遇的攻擊方法，也就是說分別枚舉第 0 輪使用的密鑰和最後一輪使用的密鑰使其在第三輪相遇產生碰撞。

## 參考

- http://blog.rb-tree.xyz/2018/05/07/plaidctf-2018-transducipher/
