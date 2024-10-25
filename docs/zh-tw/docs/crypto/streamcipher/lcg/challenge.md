# 題目

## 2016 Google CTF woodman

程序的大概意思就是一個猜數遊戲，如果連續猜中若干次，就算會拿到 flag，背後的生成相應數的核心代碼如下

```python
class SecurePrng(object):
    def __init__(self):
        # generate seed with 64 bits of entropy
        self.p = 4646704883L
        self.x = random.randint(0, self.p)
        self.y = random.randint(0, self.p)

    def next(self):
        self.x = (2 * self.x + 3) % self.p
        self.y = (3 * self.y + 9) % self.p
        return (self.x ^ self.y)
```

這裏我們顯然，我們猜出前兩輪還是比較容易的，畢竟概率也有 0.25。這裏當我們猜出前兩輪後，使用 Z3 來求解出初始的 x 和 y，那麼我們就可以順利的猜出剩下的值了。

具體的腳本如下，然而 Z3 在解決這樣的問題時似乎是有問題的。。。

這裏我們考慮另外一種方法，**依次從低比特位枚舉到高比特位獲取 x 的值**，之所以能夠這樣做，是依賴於這樣的觀察

- a + b = c，c 的第 i 比特位的值只受 a 和 b 該比特位以及更低比特位的影響。**因爲第 i 比特位進行運算時，只有可能收到低比特位的進位數值。**
- a - b = c，c 的第 i 比特位的值只受 a 和 b 該比特位以及更低比特位的影響。**因爲第 i 比特位進行運算時，只有可能向低比特位的借位。**
- a * b = c，c 的第 i 比特位的值只受 a 和 b 該比特位以及更低比特位的影響。因爲這可以視作多次加法。
- a % b = c，c 的第 i 比特位的值只受 a 和 b 該比特位以及更低比特位的影響。因爲這可視爲多次進行減法。
- a ^ b = c，c 的第 i 比特位的值只受 a 和 b 該比特位的影響。這一點是顯而易見的。

**注：個人感覺這個技巧非常有用。**

此外，我們不難得知 p 的比特位爲 33 比特位。具體利用思路如下

1. 首先獲取兩次猜到的值，這個概率有 0.25。
2. 依次從低比特位到高比特位依次枚舉**第一次迭代後的 x 的相應比特位**。
3. 根據自己枚舉的值分別計算出第二次的值，只有當對應比特位正確，可以將其加入候選正確值。需要注意的是，這裏由於取模，所以我們需要枚舉到底減了多少次。
4. 此外，在最終判斷時，仍然需要確保對應的值滿足一定要求，因爲之前對減了多少次進行了枚舉。

具體利用代碼如下

```python
import os
import random
from itertools import product


class SecurePrng(object):
    def __init__(self, x=-1, y=-1):
        # generate seed with 64 bits of entropy
        self.p = 4646704883L  # 33bit
        if x == -1:
            self.x = random.randint(0, self.p)
        else:
            self.x = x
        if y == -1:
            self.y = random.randint(0, self.p)
        else:
            self.y = y

    def next(self):
        self.x = (2 * self.x + 3) % self.p
        self.y = (3 * self.y + 9) % self.p
        return (self.x ^ self.y)


def getbiti(num, idx):
    return bin(num)[-idx - 1:]


def main():
    sp = SecurePrng()
    targetx = sp.x
    targety = sp.y
    print "we would like to get x ", targetx
    print "we would like to get y ", targety

    # suppose we have already guess two number
    guess1 = sp.next()
    guess2 = sp.next()

    p = 4646704883

    # newx = tmpx*2+3-kx*p
    for kx, ky in product(range(3), range(4)):
        candidate = [[0]]
        # only 33 bit
        for i in range(33):
            #print 'idx ', i
            new_candidate = []
            for old, bit in product(candidate, range(2)):
                #print old, bit
                oldx = old[0]
                #oldy = old[1]
                tmpx = oldx | ((bit & 1) << i)
                #tmpy = oldy | ((bit / 2) << i)
                tmpy = tmpx ^ guess1
                newx = tmpx * 2 + 3 - kx * p + (1 << 40)
                newy = tmpy * 3 + 9 - ky * p + (1 << 40)
                tmp1 = newx ^ newy
                #print "tmpx:    ", bin(tmpx)
                #print "targetx: ", bin(targetx)
                #print "calculate:     ", bin(tmp1 + (1 << 40))
                #print "target guess2: ", bin(guess1 + (1 << 40))
                if getbiti(guess2 + (1 << 40), i) == getbiti(
                        tmp1 + (1 << 40), i):
                    if [tmpx] not in new_candidate:
                        #print "got one"
                        #print bin(tmpx)
                        #print bin(targetx)
                        #print bin(tmpy)
                        new_candidate.append([tmpx])
            candidate = new_candidate
            #print len(candidate)
            #print candidate
        print "candidate x for kx: ", kx, " ky ", ky
        for item in candidate:
            tmpx = candidate[0][0]
            tmpy = tmpx ^ guess1
            if tmpx >= p or tmpx >= p:
                continue
            mysp = SecurePrng(tmpx, tmpy)
            tmp1 = mysp.next()
            if tmp1 != guess2:
                continue
            print tmpx, tmpy
            print(targetx * 2 + 3) % p, (targety * 3 + 9) % p


if __name__ == "__main__":
    main()
```

