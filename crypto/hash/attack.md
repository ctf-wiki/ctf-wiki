# Hash Attack

# 暴力攻击



# hash length extension attacks

## 介绍

基本定义如下，源自[维基百科](https://zh.wikipedia.org/wiki/%E9%95%BF%E5%BA%A6%E6%89%A9%E5%B1%95%E6%94%BB%E5%87%BB)。

哈希长度扩展攻击(Hash Length Extension Attacks)是指针对某些允许包含额外信息的加密散列函数的攻击手段。该攻击适用于在**消息与密钥的长度已知**的情形下，所有采取了 H(key ∥ message) 此类构造的散列函数。MD5和SHA-1等基于Merkle–Damgård构造的算法均对此类攻击显示出脆弱性。

这类哈希函数有以下特点

- 消息填充方式都比较类似，首先在消息后面添加一个1，然后填充若干个0，直至总长度与448同余，最后在其后附上64位的消息长度（填充前）。
- 每一块得到的链接变量都会被作为下一次执行hash函数的初始向量IV。在最后一块的时候，才会将其对应的链接变量转换为hash值。

一般攻击时应满足如下条件

- 我们已知key的长度，如果不知道的话，需要爆破出来
- 我们可以控制message的消息。
- 我们已经知道了包含key的一个消息的hash值。

这样我们就可以得到得到一对(messge,x)满足x=H(key ∥ message)虽然我们并不清楚key的内容。

## 攻击原理

这里不妨假设我们我们知道了hash(key+s)本身的hash值，其中s是已知的，那么其本身在计算的时候，必然会进行填充。那么我们首先可以得到key+s扩展后的字符串now，即

now=key|s|padding

那么如果我们在now的后面再次附加上一部分信息extra，即

key|s|padding|extra

这样再去计算hash值的时候，

1. 会对extra进行填充直到满足条件。
2. 先计算前面的产生的链接变量IV1，而我们已经知道这部分的hash值，并且链接变量产生hash值的算法是可逆的，所以我们可以得到链接变量。
3. 下面会根据得到的链接变量IV1，对extra部分进行哈希算法，并返回hash值。

那么既然我们已经知道了第一部分的hash值，并且，我们还知道extra的值，那么我们便可以得到最后的hash值。

而之前我们也说了我们可以控制message的值。那么其实s，padding，extra我们都是可以控制的。所以我们自然可以找到对应的(message,x)满足x=hash(key|message)。

## 例子

似乎大都是web里面的，，不太懂web，暂时先不给例子了。

## 工具

- [hashpump](https://github.com/bwall/HashPump)

如何使用请参考github上的readme。