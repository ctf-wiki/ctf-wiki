# ECB

ECB模式全称为电子密码本模式（Electronic codebook）。

## 加密

![](./figure/ecb_encryption.png)

## 解密

![](./figure/ecb_decryption.png)

## 优缺点

### 优点

1. 实现简单。
2. 不同明文分组的加密可以并行计算，速度很快。

### 缺点

1. 同样的明文块会被加密成相同的密文块，不会隐藏明文分组的统计规律。正如下图所示

![image-20180716215135907](./figure/ecb_bad_linux.png)

为了解决统一明文产生相同密文的问题，提出了其它的加密模式。

## 典型应用

1. 用于随机数的加密保护。
2. 用于单分组明文的加密。

## 2016 ABCTF aes-mess-75

 题目描述如下

```
We encrypted a flag with AES-ECB encryption using a secret key, and got the hash: e220eb994c8fc16388dbd60a969d4953f042fc0bce25dbef573cf522636a1ba3fafa1a7c21ff824a5824c5dc4a376e75 However, we lost our plaintext flag and also lost our key and we can't seem to decrypt the hash back :(. Luckily we encrypted a bunch of other flags with the same key. Can you recover the lost flag using this?

[HINT] There has to be some way to work backwards, right?
```

可以看出，这个加密是一个 ECB 加密，然后 AES 是 16 个字节一组，每个字节可以使用两个 16 进制字符表示，因此，我们每 32 个字符一组进行分组，然后去对应的 txt 文件中搜索即可。

对应 flag

```
e220eb994c8fc16388dbd60a969d4953 abctf{looks_like
f042fc0bce25dbef573cf522636a1ba3 _you_can_break_a
fafa1a7c21ff824a5824c5dc4a376e75 es}
```

最后一个显然在加密时进行了 padding。

## 题目

- 2018 PlaidCTF macsh

