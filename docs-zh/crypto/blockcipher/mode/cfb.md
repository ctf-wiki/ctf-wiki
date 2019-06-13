# CFB

CFB 全称为密文反馈模式（Cipher feedback）。

## 加密

![](./figure/cfb_encryption.png)

## 解密

![](./figure/cfb_decryption.png)

## 优缺点

### 优点

- 适应于不同数据格式的要求
- 有限错误传播
- 自同步

### 缺点

- 加密不能并行化，解密不能并行

## 应用场景

该模式适应于数据库加密，无线通信加密等对数据格式有特殊要求的加密环境。

## 题目

- HITCONCTF-Quals-2015-Simple-(Crypto-100)

