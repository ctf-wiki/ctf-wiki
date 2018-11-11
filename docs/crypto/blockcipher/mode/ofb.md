# OFB

OFB全称为输出反馈模式（Output feedback），其反馈内容是分组加密后的内容而不是密文。

## 加密

![](./figure/ofb_encryption.png)

## 解密

![](./figure/ofb_decryption.png)

## 优缺点

### 优点

1. 不具有错误传播特性。

### 缺点

1. IV 无需保密，但是对每个消息必须选择不同的 IV。
2. 不具有自同步能力。

## 适用场景

适用于一些明文冗余度比较大的场景，如图像加密和语音加密。

