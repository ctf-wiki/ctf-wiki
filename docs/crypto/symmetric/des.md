# DES

## 基本介绍

DES 全称为 Data Encryption Standard，是典型的块加密，其基本信息如下

- 使用 64 位秘钥中的 56 位，剩余的 8 位要么丢弃，要么作为奇偶校验位
- 输入 64 位
- 输出 64 位。
- 明文经过 16 轮迭代得到密文。

给出一张简单的 [DES 流程图](http://homepage.usask.ca/~dtr467/400/) 。

![](/crypto/symmetric/figure/des.gif)

再给一张比较详细的 [图](http://bbs.pediy.com/thread-90593.htm)。

![](/crypto/symmetric/figure/des_details.jpg)

其中

- S盒的设计标准并未给出。