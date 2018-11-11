# PCBC

PCBC 的全称为明文密码块链接（Plaintext cipher-block chaining）。也称为填充密码块链接（Propagating cipher-block chaining）。

## 加密

![](./figure/pcbc_encryption.png)

## 解密

![](./figure/pcbc_decryption.png)

## 特点

- 解密过程难以并行化
- 互换邻接的密文块不会对后面的密文块造成影响