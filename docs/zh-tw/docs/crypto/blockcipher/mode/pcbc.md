# PCBC

PCBC 的全稱爲明文密碼塊鏈接（Plaintext cipher-block chaining）。也稱爲填充密碼塊鏈接（Propagating cipher-block chaining）。

## 加密

![](./figure/pcbc_encryption.png)

## 解密

![](./figure/pcbc_decryption.png)

## 特點

- 解密過程難以並行化
- 互換鄰接的密文塊不會對後面的密文塊造成影響