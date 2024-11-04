# CFB

CFB 全稱爲密文反饋模式（Cipher feedback）。

## 加密

![](./figure/cfb_encryption.png)

## 解密

![](./figure/cfb_decryption.png)

## 優缺點

### 優點

- 適應於不同數據格式的要求
- 有限錯誤傳播
- 自同步

### 缺點

- 加密不能並行化，解密不能並行

## 應用場景

該模式適應於數據庫加密，無線通信加密等對數據格式有特殊要求的加密環境。

## 題目

- HITCONCTF-Quals-2015-Simple-(Crypto-100)

