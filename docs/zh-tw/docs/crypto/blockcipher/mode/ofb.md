# OFB

OFB全稱爲輸出反饋模式（Output feedback），其反饋內容是分組加密後的內容而不是密文。

## 加密

![](./figure/ofb_encryption.png)

## 解密

![](./figure/ofb_decryption.png)

## 優缺點

### 優點

1. 不具有錯誤傳播特性。

### 缺點

1. IV 無需保密，但是對每個消息必須選擇不同的 IV。
2. 不具有自同步能力。

## 適用場景

適用於一些明文冗餘度比較大的場景，如圖像加密和語音加密。

