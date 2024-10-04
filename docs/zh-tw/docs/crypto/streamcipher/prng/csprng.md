# 密碼安全僞隨機數生成器

## 介紹

密碼學安全僞隨機數生成器（cryptographically secure pseudo-random number generator，CSPRNG），也稱爲密碼學僞隨機數生成器（cryptographic pseudo-random number generator，CPRNG），是一種特殊的僞隨機數生成器。它需要滿足滿足一些必要的特性，以便於適合於密碼學應用。

密碼學的很多方面都需要隨機數

-   密鑰生成
-   生成初始化向量，IV，用於分組密碼的 CBC，CFB，OFB 模式
-   nounce，用於防止重放攻擊以及分組密碼的 CTR 模式等、
-   [one-time pads](https://en.wikipedia.org/wiki/One-time_pad)
-   某些簽名方案中的鹽，如 [ECDSA](https://en.wikipedia.org/wiki/ECDSA)， [RSASSA-PSS](https://en.wikipedia.org/w/index.php?title=RSASSA-PSS&action=edit&redlink=1)

## 需求

毫無疑問，密碼學安全僞隨機數生成器的要求肯定比一般的僞隨機數生成器要高。一般而言，CSPRNG 的要求可以分爲兩類

-   通過統計隨機性測試。CSPRNG 必須通過 [next-bit test](https://en.wikipedia.org/wiki/Next-bit_test)，也就是說，知道了一個序列的前 k 個比特，攻擊者不可能在多項式時間內以大於 50% 的概率預測出來下一個比特位。這裏特別提及一點，姚期智曾在 1982 年證明，如果一個生成器可以通過  [next-bit test](https://en.wikipedia.org/wiki/Next-bit_test)，那麼它也可以通過所有其他的多項式時間統計測試。
-   必須能夠抵抗足夠強的攻擊，比如當生成器的部分初始狀態或者運行時的狀態被攻擊者獲知時，攻擊者仍然不能夠獲取泄漏狀態之前的生成的隨機數。

## 分類

就目前而看， CSPRNG 的設計可以分爲以下三類

-   基於密碼學算法，如密文或者哈希值。
-   基於數學難題
-   某些特殊目的的設計

## 參考文獻

-   https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator
