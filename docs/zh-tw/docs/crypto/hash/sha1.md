# SHA1

## 基本描述

SHA1的輸入輸出如下

- 輸入：任意長的消息，分爲 **512 比特**長的分組。首先在消息右側補比特 1，然後再補若干個比特 0，直到消息的比特長度滿足對 512 取模後餘數是 448，使其與 448 模 512 同餘。
- 輸出：160 比特的消息摘要。

關於詳細的介紹，請自行搜索。

一般來說，我們可以通過函數的初始化來判斷是不是 SHA1 函數。一般來說，如果一個函數有如下五個初始化的變量，可以猜測該函數爲 SHA1 函數，因爲這是 SHA1 函數的初始化IV。

```
0x67452301
0xEFCDAB89
0x98BADCFE
0x10325476
0xC3D2E1F0
```

前面四個與 MD5 類似，後面的是新加的。

## 破解

就目前而言，SHA1 已經不再安全了，因爲之前谷歌公佈了求得兩個 sha1 值一樣的 pdf，具體請參考 [shattered](https://shattered.io/) 。

這裏還有一個比較有意思的網站：https://alf.nu/SHA1。

## 2017 SECCON SHA1 is dead

題目描述如下

1. file1 != file2
2. SHA1(file1) == SHA1(file2)
3. SHA256(file1) <> SHA256(file2)
4. 2017KiB < sizeof(file1) < 2018KiB
5. 2017KiB < sizeof(file2) < 2018KiB

其中 1KiB = 1024 bytes

即我們需要找到兩個文件滿足上述的約束。

這裏立馬就想到谷歌之前公佈的文檔，而且，非常重要的是，只要使用給定的前 320 字節，後面任意添加一樣的字節獲取的哈希仍然一樣，這裏我們測試如下

```shell
➜  2017_seccon_sha1_is_dead git:(master) dd bs=1 count=320 <shattered-1.pdf| sha1sum
記錄了320+0 的讀入
記錄了320+0 的寫出
320 bytes copied, 0.00796817 s, 40.2 kB/s
f92d74e3874587aaf443d1db961d4e26dde13e9c  -
➜  2017_seccon_sha1_is_dead git:(master) dd bs=1 count=320 <shattered-2.pdf| sha1sum
記錄了320+0 的讀入
記錄了320+0 的寫出
320 bytes copied, 0.00397215 s, 80.6 kB/s
f92d74e3874587aaf443d1db961d4e26dde13e9c  -
```

 進而我們直接寫程序即可，如下

```python
from hashlib import sha1
from hashlib import sha256

pdf1 = open('./shattered-1.pdf').read(320)
pdf2 = open('./shattered-2.pdf').read(320)
pdf1 = pdf1.ljust(2017 * 1024 + 1 - 320, "\00")  #padding pdf to 2017Kib + 1
pdf2 = pdf2.ljust(2017 * 1024 + 1 - 320, "\00")
open("upload1", "w").write(pdf1)
open("upload2", "w").write(pdf2)

print sha1(pdf1).hexdigest()
print sha1(pdf2).hexdigest()
print sha256(pdf1).hexdigest()
print sha256(pdf2).hexdigest()
```

## 參考文獻

- https://www.slideshare.net/herumi/googlesha1



