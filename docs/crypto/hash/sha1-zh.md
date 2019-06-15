[EN](./sha1.md) | [ZH](./sha1-zh.md)
# SHA1

## 基本描述

SHA1的输入输出如下

- 输入：任意长的消息，分为 **512 比特**长的分组。首先在消息右侧补比特 1，然后再补若干个比特 0，直到消息的比特长度满足对 512 取模后余数是 448，使其与 448 模 512 同余。
- 输出：160 比特的消息摘要。

关于详细的介绍，请自行搜索。

一般来说，我们可以通过函数的初始化来判断是不是 SHA1 函数。一般来说，如果一个函数有如下五个初始化的变量，可以猜测该函数为 SHA1 函数，因为这是 SHA1 函数的初始化IV。

```
0x67452301
0xEFCDAB89
0x98BADCFE
0x10325476
0xC3D2E1F0
```

前面四个与 MD5 类似，后面的是新加的。

## 破解

就目前而言，SHA1 已经不再安全了，因为之前谷歌公布了求得两个 sha1 值一样的 pdf，具体请参考 [shattered](https://shattered.io/) 。

这里还有一个比较有意思的网站：https://alf.nu/SHA1。

## 2017 SECCON SHA1 is dead

题目描述如下

1. file1 != file2
2. SHA1(file1) == SHA1(file2)
3. SHA256(file1) <> SHA256(file2)
4. 2017KiB < sizeof(file1) < 2018KiB
5. 2017KiB < sizeof(file2) < 2018KiB

其中 1KiB = 1024 bytes

即我们需要找到两个文件满足上述的约束。

这里立马就想到谷歌之前公布的文档，而且，非常重要的是，只要使用给定的前 320 字节，后面任意添加一样的字节获取的哈希仍然一样，这里我们测试如下

```shell
➜  2017_seccon_sha1_is_dead git:(master) dd bs=1 count=320 <shattered-1.pdf| sha1sum
记录了320+0 的读入
记录了320+0 的写出
320 bytes copied, 0.00796817 s, 40.2 kB/s
f92d74e3874587aaf443d1db961d4e26dde13e9c  -
➜  2017_seccon_sha1_is_dead git:(master) dd bs=1 count=320 <shattered-2.pdf| sha1sum
记录了320+0 的读入
记录了320+0 的写出
320 bytes copied, 0.00397215 s, 80.6 kB/s
f92d74e3874587aaf443d1db961d4e26dde13e9c  -
```

 进而我们直接写程序即可，如下

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

## 参考文献

- https://www.slideshare.net/herumi/googlesha1



