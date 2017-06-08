本节介绍一些计算机相关的编码。

## 字母表编码

- A-Z/a-z对应1-26或者0-25

## ASCII 编码

![ascii](/misc/encode/images/ascii.jpg)

### 特点

我们一般使用的ascii编码的时候采用的都是可见字符，而且主要是如下字符

- 0-9, 49-57
- A-Z, 65-90
- a-z, 97-122

### 变形

#### 二进制编码

将ascii码对应的数字换成二进制表示形式。

- 只有0和1
- 不大于8位，一般7位也可以，因为可见字符到127.
- 其实是另一种ascii编码。

#### 十六进制编码

将ascii码对应的数字换成十六进制表示形式。

- A-Z-->41-5A
- a-z-->61-7A

### 工具

- jpk, ascii to number, number to ascii
- http://www.ab126.com/goju/1711.html

### 例子

![ascii](/misc/encode/images/ascii-example.png)

### 题目

- Jarvis-basic-德军的密码

## Base 编码

Base xx 中的xx表示的是采用多少个字符进行编码，比如说 Base64 就是采用以下 64 个字符编码

![base64](/misc/encode/images/base64.png)

具体介绍参见 [Base64 - 维基百科](https://zh.wikipedia.org/wiki/Base64) 。

### 特点

- base64结尾可能会有**=**号，但最多有两个
- base32结尾可能会最多有3个等号
- 根据base的不同，字符集会有所限制
- **有可能需要自己加等号**
- **=也就是3D**

### 工具

- http://www1.tc711.com/tool/BASE64.htm
- python库函数

### 题目

## 霍夫曼编码

参见 [霍夫曼编码](https://zh.wikipedia.org/wiki/%E9%9C%8D%E5%A4%AB%E6%9B%BC%E7%BC%96%E7%A0%81) 。

## XXencoding

XXencode将输入文本以每三个字节为单位进行编码。如果最后剩下的资料少于三个字节，不够的部份用零补齐。这三个字节共有24个Bit，以6bit为单位分为4个组，每个组以十进制来表示所出现的数值只会落在0到63之间。以所对应值的位置字符代替。

```text
           1         2         3         4         5         6
 0123456789012345678901234567890123456789012345678901234567890123
 |         |         |         |         |         |         |
 +-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
```

具体信息参见[维基百科](https://en.wikipedia.org/wiki/Xxencoding)

### 特点

- 只有数字，大小写字母
- +号，-号。

### 工具

- http://web.chacuo.net/charsetxxencode

### 题目

## URL 编码

参见[URL 编码 - 维基百科](https://zh.wikipedia.org/wiki/%E7%99%BE%E5%88%86%E5%8F%B7%E7%BC%96%E7%A0%81) 。

### 特点

- 大量的百分号

### 工具

### 题目

## Unicode 编码

参见[Unicode - 维基百科](https://zh.wikipedia.org/wiki/Unicode) 。

注意，它有四种表现形式。

### 例子

源文本： `The`

&#x [Hex]： `&#x0054;&#x0068;&#x0065;`

&# [Decimal]： `&#00084;&#00104;&#00101;`

\U [Hex]： `\U0054\U0068\U0065`

\U+ [Hex]： `\U+0054\U+0068\U+0065`

### 工具

### 题目

## HTML 实体编码