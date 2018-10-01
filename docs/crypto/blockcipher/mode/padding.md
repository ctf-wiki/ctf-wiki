# 填充规则

正如我们之前所说，在分组加密中，明文的长度往往并不满足要求，需要进行 padding，而如何 padding 目前也已经有了不少的规定。

常见的 [填充规则]( https://www.di-mgt.com.au/cryptopad.html) 如下。**需要注意的是，即使消息的长度是块大小的整数倍，仍然需要填充。**

一般来说，如果在解密之后发现 Padding 不正确，则往往会抛出异常。我们也因此可以知道 Paddig 是否正确。

## Pad with bytes all of the same value as the number of padding bytes (PKCS5 padding)

举例子如下

```
DES INPUT BLOCK  = f  o  r  _  _  _  _  _
(IN HEX)           66 6F 72 05 05 05 05 05
KEY              = 01 23 45 67 89 AB CD EF
DES OUTPUT BLOCK = FD 29 85 C9 E8 DF 41 40
```

## Pad with 0x80 followed by zero bytes (OneAndZeroes Padding)

举例子如下

```
DES INPUT BLOCK  = f  o  r  _  _  _  _  _
(IN HEX)           66 6F 72 80 00 00 00 00
KEY              = 01 23 45 67 89 AB CD EF
DES OUTPUT BLOCK = BE 62 5D 9F F3 C6 C8 40
```

这里其实就是和 md5 和 sha1 的 padding 差不多。

## Pad with zeroes except make the last byte equal to the number of padding bytes

举例子如下

```
DES INPUT BLOCK  = f  o  r  _  _  _  _  _
(IN HEX)           66 6f 72 00 00 00 00 05
KEY              = 01 23 45 67 89 AB CD EF
DES OUTPUT BLOCK = 91 19 2C 64 B5 5C 5D B8
```

## Pad with zero (null) characters

举例子如下

```
DES INPUT BLOCK  = f  o  r  _  _  _  _  _
(IN HEX)           66 6f 72 00 00 00 00 00
KEY              = 01 23 45 67 89 AB CD EF
DES OUTPUT BLOCK = 9E 14 FB 96 C5 FE EB 75
```

## Pad with spaces

举例子如下

```
DES INPUT BLOCK  = f  o  r  _  _  _  _  _
(IN HEX)           66 6f 72 20 20 20 20 20
KEY              = 01 23 45 67 89 AB CD EF
DES OUTPUT BLOCK = E3 FF EC E5 21 1F 35 25
```

