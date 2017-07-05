## 分组模式

有时候明文的长度会比较长，此时会将明文消息的二进制序列划分为固定大小的块，每块分别在密钥控制下变换成等长的二进制密文序列。

![分组加密](/crypto/figure/block.png)

1. 前一个分组的加密结果会影响到下一个分组的加密结果。如 CBC 模式、CFB 模式、OFB 模式。

   ![CBC 模式](/crypto/figure/cbc.png)

2. 前一个分组的加密结果和下一个分组独立。如 ECB 模式、CTR 模式。

   ![ECB 模式](/crypto/figure/ecb.png)


## 证书格式

### DER

使用该扩展名的证书采用**二进制编码**，当然，这些证书也可以使用 CER 或者 CRT 作为扩展名。

### PEM

使用该扩展名的证书采用 Base64 编码，文件的开始是一行 `-----BEGIN`。

### 格式转换

```bash
openssl x509 -outform der -in certificate.pem -out certificate.der
openssl x509 -inform der -in certificate.cer -out certificate.pem
```

