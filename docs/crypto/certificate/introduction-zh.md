[EN](./introduction.md) | [ZH](./introduction-zh.md)
# 证书格式

## DER

使用该扩展名的证书采用**二进制编码**，当然，这些证书也可以使用 CER 或者 CRT 作为扩展名。

## PEM

使用该扩展名的证书采用 Base64 编码，文件的开始是一行 `-----BEGIN`。

## 格式转换

```bash
openssl x509 -outform der -in certificate.pem -out certificate.der
openssl x509 -inform der -in certificate.cer -out certificate.pem
```

