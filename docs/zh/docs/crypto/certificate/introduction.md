# 证书格式


## PEM


PEM 以 `-----BEGIN` 开头，以 `-----END` 结尾，中间包含 ASN.1 格式的数据。ASN.1 是经过 base64 转码的二进制数据。[Wikipedia](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) 上有完整 PEM 文件的例子。


用 Python 3 和 PyCryptodome 库可以与 PEM 文件交互并提取相关数据。例如我们想提取出模数 `n`：


```py
#!/usr/bin/env python3
from Crypto.PublicKey import RSA

with open("certificate.pem","r") as f:
	key = RSA.import_key(f.read())
	print(key.n)
```


## DER


DER 是 ASN.1 类型的二进制编码。后缀 `.cer` 或 `.crt` 的证书通常包含 DER 格式的数据，但 Windows 也可能会接受 PEM 格式的数据。


我们可以用 `openssl` 将 PEM 文件转化为 DER 文件：


```bash
openssl x509 -inform DER -in certificate.der > certificate.pem
```


现在问题被简化成了如何读取 PEM 文件，所以我们可以重复使用上一小节中的 Python 代码。


## 其他格式转换


```bash
openssl x509 -outform der -in certificate.pem -out certificate.der
openssl x509 -inform der -in certificate.cer -out certificate.pem
```


## 引用

1. [Attacking RSA for fun and CTF points – part 1](https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-1/)
2. [What are the differences between .pem, .cer and .der?](https://stackoverflow.com/questions/22743415/what-are-the-differences-between-pem-cer-and-der)

