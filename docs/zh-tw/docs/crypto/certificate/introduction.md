# 證書格式


## PEM


PEM 以 `-----BEGIN` 開頭，以 `-----END` 結尾，中間包含 ASN.1 格式的數據。ASN.1 是經過 base64 轉碼的二進制數據。[Wikipedia](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) 上有完整 PEM 文件的例子。


用 Python 3 和 PyCryptodome 庫可以與 PEM 文件交互並提取相關數據。例如我們想提取出模數 `n`：


```py
#!/usr/bin/env python3
from Crypto.PublicKey import RSA

with open("certificate.pem","r") as f:
	key = RSA.import_key(f.read())
	print(key.n)
```


## DER


DER 是 ASN.1 類型的二進制編碼。後綴 `.cer` 或 `.crt` 的證書通常包含 DER 格式的數據，但 Windows 也可能會接受 PEM 格式的數據。


我們可以用 `openssl` 將 PEM 文件轉化爲 DER 文件：


```bash
openssl x509 -inform DER -in certificate.der > certificate.pem
```


現在問題被簡化成了如何讀取 PEM 文件，所以我們可以重複使用上一小節中的 Python 代碼。


## 其他格式轉換


```bash
openssl x509 -outform der -in certificate.pem -out certificate.der
openssl x509 -inform der -in certificate.cer -out certificate.pem
```


## 引用

1. [Attacking RSA for fun and CTF points – part 1](https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-1/)
2. [What are the differences between .pem, .cer and .der?](https://stackoverflow.com/questions/22743415/what-are-the-differences-between-pem-cer-and-der)

