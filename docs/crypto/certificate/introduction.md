[EN](./introduction.md) | [ZH](./introduction-zh.md)
#证书格式


## PEM


PEM is just ASN.1 data put between headers `-----BEGIN` and `-----END`, where ASN.1 is binary data with base64 encoding. There are valid PEM examples [here on Wikipedia](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail).


With Python 3 and the PyCryptodome library, we could easily access a PEM file and extract data from it. For example, say we want to extract the modulus `n`:


```py
#!/usr/bin/env python3
from Crypto.PublicKey import RSA

with open("certificate.pem","r") as f:
	key = RSA.import_key(f.read())
	print(key.n)
```


## DER


DER is a **binary encoding** method for data described by ASN.1. Certificates with the `.cer` or `.crt` extension usually contains DER formatted data, but Windows might also accept PEM formatted data.


To work with a DER file, we could convert it to PEM using `openssl`:


```bash
openssl x509 -inform DER -in certificate.der > certificate.pem
```

Now the problem is reduced to "how to work with a PEM file", so we could use the same Python code as the one in the PEM section.

## Additonal Format Conversion

```bash
openssl x509 -outform der -in certificate.pem -out certificate.der
openssl x509 -inform der -in certificate.cer -out certificate.pem
```

## Reference

1. [Attacking RSA for fun and CTF points – part 1](https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-1/)
2. [What are the differences between .pem, .cer and .der?](https://stackoverflow.com/questions/22743415/what-are-the-differences-between-pem-cer-and-der)

