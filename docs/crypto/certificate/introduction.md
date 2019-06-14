[EN](./introduction.md) | [ZH](./introduction-zh.md)
#证书格式


## THE


Certificates with this extension are **binary encoding**, of course, these certificates can also use CER or CRT as the extension.


## PEM


Certificates that use this extension are Base64 encoded, starting with a line of `-----BEGIN`.


## Format Conversion


```bash

openssl x509 -outform der -in certificate.pem -out certificate.der

openssl x509 -inform der -in certificate.cer -out certificate.pem

```


