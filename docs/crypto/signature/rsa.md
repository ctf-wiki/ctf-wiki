# RSA 数字签名

## 原理

原理类似于 RSA 加密，只是这里使用私钥进行加密，将加密后的结果作为签名。

## 2018 Backdoor Awesome mix1

首先，可以简单分析源码，这里程序使用 PKCS1_V1.5 进行了 RSA 签名，这会对明文消息进行扩展，具体扩展规则请参考 https://www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf 。这里给出对应扩展脚本，对应于题目中的 `from Util import PKCS1_pad as pad` 

```python
def PKCS1_pad(data):
    asn1 = "3021300906052b0e03021a05000414"
    ans = asn1 + data
    n = len(ans)
    return int(('00' + '01' + 'ff' * (1024 / 8 - n / 2 - 3) + '00' + ans), 16)
```

程序希望我们给出 `n,e` 使得程序满足 

$h(m)^e mod \ n=pad(m)$

这里我们已经知道 `h(m)，pad(m)`。显然如果我们控制 `e=1`的话，那么

$h(m)-pad(m)=kn$

那么如果我们可以设置 k=1，既可以得到 n。

本地部署 `socat TCP4-LISTEN:12345,fork EXEC:./mix1.py`。

exp 如下

```python
from Crypto.Hash import SHA
from pwn import *

from Util import PKCS1_pad

#context.log_level = 'debug'


def main():
    port = 12345
    host = "127.0.0.1"
    p = remote(host, port)
    p.recvuntil('Message   -> ')
    message = p.recvuntil('\n\nSignature -> ', drop=True)
    log.info('message: ' + message)
    signature = p.recvuntil('\n', drop=True)
    log.info('signature: ' + signature)

    h = SHA.new(message)

    m = PKCS1_pad(h.hexdigest())

    e = 1
    n = int(signature, 16) - m

    p.sendlineafter('Enter n:', str(n))
    p.sendlineafter('Enter e:', str(e))

    p.interactive()


main()

```

效果如下

```shell
➜  2018-BackdoorCTF-Awesome-mix1 git:(master) python exp.py
[+] Opening connection to 127.0.0.1 on port 12345: Done
[*] message: super important information for admin only
[*] signature: 721af5bd401b5f2aff8e86bf811b827cdb5877ef12202f24fa914a26f235523f80c45fdbf0d3c9fa77278828ddd8ca0551a941bd57c97dd38654692568d1357a49e7a2a284d296508602ead24c91e5aa7f517b9e48422575f0dd373d00f267a206ba164ab104c488268b5f95daf490a048407773d4b1016de8ef508bf1aa678f
[*] Switching to interactive mode
CTF{cryp70_5ur3_15_w13rd}
[*] Got EOF while reading in interactive
```

## 2018 Backdoor Awesome mix2

待续。