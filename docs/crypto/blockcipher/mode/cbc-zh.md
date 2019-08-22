[EN](./cbc.md) | [ZH](./cbc-zh.md)
# CBC

CBC全称为密码分组链接（Cipher-block chaining） 模式，这里

- IV 不要求保密
- IV 必须是不可预测的，而且要保证完整性。

## 加密

![](./figure/cbc_encryption.png)

## 解密

![](./figure/cbc_decryption.png)

## 优缺点

### 优点

1. 密文块不仅和当前密文块相关，而且和前一个密文块或 IV 相关，隐藏了明文的统计特性。
2. 具有有限的两步错误传播特性，即密文块中的一位变化只会影响当前密文块和下一密文块。
3. 具有自同步特性，即第 k 块起密文正确，则第 k+1 块就能正常解密。

### 缺点

1. 加密不能并行，解密可以并行。

## 应用

CBC 应用十分广泛

- 常见的数据加密和 TLS 加密。
- 完整性认证和身份认证。

## 攻击

###  字节反转攻击

#### 原理
字节反转的原理十分简单，我们观察**解密过程**可以发现如下特性:

- IV 向量影响第一个明文分组
- 第 n 个密文分组可以影响第 n + 1 个明文分组

假设第$n$个密文分组为$C_n$，解密后的第$n$个明文分组为为$P_n$。

然后$P_{n+1}=C_n~\text{xor}~f(C_{n+1})$。

其中$f$函数为图中的$\text{Block Cipher Decryption}$。

对于某个信息已知的原文和密文，然后我们可以修改第$n$个密文块$C_n$为$C_n~\text{xor}~P_{n+1}~\text{xor}~A$。然后再对这条密文进行解密，那么解密后的第$n$个明文快将会变成$A$。

#### 例题

```python
from flag import FLAG
from Crypto.Cipher import AES
from Crypto import Random
import base64

BLOCK_SIZE=16
IV = Random.new().read(BLOCK_SIZE)
passphrase = Random.new().read(BLOCK_SIZE)

pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

prefix = "flag="+FLAG+"&userdata="
suffix = "&user=guest"
def menu():
    print "1. encrypt"
    print "2. decrypt"
    return raw_input("> ")

def encrypt():
    data = raw_input("your data: ")
    plain = prefix+data+suffix
    aes = AES.new(passphrase, AES.MODE_CBC, IV)
    print base64.b64encode(aes.encrypt(pad(plain)))


def decrypt():
    data = raw_input("input data: ")
    aes = AES.new(passphrase, AES.MODE_CBC, IV)
    plain = unpad(aes.decrypt(base64.b64decode(data)))
    print 'DEBUG ====> ' + plain
    if plain[-5:]=="admin":
        print plain
    else:
        print "you are not admin"

def main():
    for _ in range(10):
        cmd = menu()
        if cmd=="1":
            encrypt()
        elif cmd=="2":
            decrypt()
        else:
            exit()

if __name__=="__main__":
    main()
```

可见题目希望我们提供一个加密的字符串，如果这个字符串解密后最后的内容为admin。程序将会输出明文。所以题目流程为先随便提供一个明文，然后将密文进行修改，使得解密后的字符串最后的内容为admin,我们可以枚举flag的长度来确定我们需要在什么位置进行修改。

以下是exp.py

```python
from pwn import *
import base64

pad = 16
data = 'a' * pad
for x in range(10, 100):
    r = remote('xxx.xxx.xxx.xxx', 10004)
    #r = process('./chall.sh')
    
    r.sendlineafter('> ', '1')
    r.sendlineafter('your data: ', data)
    cipher = list(base64.b64decode(r.recv()))
    #print 'cipher ===>', ''.join(cipher)
    
    BLOCK_SIZE = 16
    prefix = "flag=" + 'a' * x + "&userdata="
    suffix = "&user=guest"
    plain = prefix + data + suffix
    
    idx = (22 + x + pad) % BLOCK_SIZE + ((22 + x + pad) / BLOCK_SIZE - 1) * BLOCK_SIZE
    cipher[idx + 0] = chr(ord(cipher[idx + 0]) ^ ord('g') ^ ord('a'))
    cipher[idx + 1] = chr(ord(cipher[idx + 1]) ^ ord('u') ^ ord('d'))
    cipher[idx + 2] = chr(ord(cipher[idx + 2]) ^ ord('e') ^ ord('m'))
    cipher[idx + 3] = chr(ord(cipher[idx + 3]) ^ ord('s') ^ ord('i'))
    cipher[idx + 4] = chr(ord(cipher[idx + 4]) ^ ord('t') ^ ord('n'))

    r.sendlineafter('> ', '2')
    r.sendlineafter('input data: ', base64.b64encode(''.join(cipher)))

    msg = r.recvline()
    if 'you are not admin' not in msg:
        print msg
        break
    r.close()  

```
### Padding Oracle Attack
具体参见下面的介绍。
