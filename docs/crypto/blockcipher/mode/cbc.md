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

#### 0ops 训练平台某题
以下以 0ops 训练平台的一个题目作为例子:

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

#### 原理

Padding Oracle Attack 除了利用了**字节反转攻击**的原理之外，还利用了另一个特性。那就是密码加密时，必须保证明文的长度为某个$\text{BlockSize}$的整数倍，如果明文的长度不满足这个要求，那么加密前会先增加若干个字符使其满足此要求。假设需要需要最少需要增加x个字符能够满足要求，那么加密前将明文后添加x个ascii值为x的字符。

如果满足这个要求，仍会添加$\text{BlockSize}$个ascii值为$\text{BlockSize}$的字符。

例如如果要加密`admin`这个明文，$\text{BlockSize}=8$。那么加密前会先将明文变成`admin\x03\x03\x03`再进行加密。

所在解密时，需要判断解密出来的密文是否合法，假设有一台服务器允许我们提交密文，然后服务器会返回这是否是一个合法的密文，那么这时候就存在Padding Oracle Attack。

Padding Oracle Attack的功能是：我们现在有一个合法的密文，然后我们可以用Padding Oracle Attack得到全部明文。

我在这里采用与上面**字节翻转攻击**相同的记号。

假设我们总共有$m$块密文，我们想获取第$n$块密文对应的明文，我们先枚举修改第$n-1$块的倒数第一个字节，然后将前$n$块作为密文提交进行解密，当返回**密文合法**时。假设$\text{BlockSize}=8$，第$n$块密文对应的明文为`deadbeef`。

那么我们提交的第$n$块密文解密出来应当是:

```
|d|e|a|d|b|e|e|0x01|
```

因为我们只修改了第$n-1$块的倒数第一个字节，所以只会有最后一个字节有影响，只有最后一个为0x01时合法。

我们假设此时我们枚举到的数为$e$，$f(C_n)$的最后一个字节为$c$，于是c$~\text{xor}~$e=0x01，我们可以求出$e$。

按照这个思路，我们可以枚举倒数第二，第三个字节，求出全部的$f(C_n)$，那么$P_n=f(C_n)~\text{xor}~C_{n-1}$。我们就得到了这一块的明文。

#### 0ops 训练平台某题
放一到模板题方便理解吧

```python
from flag import FLAG
from Crypto.Cipher import AES
from Crypto import Random
import base64

BLOCK_SIZE=16
IV = Random.new().read(BLOCK_SIZE)
passphrase = Random.new().read(BLOCK_SIZE)

pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)


suffix = "flag="+FLAG

def unpad(data):
    padlen=ord(data[-1])
    if padlen<1 or padlen>BLOCK_SIZE:
        return None
    for i in range(1,padlen):
        if data[-1-i]!=chr(padlen):
            return None
    return data[:-padlen]

def decrypt():
    data = raw_input("input your data: ")
    aes = AES.new(passphrase, AES.MODE_CBC, IV)
    plain = unpad(aes.decrypt(base64.b64decode(data)))
    if plain==None:
        print "KO"
    else:
        print "OK"

def encrypt():
    data = raw_input("input your data: ")
    plain = data+suffix
    aes = AES.new(passphrase, AES.MODE_CBC, IV)
    print base64.b64encode(aes.encrypt(pad(plain)))

def menu():
    print "1 for encrypt"
    print "2 for decrypt"
    return raw_input("> ")

def main():
    while True:
        option = menu()
        if option=="1":
            encrypt()
        elif option=="2":
            decrypt()
        else:
            exit()
    


if __name__=="__main__":
    main()
```

exp.py

```python
from pwn import *
import base64

r = remote('xxx.xxx.xxx.xxx', 10005)

def encrypt(data):
    r.sendlineafter('> ', '1')
    r.sendlineafter('data: ', data)

    cipher = r.recv()
    cipher = base64.b64decode(cipher)

    return cipher

def decrypt(data):
    r.sendlineafter('> ', '2')
    r.sendlineafter('data: ', data)
    val = r.recv()
    return 'OK' in val

block_size = 16
cipher = encrypt('a' * 12)
count = len(cipher) / block_size

middle = [0 for i in range(len(cipher))]

def exp(x):
    data, plain0 = list(cipher[0 : (x + 2) * block_size]), ''
    for e in range(1, block_size + 1):
        ind = (x + 1) * block_size - e
        for c in range(256):
            data[ind] = chr(c)
            #print ind, c
            if decrypt(base64.b64encode(''.join(data))):
                middle[ind + block_size] = chr(e ^ c)
                plain0 += chr(c ^ e ^ ord(cipher[ind]))
                #print plain0[::-1]
                for y in range(e):
                    data[ind + y] = chr(ord(middle[ind + y + block_size]) ^ (e + 1))
                break
    print plain0[::-1]

for x in range(0, count - 1):
    exp(x)
r.interactive()
```
