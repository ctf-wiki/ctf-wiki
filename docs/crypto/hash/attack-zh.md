[EN](./attack.md) | [ZH](./attack-zh.md)
# Hash Attack

常见的Hash函数的攻击方法主要有

-  暴力攻击：不依赖于任何算法细节，仅与Hash值长度有关；
  - 生日攻击法(Birthday Attack)：没有利用Hash函数的结构和任何代数弱性质，只依赖于消息摘要的长度，即Hash值的长度。
  - 中点交会攻击法(Meet-In-The-Middle)：是生日攻击的一种变形，不比较Hash值，而是比较中间变量。这种攻击主要适用于攻击具有分组链结构的Hash方案。
-  密码分析：依赖于具体算法的设计缺点。

## 暴力攻击

 **HashCat 工具** 可以说是目前最好的基于 CPU 和 GPU 破解 Hash 的软件，相关链接如下

[HashCat 官网](http://www.hashcat.net/hashcat/)

[HashCat 简单使用](http://www.freebuf.com/sectool/112479.html)

## 哈希长度拓展攻击（hash length extension attacks）
### 介绍

基本定义如下，源自[维基百科](https://zh.wikipedia.org/wiki/%E9%95%BF%E5%BA%A6%E6%89%A9%E5%B1%95%E6%94%BB%E5%87%BB)。

哈希长度扩展攻击(Hash Length Extension Attacks)是指针对某些允许包含额外信息的加密散列函数的攻击手段。该攻击适用于在**消息与密钥的长度已知**的情形下，所有采取了 H(key ∥ message) 此类构造的散列函数。MD5和SHA-1 等基于 Merkle–Damgård 构造的算法均对此类攻击显示出脆弱性。

这类哈希函数有以下特点

- 消息填充方式都比较类似，首先在消息后面添加一个1，然后填充若干个0，直至总长度与 448 同余，最后在其后附上64位的消息长度（填充前）。
- 每一块得到的链接变量都会被作为下一次执行hash函数的初始向量IV。在最后一块的时候，才会将其对应的链接变量转换为hash值。

一般攻击时应满足如下条件

- 我们已知 key 的长度，如果不知道的话，需要爆破出来
- 我们可以控制 message 的消息。
- 我们已经知道了包含 key 的一个消息的hash值。

这样我们就可以得到一对(messge,x)满足x=H(key ∥ message)虽然我们并不清楚key的内容。

### 攻击原理

这里不妨假设我们我们知道了 hash(key+s) 的 hash 值，其中 s 是已知的，那么其本身在计算的时候，必然会进行填充。那么我们首先可以得到 key+s 扩展后的字符串 now，即

now=key|s|padding

那么如果我们在 now 的后面再次附加上一部分信息extra，即

key|s|padding|extra

这样再去计算hash值的时候，

1. 会对 extra 进行填充直到满足条件。
2. 先计算 now 对应的链接变量 IV1，而我们已经知道这部分的 hash 值，并且链接变量产生 hash 值的算法是可逆的，所以我们可以得到链接变量。
3. 下面会根据得到的链接变量 IV1，对 extra 部分进行哈希算法，并返回hash值。

那么既然我们已经知道了第一部分的 hash 值，并且，我们还知道 extra 的值，那么我们便可以得到最后的hash值。

而之前我们也说了我们可以控制 message 的值。那么其实 s，padding，extra 我们都是可以控制的。所以我们自然可以找到对应的(message,x)满足x=hash(key|message)。

### 例子

似乎大都是web里面的，，不太懂web，暂时先不给例子了。

### 工具

- [hashpump](https://github.com/bwall/HashPump)

如何使用请参考github上的readme。

## hash算法设计有误
一些自定义的hash算法可能是可逆的。

### Hashinator
题目的逻辑很简单，从一个知名的密码字典"rockyou"挑选出一个`password`，并且使用多种hash算法随机的哈希32轮。我们需要从最后的hash结果中破解出原始的`password`。

#### 分析
题目采用的hash算法有：`md5`，`sha1`，`blake`，`scrypt`。
关键的代码如下：
```python
    password = self.generate_password()     # from rock_you.txt
    salt = self.generate_salt(password)     # 与password的长度有关
    hash_rounds = self.generate_rounds()    # 生成进行hash算法的顺序
    password_hash = self.calculate_hash(salt + password, hash_rounds)
```
1. 程序首先通过从`rockyou.txt`中随机抽取一个`password`，作为加密的明文。
2. 然后根据抽取的`password`的长度，生成一个长度为`128 - len(password)`的`salt`。
3. 从之前列举的4种hash算法中抽取，组成32轮的哈希运算。
4. 根据之前得到的`password`、`salt`计算出最后给我们的`password_hash`。

很明显，我们不可能通过逆向hash算法来完成题目。
我们知道所有的可能的明文，首先考虑能否通过构造彩虹表来完成穷举。但是注意到`generate_salt()`函数中，`salt`和`password`的长度组合超过了128byte的长度，并且被注释了
```
    msize = 128 # f-you hashcat :D
```
so，只能无奈放弃。

那这样的话，只存在一种可能，也即算法可逆。查看`calculate_hash()`函数的具体实现，可以发现如下可疑的代码：
```python
for i in range(len(hash_rounds)):
    interim_salt = xor(interim_salt, hash_rounds[-1-i](interim_hash))
    interim_hash = xor(interim_hash, hash_rounds[i](interim_salt))
final_hash = interim_salt + interim_hash
```
重新梳理一下我们知道的信息：
1. hash_rounds中保存了32轮，即每轮要使用的hash函数句柄。
2. final_hash是最后给我们的hash结果。
3. hash_rounds中的内容也会在生成之后打印给我们。
4. 我们希望得到`interim_salt`和`interim_hash`在第一轮的值。
5. `interim_salt`和`interim_hash`的长度均为64byte。

仔细观察一下`interim_salt`和`interim_hash`的计算方法，可以发现它是可逆的。

$$
interim\_hash_1 = interim\_hash_2 \oplus hash\_rounds[i](interim\_salt_3)
$$

这行代码里，我们已知 $interim\_hash_1$ 和 $interim\_salt_3$，由此可以推出$interim\_hash_2$的值，而$interim\_hash_2$则是上一轮的`interim_hash`。
以此方法逆推32次，则可以得到最初的`password`和`salt`。

具体的解密脚本为：
```python
import os
import hashlib
import socket
import threading
import socketserver
import struct
import time
import threading
# import pyscrypt
from base64 import b64encode, b64decode
from pwn import *
def md5(bytestring):
    return hashlib.md5(bytestring).digest()
def sha(bytestring):
    return hashlib.sha1(bytestring).digest()
def blake(bytestring):
    return hashlib.blake2b(bytestring).digest()
def scrypt(bytestring):
    l = int(len(bytestring) / 2)
    salt = bytestring[:l]
    p = bytestring[l:]
    return hashlib.scrypt(p, salt=salt, n=2**16, r=8, p=1, maxmem=67111936)
    # return pyscrypt.hash(p, salt, 2**16, 8, 1, dkLen=64)
def xor(s1, s2):
    return b''.join([bytes([s1[i] ^ s2[i % len(s2)]]) for i in range(len(s1))])
def main():
    # io = socket.socket(family=socket.AF_INET)
    # io.connect(('47.88.216.38', 20013))
    io = remote('47.88.216.38', 20013)
    print(io.recv(1000))
    ans_array = bytearray()
    while True:
        buf = io.recv(1)
        if buf:
            ans_array.extend(buf)
        if buf == b'!':
            break

    password_hash_base64 = ans_array[ans_array.find(b"b'") + 2: ans_array.find(b"'\n")]
    password_hash = b64decode(password_hash_base64)
    print('password:', password_hash)
    method_bytes = ans_array[
        ans_array.find(b'used:\n') + 6 : ans_array.find(b'\nYour')
    ]
    methods = method_bytes.split(b'\n')
    methods = [bytes(x.strip(b'- ')).decode() for x in methods]
    print(methods)
    in_salt = password_hash[:64]
    in_hash = password_hash[64:]
    for pos, neg in zip(methods, methods[::-1]):
        '''
            interim_salt = xor(interim_salt, hash_rounds[-1-i](interim_hash))
            interim_hash = xor(interim_hash, hash_rounds[i](interim_salt))
        '''
        in_hash = xor(in_hash, eval("{}(in_salt)".format(neg)))
        in_salt = xor(in_salt, eval("{}(in_hash)".format(pos)))
    print(in_hash, in_salt)
    print(in_hash[-20:])
    io.interactive()
main()

```

#### 原hash算法
```python

import os
import hashlib
import socket
import threading
import socketserver
import struct
import time

# import pyscrypt

from base64 import b64encode

def md5(bytestring):
    return hashlib.md5(bytestring).digest()

def sha(bytestring):
    return hashlib.sha1(bytestring).digest()

def blake(bytestring):
    return hashlib.blake2b(bytestring).digest()

def scrypt(bytestring):
    l = int(len(bytestring) / 2)
    salt = bytestring[:l]
    p = bytestring[l:]
    return hashlib.scrypt(p, salt=salt, n=2**16, r=8, p=1, maxmem=67111936)
    # return pyscrypt.hash(p, salt, 2**16, 8, 1)

def xor(s1, s2):
    return b''.join([bytes([s1[i] ^ s2[i % len(s2)]]) for i in range(len(s1))])

class HashHandler(socketserver.BaseRequestHandler):

    welcome_message = """
Welcome, young wanna-be Cracker, to the Hashinator.

To prove your worthiness, you must display the power of your cracking skills.

The test is easy:
1. We send you a password from the rockyou list, hashed using multiple randomly chosen algorithms.
2. You crack the hash and send back the original password.

As you already know the dictionary and won't need any fancy password rules, {} seconds should be plenty, right?

Please wait while we generate your hash...
    """

    hashes = [md5, sha, blake, scrypt]
    timeout = 10
    total_rounds = 32

    def handle(self):
        self.request.sendall(self.welcome_message.format(self.timeout).encode())

        password = self.generate_password()     # from rock_you.txt
        salt = self.generate_salt(password)     # 与password的长度有关
        hash_rounds = self.generate_rounds()    # 生成进行hash算法的顺序
        password_hash = self.calculate_hash(salt + password, hash_rounds)
        self.generate_delay()

        self.request.sendall("Challenge password hash: {}\n".format(b64encode(password_hash)).encode())
        self.request.sendall("Rounds used:\n".encode())
        test_rounds = []
        for r in hash_rounds:
            test_rounds.append(r)

        for r in hash_rounds:
            self.request.sendall("- {}\n".format(r.__name__).encode())
        self.request.sendall("Your time starts now!\n".encode())
        self.request.settimeout(self.timeout)
        try:
            response = self.request.recv(1024)
            if response.strip() == password:
                self.request.sendall("Congratulations! You are a true cracking master!\n".encode())
                self.request.sendall("Welcome to the club: {}\n".format(flag).encode())
                return
        except socket.timeout:
            pass
        self.request.sendall("Your cracking skills are bad, and you should feel bad!".encode())


    def generate_password(self):
        rand = struct.unpack("I", os.urandom(4))[0]
        lines = 14344391 # size of rockyou
        line = rand % lines
        password = ""
        f = open('rockyou.txt', 'rb')
        for i in range(line):
            password = f.readline()
        return password.strip()

    def generate_salt(self, p):
        msize = 128 # f-you hashcat :D
        salt_size = msize - len(p)
        return os.urandom(salt_size)

    def generate_rounds(self):
        rand = struct.unpack("Q", os.urandom(8))[0]
        rounds = []
        for i in range(self.total_rounds):
            rounds.append(self.hashes[rand % len(self.hashes)])
            rand = rand >> 2
        return rounds

    def calculate_hash(self, payload, hash_rounds):
        interim_salt = payload[:64]
        interim_hash = payload[64:]
        for i in range(len(hash_rounds)):
            interim_salt = xor(interim_salt, hash_rounds[-1-i](interim_hash))
            interim_hash = xor(interim_hash, hash_rounds[i](interim_salt))
            '''
            interim_hash = xor(
                interim_hash,
                hash_rounds[i](
                    xor(interim_salt, hash_rounds[-1-i](interim_hash))
                )
            )
            '''
        final_hash = interim_salt + interim_hash
        return final_hash

    def generate_delay(self):
        rand = struct.unpack("I", os.urandom(4))[0]
        time.sleep(rand / 1000000000.0)



class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

PORT = 1337
HOST = '0.0.0.0'
flag = ""

with open("flag.txt") as f:
    flag = f.read()

def main():
    server = ThreadedTCPServer((HOST, PORT), HashHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    server_thread.join()

if __name__ == "__main__":
    main()


```
