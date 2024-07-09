# Hash Attack

常見的Hash函數的攻擊方法主要有

-  暴力攻擊：不依賴於任何算法細節，僅與Hash值長度有關；
  - 生日攻擊法(Birthday Attack)：沒有利用Hash函數的結構和任何代數弱性質，只依賴於消息摘要的長度，即Hash值的長度。
  - 中點交會攻擊法(Meet-In-The-Middle)：是生日攻擊的一種變形，不比較Hash值，而是比較中間變量。這種攻擊主要適用於攻擊具有分組鏈結構的Hash方案。
-  密碼分析：依賴於具體算法的設計缺點。

## 暴力攻擊

 **HashCat 工具** 可以說是目前最好的基於 CPU 和 GPU 破解 Hash 的軟件，相關鏈接如下

[HashCat 官網](http://www.hashcat.net/hashcat/)

[HashCat 簡單使用](http://www.freebuf.com/sectool/112479.html)

## 哈希長度拓展攻擊（hash length extension attacks）
### 介紹

基本定義如下，源自[維基百科](https://zh.wikipedia.org/wiki/%E9%95%BF%E5%BA%A6%E6%89%A9%E5%B1%95%E6%94%BB%E5%87%BB)。

哈希長度擴展攻擊(Hash Length Extension Attacks)是指針對某些允許包含額外信息的加密散列函數的攻擊手段。該攻擊適用於在**消息與密鑰的長度已知**的情形下，所有采取了 H(key ∥ message) 此類構造的散列函數。MD5和SHA-1 等基於 Merkle–Damgård 構造的算法均對此類攻擊顯示出脆弱性。

這類哈希函數有以下特點

- 消息填充方式都比較類似，首先在消息後面添加一個1，然後填充若干個0，直至總長度與 448 同餘，最後在其後附上64位的消息長度（填充前）。
- 每一塊得到的鏈接變量都會被作爲下一次執行hash函數的初始向量IV。在最後一塊的時候，纔會將其對應的鏈接變量轉換爲hash值。

一般攻擊時應滿足如下條件

- 我們已知 key 的長度，如果不知道的話，需要爆破出來
- 我們可以控制 message 的消息。
- 我們已經知道了包含 key 的一個消息的hash值。

這樣我們就可以得到一對(messge,x)滿足x=H(key ∥ message)雖然我們並不清楚key的內容。

### 攻擊原理

這裏不妨假設我們我們知道了 hash(key+s) 的 hash 值，其中 s 是已知的，那麼其本身在計算的時候，必然會進行填充。那麼我們首先可以得到 key+s 擴展後的字符串 now，即

now=key|s|padding

那麼如果我們在 now 的後面再次附加上一部分信息extra，即

key|s|padding|extra

這樣再去計算hash值的時候，

1. 會對 extra 進行填充直到滿足條件。
2. 先計算 now 對應的鏈接變量 IV1，而我們已經知道這部分的 hash 值，並且鏈接變量產生 hash 值的算法是可逆的，所以我們可以得到鏈接變量。
3. 下面會根據得到的鏈接變量 IV1，對 extra 部分進行哈希算法，並返回hash值。

那麼既然我們已經知道了第一部分的 hash 值，並且，我們還知道 extra 的值，那麼我們便可以得到最後的hash值。

而之前我們也說了我們可以控制 message 的值。那麼其實 s，padding，extra 我們都是可以控制的。所以我們自然可以找到對應的(message,x)滿足x=hash(key|message)。

### 例子

似乎大都是web裏面的，，不太懂web，暫時先不給例子了。

### 工具

- [hashpump](https://github.com/bwall/HashPump)

如何使用請參考github上的readme。

## hash算法設計有誤
一些自定義的hash算法可能是可逆的。

### Hashinator
題目的邏輯很簡單，從一個知名的密碼字典"rockyou"挑選出一個`password`，並且使用多種hash算法隨機的哈希32輪。我們需要從最後的hash結果中破解出原始的`password`。

#### 分析
題目採用的hash算法有：`md5`，`sha1`，`blake`，`scrypt`。
關鍵的代碼如下：
```python
    password = self.generate_password()     # from rock_you.txt
    salt = self.generate_salt(password)     # 與password的長度有關
    hash_rounds = self.generate_rounds()    # 生成進行hash算法的順序
    password_hash = self.calculate_hash(salt + password, hash_rounds)
```
1. 程序首先通過從`rockyou.txt`中隨機抽取一個`password`，作爲加密的明文。
2. 然後根據抽取的`password`的長度，生成一個長度爲`128 - len(password)`的`salt`。
3. 從之前列舉的4種hash算法中抽取，組成32輪的哈希運算。
4. 根據之前得到的`password`、`salt`計算出最後給我們的`password_hash`。

很明顯，我們不可能通過逆向hash算法來完成題目。
我們知道所有的可能的明文，首先考慮能否通過構造彩虹表來完成窮舉。但是注意到`generate_salt()`函數中，`salt`和`password`的長度組合超過了128byte的長度，並且被註釋了
```
    msize = 128 # f-you hashcat :D
```
so，只能無奈放棄。

那這樣的話，只存在一種可能，也即算法可逆。查看`calculate_hash()`函數的具體實現，可以發現如下可疑的代碼：
```python
for i in range(len(hash_rounds)):
    interim_salt = xor(interim_salt, hash_rounds[-1-i](interim_hash))
    interim_hash = xor(interim_hash, hash_rounds[i](interim_salt))
final_hash = interim_salt + interim_hash
```
重新梳理一下我們知道的信息：
1. hash_rounds中保存了32輪，即每輪要使用的hash函數句柄。
2. final_hash是最後給我們的hash結果。
3. hash_rounds中的內容也會在生成之後打印給我們。
4. 我們希望得到`interim_salt`和`interim_hash`在第一輪的值。
5. `interim_salt`和`interim_hash`的長度均爲64byte。

仔細觀察一下`interim_salt`和`interim_hash`的計算方法，可以發現它是可逆的。

$$
interim\_hash_1 = interim\_hash_2 \oplus hash\_rounds[i](interim\_salt_3)
$$

這行代碼裏，我們已知 $interim\_hash_1$ 和 $interim\_salt_3$，由此可以推出$interim\_hash_2$的值，而$interim\_hash_2$則是上一輪的`interim_hash`。
以此方法逆推32次，則可以得到最初的`password`和`salt`。

具體的解密腳本爲：
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
        salt = self.generate_salt(password)     # 與password的長度有關
        hash_rounds = self.generate_rounds()    # 生成進行hash算法的順序
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
