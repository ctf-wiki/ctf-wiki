# CTR

CTR全称为计数器模式（Counter mode），该模式由 Diffe 和 Hellman 设计。

## 加密

![](./figure/ctr_encryption.png)

## 解密

![](./figure/ctr_decryption.png)

## 特点

| 特性                          | 描述     |
| ----------------------------- | -------- |
| 加密可并行化 (Encryption parallelizable) | 是 (Yes) |
| 解密可并行化 (Decryption parallelizable) | 是 (Yes) |
| 随机读取访问 (Random read access)   | 是 (Yes) |

CTR 模式比 OFB 模式有一些优势。一个优点是它允许并行加密和解密多个块，因为可以为每个块独立计算密钥流。这可以提高加密和解密过程的性能和效率。

## 2023 某CTF

题面

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util import Counter
from hashlib import sha256
import os
from secret import flag

def padding(msg):
    return msg + os.urandom(16 - len(msg) % 16)

msg = b"where is the flag? Key in my Heart/Counter!!!!"
key = b"I w0nder how????"

assert len(msg) == 46
assert len(key) == 16

enc_key = os.urandom(16)
initial_value = bytes_to_long(enc_key)
hash = sha256(str(initial_value).encode()).hexdigest()

aes = AES.new(enc_key,AES.MODE_ECB)
enc_flag = aes.encrypt(padding(flag))

ctr = Counter.new(AES.block_size * 8, initial_value = initial_value) 
aes = AES.new(key, counter = ctr, mode = AES.MODE_CTR)
enc = aes.encrypt(msg)

print("enc = {}".format(enc[-16:]))
print("enc_flag = {}".format(enc_flag))
print("hash = {}".format(hash))

"""
enc_last16 = b'\xbe\x9bd\xc6\xd4=\x8c\xe4\x95bi\xbc\xe01\x0e\xb8'
enc_flag = b'\xb2\x97\x83\x1dB\x13\x9b\xc2\x97\x9a\xa6+M\x19\xd74\xd2-\xc0\xb6\xba\xe8ZE\x0b:\x14\xed\xec!\xa1\x92\xdfZ\xb0\xbd\xb4M\xb1\x14\xea\xd8\xee\xbf\x83\x16g\xfa'
hash = efb07225b3f1993113e104757210261083c79de50f577b3f0564368ee7b25eeb
"""
```

可以看出: 先用 ECB 模式加密了 `flag`，且这时的 `key1` 是未知的，同时给出将 `key1` 字节转整数后进行 sha256 hash 的结果

将 `key1` 字节转整数设为 CTR 模式中 `Counter` 的计数器初始值，且接下来用此 `Counter` 作为参数对明文， `key2` 进行加密，并给出密文最后16字节，这其中: 明文、`key2`、最后一块的密文(实际上还需处理) 我们都是已知的

这时我们的目标即为根据已知条件来逆推回 `Counter` 初始值

我们来回顾下 CTR 模式加密流程: 

![](./figure/ctr_encryption.png)

想要得到 `Counter`，那就得先得到加密器给出的结果，加密时: $明文 \oplus E(Counter) = 密文$，而根据异或性质 $E(Counter)$ 则为 $明文 \oplus 密文$

这时仅剩将 $E(Counter)$ 转为 $Counter$

这里我们不要被 CTR 模式加解密图示所局限思维，实际上只看最后这部分，完全可以将其理解为 ECB 模式的某一个块，那解密即为: $D(E(Counter)) = Counter$

接着我们还要将 $Counter$ 减去其在加密过程中，计数器增加的数值，则为最终的结果

其中还有一些坑点可以看如下 Exploit 中的注释

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util import Counter
from hashlib import sha256
import os
# from secret import flag
flag = b'flag{test}'

def padding(msg):
    return msg + os.urandom(16 - len(msg) % 16)  # 随机值填充

msg = b"where is the flag? Key in my Heart/Counter!!!!"
key = b"I w0nder how????"

assert len(msg) == 46
assert len(key) == 16

enc_key = os.urandom(16)  # 随机key
initial_value = bytes_to_long(enc_key) # key转为整数
hash = sha256(str(initial_value).encode()).hexdigest()  # 字符串(key) 的 sha256

aes = AES.new(enc_key,AES.MODE_ECB) 
enc_flag = aes.encrypt(padding(flag))

                # 16 * 8 = 128,
# {'counter_len': 16, 'prefix': b'', 'suffix': b'', 'initial_value': 1, 'little_endian': False}
ctr = Counter.new(AES.block_size * 8, initial_value = initial_value) 
print(ctr)
aes = AES.new(key, counter = ctr, mode = AES.MODE_CTR)  # key 已知, 推 counter, CTR mode 不需要 padding
enc = aes.encrypt(msg)  # msg 已知


# print("enc = {}".format(len(enc)))  # 46
print("enc = {}".format(enc[-16:]))  # 密文的最后16位, 但并不是最后一个 block
print("enc_flag = {}".format(enc_flag))
print("hash = {}".format(hash))
print('题目数据输出结束' + ' *' * 16)
# Data
enc_last16 = b'\xbe\x9bd\xc6\xd4=\x8c\xe4\x95bi\xbc\xe01\x0e\xb8'
enc_flag = b'\xb2\x97\x83\x1dB\x13\x9b\xc2\x97\x9a\xa6+M\x19\xd74\xd2-\xc0\xb6\xba\xe8ZE\x0b:\x14\xed\xec!\xa1\x92\xdfZ\xb0\xbd\xb4M\xb1\x14\xea\xd8\xee\xbf\x83\x16g\xfa'
hash = 'efb07225b3f1993113e104757210261083c79de50f577b3f0564368ee7b25eeb'

# Solution
# a = msg[32:]  # 从明文index 32 开始
a = msg[16 * (len(msg) // 16):]  # 取最后一个 block
b = enc_last16[16 - (len(enc) % 16):]  # 从密文index 2 开始 | 选最后一个 block
# 加密最后步骤 明文 xor enc_{key}(counter) = 密文
# 解密最后步骤 enc_{key}(counter) xor 密文 = 明文 | enc_{key}(counter) = 密文 xor 明文
enc_Counter1 = bytes(a[i] ^ b[i] for i in range(14))  
for i in range(0xff):
    for j in range(0xff):
        # ECB mode 要求数据长度与块长对齐, 而加密后的数据的最后 2 bytes 我们并不清楚, 所以我们需要尝试所有的可能
        enc_Counter2 = enc_Counter1 + bytes([i]) + bytes([j])
        aes = AES.new(key,AES.MODE_ECB)
        Counter = aes.decrypt(enc_Counter2)  # E_{key}(Counter) = Counter_enc | Counter = D_{key}(Counter_enc)
        initial_value = bytes_to_long(Counter) - (len(msg) // 16)  # 经历两个 block, 最后一个 block 的 Counter - block 数 = 初始值
        if hash == sha256(str(initial_value).encode()).hexdigest():  # type: str
            print(f'found {initial_value = }')
            enc_key = long_to_bytes(initial_value)
            aes = AES.new(enc_key,AES.MODE_ECB)
            flag = aes.decrypt(enc_flag)
            print(flag)
            break
# flag{9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d}
```

## 题目

- 2017 star ctf ssss
- 2017 star ctf ssss2
