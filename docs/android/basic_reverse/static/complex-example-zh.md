[EN](./complex-example.md) | [ZH](./complex-example-zh.md)
# 静态分析综合题目

## 2017 ISCC Crackone

利用 jadx 进行反编译，可以得到程序的基本逻辑如下

-   对用户输入的内容进行 base64 编码，然后在指定长度位置处插入`\r\n` ，这个似乎并没有什么乱用。
-   之后程序将编码后的内容传递给 so 中的 check 函数。这个函数的逻辑如下

```c
  env = a1;
  len = plen;
  str = pstr;
  v7 = malloc(plen);
  ((*env)->GetByteArrayRegion)(env, str, 0, len, v7);
  v8 = malloc(len + 1);
  memset(v8, 0, len + 1);
  memcpy(v8, v7, len);
  v9 = 0;
  for ( i = 0; ; ++i )
  {
    --v9;
    if ( i >= len / 2 )
      break;
    v11 = v8[i] - 5;
    v8[i] = v8[len + v9];
    v8[len + v9] = v11;
  }
  v8[len] = 0;
  v12 = strcmp(v8, "=0HWYl1SE5UQWFfN?I+PEo.UcshU");
  free(v8);
  free(v7);
  return v12 <= 0;
```

不难看出，程序就是直接将 base64 之后的字符串的两半分别进行适当的操作，这里我们很容易写出 python 对应的恢复代码，如下

```python
import base64


def solve():
    ans = '=0HWYl1SE5UQWFfN?I+PEo.UcshU'
    length = len(ans)
    flag = [0] * length

    beg = 0
    end = length
    while beg < length / 2:
        end -= 1
        flag[beg] = chr(ord(ans[end]) + 5)
        flag[end] = ans[beg]
        beg += 1
    flag = ''.join(flag)
    print base64.b64decode(flag)
if __name__ == "__main__":
    solve()
```

对应的结果如下

```shell
➜  2017ISCC python exp.py
flag{ISCCJAVANDKYXX}
```

## 2017 NJCTF easycrack

通过简单逆向，可以发现程序的基本逻辑如下

1.  监控界面文本框，如果文本框内容改变则调用 native `parseText` 函数。
2.   `parseText` 的主要功能如下
    1.  首先调用 java 层的函数 messageMe 获取一个字符串 mestr。这个函数的逻辑基本是
        1.  依次将 packagename 的最后一个 `.` 后面的字符串的每一个与 51进行异或，将结果拼接起来。
    2.  然后以 mestr 长度为周期，将两者进行异或，核心逻辑 `str[i + j] = mestr[j] ^ iinput[i + j];`
    3.  继而下面以 `I_am_the_key` 为密钥，使用 RC4 加密对该部分进行加密，然后将结果与最后的 `compare` 比较。这里猜测的依据如下
        1.  在 init 函数中有 256 这个关键字，而且基本就是 RC4 密钥的初始化过程。
        2.  crypt 函数显然就是一个 RC4 加密函数，明显就是 RC4 的加密逻辑。

解密脚本如下

```python
from Crypto.Cipher import ARC4

def messageme():
    name = 'easycrack'
    init = 51
    ans = ""
    for c in name:
        init = ord(c) ^ init
        ans += chr(init)
    return ans

def decrypt(cipher,key):
    plain =""
    for i in range(0,len(cipher),len(key)):
        tmp = cipher[i:i+len(key)]
        plain +=''.join(chr(ord(tmp[i])^ord(key[i])) for i in range(len(tmp)))
    return plain

def main():
    rc4 = ARC4.new('I_am_the_key')
    cipher = 'C8E4EF0E4DCCA683088134F8635E970EEAD9E277F314869F7EF5198A2AA4'
    cipher = ''.join(chr(int(cipher[i:i+2], 16)) for i in range(0, len(cipher), 2))
    middleplain = rc4.decrypt(cipher)
    mestr = messageme()
    print decrypt(middleplain,mestr)


if __name__ == '__main__':
    main()
```

结果如下

```shell
➜  2017NJCTF-easycrack python exp.py 
It_s_a_easyCrack_for_beginners
➜  2017NJCTF-easycrack 
```

## 2018 强网杯 picture lock

简单分析之后发现这是一个图片加密程序：java 层为 native 层传入 image/ 下的第一个文件名，以及希望加密后的图片文件名，包括对应的 apk 的签名的 md5。

下面我们就可以分析 native 层代码，由于程序很明显说是一个加密程序，我们可以使用IDA 的 findcrypto 插件来进行识别，结果却是发现了 S 盒，而且基本上就是符合 AES 的加密流程的，所以可以基本确定程序的主体是一个 AES 加密，经过细致分析可以发现 native 层程序的基本流程如下

1. 将传入的签名的 md5 字符串分为两半，生成两组密钥。
2. 每次读入md5sig[i%32]大小的内容
3. 根据读入的大小决定使用哪一组密钥
   1. 奇数使用第二组密钥
   2. 偶数使用第一组密钥
4. 如果读入的大小不够 16 的话，就将后面填充为不够的大小（比如大小为12时，填充 4 个0x4）
5. 这时修改后的内容必然够16个字节，对前16个字节进行 AES 加密。对于后面的字节，将其与 md5sig[i%32]依次进行异或。

既然知道加密算法后，那就很容易逆了，我们首先可以获取签名的 md5，如下

```shell
➜  picturelock keytool -list -printcert -jarfile picturelock.apk
签名者 #1:

签名:

所有者: CN=a, OU=b, O=c, L=d, ST=e, C=ff
发布者: CN=a, OU=b, O=c, L=d, ST=e, C=ff
序列号: 5f4e6be1
有效期为 Fri Sep 09 14:32:36 CST 2016 至 Tue Sep 03 14:32:36 CST 2041
证书指纹:
	 MD5:  F8:C4:90:56:E4:CC:F9:A1:1E:09:0E:AF:47:1F:41:8D
	 SHA1: 48:E7:04:5E:E6:0D:9D:8A:25:7C:52:75:E3:65:06:09:A5:CC:A1:3E
	 SHA256: BA:12:C1:3F:D6:0E:0D:EF:17:AE:3A:EE:4E:6A:81:67:82:D0:36:7F:F0:2E:37:CC:AD:5D:6E:86:87:0C:8E:38
签名算法名称: SHA256withRSA
主体公共密钥算法: 2048 位 RSA 密钥
版本: 3

扩展:

#1: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: 71 A3 2A FB D3 F4 A9 A9   2A 74 3F 29 8E 67 8A EA  q.*.....*t?).g..
0010: 3B DD 30 E3                                        ;.0.
]
]
➜  picturelock md5value=F8:C4:90:56:E4:CC:F9:A1:1E:09:0E:AF:47:1F:41:8D
➜  picturelock echo $md5value | sed 's/://g' | tr '[:upper:]' '[:lower:]'
f8c49056e4ccf9a11e090eaf471f418d
```

继而，我们可以直接使用已有的 AES 库来进行解密

```python
#!/usr/bin/env python

import itertools

sig = 'f8c49056e4ccf9a11e090eaf471f418d'

from Crypto.Cipher import AES

def decode_sig(payload):
    ans = ""
    for i in range(len(payload)):
        ans +=chr(ord(payload[i]) ^ ord(sig[(16+i)%32]))
    return ans

def dec_aes():
	data = open('flag.jpg.lock', 'rb').read()
	jpg_data = ''
	f = open('flag.jpg', 'wb')
	idx = 0
	i = 0
	cipher1 = AES.new(sig[:0x10])
	cipher2 = AES.new(sig[0x10:])
	while idx < len(data):
		read_len = ord(sig[i % 32])
		payload = data[idx:idx+read_len]
		#print('[+] Read %d bytes' % read_len)
		print('[+] Totally %d / %d bytes, sig index : %d' % (idx, len(data), i))

		if read_len % 2 == 0:
			f.write(cipher1.decrypt(payload[:0x10]))
		else:
			f.write(cipher2.decrypt(payload[:0x10]))
		f.write(decode_sig(payload[16:]))
		f.flush()
		idx += read_len
		i += 1
	print('[+] Decoding done ...')
	f.close()

dec_aes()
```

最后可以得到一个图片解密后的结果，其中就包含 flag 了。
