# 靜態分析綜合題目

## 2017 ISCC Crackone

利用 jadx 進行反編譯，可以得到程序的基本邏輯如下

-   對用戶輸入的內容進行 base64 編碼，然後在指定長度位置處插入`\r\n` ，這個似乎並沒有什麼亂用。
-   之後程序將編碼後的內容傳遞給 so 中的 check 函數。這個函數的邏輯如下

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

不難看出，程序就是直接將 base64 之後的字符串的兩半分別進行適當的操作，這裏我們很容易寫出 python 對應的恢復代碼，如下

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

對應的結果如下

```shell
➜  2017ISCC python exp.py
flag{ISCCJAVANDKYXX}
```

## 2017 NJCTF easycrack

通過簡單逆向，可以發現程序的基本邏輯如下

1.  監控界面文本框，如果文本框內容改變則調用 native `parseText` 函數。
2.   `parseText` 的主要功能如下
    1.  首先調用 java 層的函數 messageMe 獲取一個字符串 mestr。這個函數的邏輯基本是
        1.  依次將 packagename 的最後一個 `.` 後面的字符串的每一個與 51進行異或，將結果拼接起來。
    2.  然後以 mestr 長度爲週期，將兩者進行異或，核心邏輯 `str[i + j] = mestr[j] ^ iinput[i + j];`
    3.  繼而下面以 `I_am_the_key` 爲密鑰，使用 RC4 加密對該部分進行加密，然後將結果與最後的 `compare` 比較。這裏猜測的依據如下
        1.  在 init 函數中有 256 這個關鍵字，而且基本就是 RC4 密鑰的初始化過程。
        2.  crypt 函數顯然就是一個 RC4 加密函數，明顯就是 RC4 的加密邏輯。

解密腳本如下

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

結果如下

```shell
➜  2017NJCTF-easycrack python exp.py 
It_s_a_easyCrack_for_beginners
➜  2017NJCTF-easycrack 
```

## 2018 強網杯 picture lock

簡單分析之後發現這是一個圖片加密程序：java 層爲 native 層傳入 image/ 下的第一個文件名，以及希望加密後的圖片文件名，包括對應的 apk 的簽名的 md5。

下面我們就可以分析 native 層代碼，由於程序很明顯說是一個加密程序，我們可以使用IDA 的 findcrypto 插件來進行識別，結果卻是發現了 S 盒，而且基本上就是符合 AES 的加密流程的，所以可以基本確定程序的主體是一個 AES 加密，經過細緻分析可以發現 native 層程序的基本流程如下

1. 將傳入的簽名的 md5 字符串分爲兩半，生成兩組密鑰。
2. 每次讀入md5sig[i%32]大小的內容
3. 根據讀入的大小決定使用哪一組密鑰
   1. 奇數使用第二組密鑰
   2. 偶數使用第一組密鑰
4. 如果讀入的大小不夠 16 的話，就將後面填充爲不夠的大小（比如大小爲12時，填充 4 個0x4）
5. 這時修改後的內容必然夠16個字節，對前16個字節進行 AES 加密。對於後面的字節，將其與 md5sig[i%32]依次進行異或。

既然知道加密算法後，那就很容易逆了，我們首先可以獲取簽名的 md5，如下

```shell
➜  picturelock keytool -list -printcert -jarfile picturelock.apk
簽名者 #1:

簽名:

所有者: CN=a, OU=b, O=c, L=d, ST=e, C=ff
發佈者: CN=a, OU=b, O=c, L=d, ST=e, C=ff
序列號: 5f4e6be1
有效期爲 Fri Sep 09 14:32:36 CST 2016 至 Tue Sep 03 14:32:36 CST 2041
證書指紋:
	 MD5:  F8:C4:90:56:E4:CC:F9:A1:1E:09:0E:AF:47:1F:41:8D
	 SHA1: 48:E7:04:5E:E6:0D:9D:8A:25:7C:52:75:E3:65:06:09:A5:CC:A1:3E
	 SHA256: BA:12:C1:3F:D6:0E:0D:EF:17:AE:3A:EE:4E:6A:81:67:82:D0:36:7F:F0:2E:37:CC:AD:5D:6E:86:87:0C:8E:38
簽名算法名稱: SHA256withRSA
主體公共密鑰算法: 2048 位 RSA 密鑰
版本: 3

擴展:

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

繼而，我們可以直接使用已有的 AES 庫來進行解密

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

最後可以得到一個圖片解密後的結果，其中就包含 flag 了。
