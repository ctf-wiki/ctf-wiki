# Padding Oracle Attack

## 介紹

Padding Oracle Attack 攻擊一般需要滿足以下幾個條件

- 加密算法
    - 採用 PKCS5 Padding 的加密算法。 當然，非對稱加密中 OAEP 的填充方式也有可能會受到影響。
    - 分組模式爲 CBC 模式。
- 攻擊者能力
    - 攻擊者可以攔截上述加密算法加密的消息。
    - 攻擊者可以和 padding oracle（即服務器） 進行交互：客戶端向服務器端發送密文，服務器端會以某種返回信息告知客戶端 padding 是否正常。

Padding Oracle Attack 攻擊可以達到的效果如下

- 在不清楚 key 和 IV 的前提下解密任意給定的密文。

## 原理

Padding Oracle Attack 攻擊的基本原理如下

- 對於很長的消息一塊一塊解密。
- 對於每一塊消息，先解密消息的最後一個字節，然後解密倒數第二個字節，依次類推。

這裏我們回顧一下 CBC 的

- 加密

$$
C_i=E_K(P_i \oplus C_{i-1})\\
C_0=IV
$$

- 解密

$$
P_{i}=D_{K}(C_{i})\oplus C_{i-1}\\ C_{0}=IV
$$

我們主要關注於解密，這裏我們並不知道 IV 和 key。這裏我們假設密文塊的長度爲 n 個字節。

假設我們截獲了密文最後兩個密文塊 $F$ 與 $Y$ ，以獲取密文塊 $Y$ 的對應明文的最後一個字節爲例子進行分析。爲了獲取 $Y$ 解密後的內容，我們首先需要僞造一塊密文塊 $F'$ 以便於可以修改 $Y$ 對應解密明文的最後一個字節。這是因爲若我們構造密文 `F'|Y` ，那麼解密 $Y$ 時具體爲 $P'=D_K(Y)\oplus F'$ ，所以修改密文塊 $F'$ 的最後一個字節 $F'_{n}$ 可以修改 Y 對應解密明文 $P'$ 的最後一個字節 $P'_n$ ，進而反推出原先的明文 $P$ 的最後一個字節。下面給出獲取 $P$ 最後一個字節的過程：

1. `i=0`，設置 $F'$ 的每個字節爲**隨機字節**。
2. 設置 $F'_n=i \oplus 0x01$ 。
3. 將 `F'|Y` 發送給服務器，如果服務器端沒有報錯，那有很大概率 $P'$ 的最後一個字節是 0x01。否則，只有 $P'$ 的最後 $P'_n \oplus i \oplus 0x01$ 字節都是 $P'_n \oplus i \oplus 0x01$ 纔不會報錯。**而且，需要注意的是 padding 的字節只能是 1 到 n。** 因此，若想要使得在 F' 隨機地情況下，並且滿足 padding 字節大小的約束情況下還不報錯**概率很小**。所以在服務器端不報錯的情況下，我們可以認爲我們確實獲取了正確的字節。這時可知 $D_k(Y)$ 的最後一個字節 $D_k(Y)_n$ 爲 $P'_n \oplus F'_n = 0x01 \oplus i \oplus 0x01 = i$ ，即可知道原先的明文 $P$ 的最後一個字節 $P_n = D_k(Y)_n \oplus F_n = i \oplus F_n$ 。
4. 在出現錯誤的情況下，`i=i+1`，跳轉到 2.。

當獲取了 $P$ 的最後一個字節後，我們可以繼續獲取 $P$ 的倒數第二個字節，此時需要設置 $F'_n=D_k(Y)_n\oplus 0x02$ ，同時設置 $F_{n-1}=i \oplus 0x02$ 去枚舉 `i`。以此類推，我們可以獲取 Y 所對應的明文 $P$ 的所有字節。

所以，綜上所示，Padding Oracle Attack 其實在一定程度上是一種具有很大概率成功的攻擊方法。

然而，需要注意的是，往往遇到的一些現實問題並不是標準的 Padding Oracle Attack 模式，我們往往需要進行一些變形。

## 2017 HITCON Secret Server

### 分析

程序中採用的加密是 AES CBC，其中採用的 padding 與 PKCS5 類似

```python
def pad(msg):
    pad_length = 16-len(msg)%16
    return msg+chr(pad_length)*pad_length

def unpad(msg):
    return msg[:-ord(msg[-1])]
```

但是，在每次 unpad 時並沒有進行檢測，而是直接進行 unpad。

其中，需要注意的是，每次和用戶交互的函數是

- `send_msg` ，接受用戶的明文，使用固定的 `2jpmLoSsOlQrqyqE` 作爲 IV，進行加密，並將加密結果輸出。
- `recv_msg` ，接受用戶的 IV 和密文，對密文進行解密，並返回。根據返回的結果會有不同的操作

```python
            msg = recv_msg().strip()
            if msg.startswith('exit-here'):
                exit(0)
            elif msg.startswith('get-flag'):
                send_msg(flag)
            elif msg.startswith('get-md5'):
                send_msg(MD5.new(msg[7:]).digest())
            elif msg.startswith('get-time'):
                send_msg(str(time.time()))
            elif msg.startswith('get-sha1'):
                send_msg(SHA.new(msg[8:]).digest())
            elif msg.startswith('get-sha256'):
                send_msg(SHA256.new(msg[10:]).digest())
            elif msg.startswith('get-hmac'):
                send_msg(HMAC.new(msg[8:]).digest())
            else:
                send_msg('command not found')
```

### 主要漏洞

這裏我們再簡單總結一下我們已有的部分

- 加密
  - 加密時的 IV 是固定的而且已知。
  - 'Welcome!!' 加密後的結果。
- 解密
  - 我們可以控制 IV。

首先，既然我們知道 `Welcome!!` 加密後的結果，還可以控制 recv_msg 中的 IV，那麼根據解密過程

$$
P_{i}=D_{K}(C_{i})\oplus C_{i-1}\\ C_{0}=IV
$$

如果我們將 `Welcome!!` 加密後的結果輸入給 recv_msg，那麼直接解密後的結果便是 `（Welcome!!+'\x07'*7) xor iv`，如果我們**恰當的控制解密過程中傳遞的 iv**，那麼我們就可以控制解密後的結果。也就是說我們可以執行**上述所說的任意命令**。從而，我們也就可以知道 `flag` 解密後的結果。

其次，在上面的基礎之上，如果我們在任何密文 C 後面添加自定義的 IV 和 Welcome 加密後的結果，作爲輸入傳遞給 recv_msg，那麼我們便可以控制解密之後的消息的最後一個字節，**那麼由於 unpad 操作，我們便可以控制解密後的消息的長度減小 0 到 255**。

### 利用思路

基本利用思路如下

1. 繞過 proof of work
2. 根據執行任意命令的方式獲取加密後的 flag。
3. 由於 flag 的開頭是 `hitcon{`，一共有7個字節，所以我們任然可以通過控制 iv 來使得解密後的前 7 個字節爲指定字節。這使得我們可以對於解密後的消息執行 `get-md5` 命令。而根據 unpad 操作，我們可以控制解密後的消息恰好在消息的第幾個字節處。所以我們可以開始時將控制解密後的消息爲 `hitcon{x`，即只保留`hitcon{` 後的一個字節。這樣便可以獲得帶一個字節哈希後的加密結果。類似地，我們也可以獲得帶制定個字節哈希後的加密結果。
4. 這樣的話，我們可以在本地逐字節爆破，計算對應 `md5`，然後再次利用任意命令執行的方式，控制解密後的明文爲任意指定命令，如果控制不成功，那說明該字節不對，需要再次爆破；如果正確，那麼就可以直接執行對應的命令。

具體代碼如下

```python
#coding=utf-8
from pwn import *
import base64, time, random, string
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, MD5
#context.log_level = 'debug'
if args['REMOTE']:
    p = remote('52.193.157.19', 9999)
else:
    p = remote('127.0.0.1', 7777)


def strxor(str1, str2):
    return ''.join([chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(str1, str2)])


def pad(msg):
    pad_length = 16 - len(msg) % 16
    return msg + chr(pad_length) * pad_length


def unpad(msg):
    return msg[:-ord(msg[-1])]  # 去掉pad


def flipplain(oldplain, newplain, iv):
    """flip oldplain to new plain, return proper iv"""
    return strxor(strxor(oldplain, newplain), iv)


def bypassproof():
    p.recvuntil('SHA256(XXXX+')
    lastdata = p.recvuntil(')', drop=True)
    p.recvuntil(' == ')
    digest = p.recvuntil('\nGive me XXXX:', drop=True)

    def proof(s):
        return SHA256.new(s + lastdata).hexdigest() == digest

    data = pwnlib.util.iters.mbruteforce(
        proof, string.ascii_letters + string.digits, 4, method='fixed')
    p.sendline(data)
    p.recvuntil('Done!\n')


iv_encrypt = '2jpmLoSsOlQrqyqE'


def getmd5enc(i, cipher_flag, cipher_welcome):
    """return encrypt( md5( flag[7:7+i] ) )"""
    ## keep iv[7:] do not change, so decrypt won't change
    new_iv = flipplain("hitcon{".ljust(16, '\x00'), "get-md5".ljust(
        16, '\x00'), iv_encrypt)
    payload = new_iv + cipher_flag
    ## calculate the proper last byte number
    last_byte_iv = flipplain(
        pad("Welcome!!"),
        "a" * 15 + chr(len(cipher_flag) + 16 + 16 - (7 + i + 1)), iv_encrypt)
    payload += last_byte_iv + cipher_welcome
    p.sendline(base64.b64encode(payload))
    return p.recvuntil("\n", drop=True)


def main():
    bypassproof()

    # result of encrypted Welcome!!
    cipher = p.recvuntil('\n', drop=True)
    cipher_welcome = base64.b64decode(cipher)[16:]
    log.info("cipher welcome is : " + cipher_welcome)

    # execute get-flag
    get_flag_iv = flipplain(pad("Welcome!!"), pad("get-flag"), iv_encrypt)
    payload = base64.b64encode(get_flag_iv + cipher_welcome)
    p.sendline(payload)
    cipher = p.recvuntil('\n', drop=True)
    cipher_flag = base64.b64decode(cipher)[16:]
    flaglen = len(cipher_flag)
    log.info("cipher flag is : " + cipher_flag)

    # get command not found cipher
    p.sendline(base64.b64encode(iv_encrypt + cipher_welcome))
    cipher_notfound = p.recvuntil('\n', drop=True)

    flag = ""
    # brute force for every byte of flag
    for i in range(flaglen - 7):
        md5_indexi = getmd5enc(i, cipher_flag, cipher_welcome)
        md5_indexi = base64.b64decode(md5_indexi)[16:]
        log.info("get encrypt(md5(flag[7:7+i])): " + md5_indexi)
        for guess in range(256):
            # locally compute md5 hash
            guess_md5 = MD5.new(flag + chr(guess)).digest()
            # try to null out the md5 plaintext and execute a command
            payload = flipplain(guess_md5, 'get-time'.ljust(16, '\x01'),
                                iv_encrypt)
            payload += md5_indexi
            p.sendline(base64.b64encode(payload))
            res = p.recvuntil("\n", drop=True)
            # if we receive the block for 'command not found', the hash was wrong
            if res == cipher_notfound:
                print 'Guess {} is wrong.'.format(guess)
            # otherwise we correctly guessed the hash and the command was executed
            else:
                print 'Found!'
                flag += chr(guess)
                print 'Flag so far:', flag
                break


if __name__ == "__main__":
    main()

```

最後結果如下

```Shell
Flag so far: Paddin9_15_ve3y_h4rd__!!}\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10
```

## 2017 HITCON Secret Server Revenge

### 描述

```
The password of zip is the flag of "Secret Server"
```

### 分析

這個程序時接着上面的程序繼續搞的，不過這次進行的簡單的修改

- 加密算法的 iv 未知，不過可以根據 Welcome 加密後的消息推算出來。
- 程序多了一個 56 字節的 token。
- 程序最多能進行 340 操作，因此上述的爆破自然不可行

程序的大概流程如下

1. 經過 proof of work
2. 發送 “Welcome!!” 加密後的消息
3. 在 340 次操作中，需要猜中 token 的值，然後會自動將 flag 輸出。

### 漏洞

當然，在上個題目中存在的漏洞，在這個題目中仍然存在，即

1. 任意執行給定命令
2. 長度截斷

### 利用思路

由於 340 的次數限制，雖然我們仍然可以獲得 `md5(token[:i])` 加密後的值（**這裏需要注意的是這部分加密後恰好是 32 個字節，前 16 個字節是 md5 後加密的值，後面的 16 個字節完全是填充的加密後的字節。**這裏`md5(token[:i])`  特指前16個字節。）。但是，我們不能再次爲了獲得一個字符去爆破 256 次了。

既然不能夠爆破，那麼我們有沒有可能一次獲取一個字節的大小呢？這裏，我們再來梳理一下該程序可能可以泄漏的信息

1. 某些消息的 md5 值加密後的值，這裏我們可以獲取 `md5(token[:i])` 加密後的值。
2. unpad 每次會對解密後的消息進行 unpad，這個字節是根據解密後的消息的最後一個字節來決定的。如果我們可以計算出這個字節的大小，那麼我們就可能可以知道一個字節的值。

這裏我們深入分析一下 unpad 的信息泄漏。如果我們將加密 IV 和 `encrypt(md5(token[:i]))` 放在某個密文 C 的後面，構成 `C|IV|encrypt(md5(token[:i]))`，那麼解密出來的消息的最後一個明文塊就是 `md5(token[:i])`。進而，在 unpad 的時候就是利用 `md5(token[:i])` 的最後一個字節（ 0-255）進行 unpad，之後對 unpad 後的字符串執行指定的命令（比如md5）。那麼，如果我們**事先構造一些消息哈希後加密的樣本**，然後將上述執行後的結果與樣本比較，如果相同，那麼我們基本可以確定 `md5(token[:i]) ` 的**最後一個字節**。然而，如果 `md5(token[:i])` 的最後一個字節小於16，那麼在 unpad 時就會利用一些 md5 中的值，而這部分值，由於對於不同長度的 `token[:i]` 幾乎都不會相同。所以可能需要特殊處理。

我們已經知道了這個問題的關鍵，即生成與 unpad 字節大小對應的加密結果樣本，以便於查表。

具體利用思路如下

1. 繞過 proof of work。
2. 獲取 token 加密後的結果 `token_enc` ，這裏會在 token 前面添加 7 個字節 `"token: "` 。 因此加密後的長度爲 64。
3. 依次獲取 `encrypt(md5(token[:i]))` 的結果，一共是 57 個，包括最後一個 token 的 padding。
4. 構造與 unpad 大小對應的樣本。這裏我們構造密文 `token_enc|padding|IV_indexi|welcome_enc`。由於 `IV_indexi` 是爲了修改最後一個明文塊的最後一個字節，所以該字節處於變化之中。我們若想獲取一些固定字節的哈希值，這部分自然不能添加。因此這裏產生樣本時 unpad 的大小範圍爲 17 ~ 255。如果最後測試時 `md5(token[:i])` 的最後一個字節小於17的話，基本就會出現一些未知的樣本。很自然的一個想法是我們直接獲取 255-17+1個這麼多個樣本，然而，如果這樣做的話，根據上面 340 的次數（255-17+1+57+56>340）限制，我們顯然不能獲取到 token 的所有字節。所以這裏我們需要想辦法複用一些內容，這裏我們選擇複用  `encrypt(md5(token[:i]))`  的結果。那麼我們在補充 padding 時需要確保一方面次數夠用，另一方面可以複用之前的結果。這裏我們設置 unpad 的循環爲 17 到 208，並使得 unpad 大於 208 時恰好 unpad 到我們可以複用的地方。這裏需要注意的是，當 `md5(token[:i])` 的最後一個字節爲 0 時，會將所有解密後的明文 unpad 掉，因此會出現 command not found 的密文。
5. 再次構造密文 `token_enc|padding|IV|encrypt(md5(token[:i])) ` ，那麼，解密時即使用 `md5(token[:i])` 的最後一個字節進行 unpad。如果這個字節不小於17或者爲0，則可以處理。如果這個字節小於17，那麼顯然，最後返回給用戶的 md5 的結果並不在樣本範圍內，那麼我們修改其最後一個字節的最高比特位，使其 unpad 後可以落在樣本範圍內。這樣，我們就可以猜出 `md5(token[:i]) ` 的最後一個字節。
6. 在猜出 `md5(token[:i]) ` 的最後一個字節後，我們可以在本地暴力破解 256 次，找出所有哈希值末尾爲 `md5(token[:i]) ` 的最後一個字節的字符。
7. 但是，在第六步中，對於一個 `md5(token[:i]) `  可能會找出多個備選字符，因爲我們只需要使得其末尾字節是給定字節即可。
8. 那麼，問題來了，如何刪除一些多餘的備選字符串呢？這裏我就選擇了一個小 trick，即在逐字節枚舉時，同時枚舉出 token 的 padding。由於 padding 是 0x01 是固定的，所以我們只需要過濾出所有結尾不是 0x01 的token 即可。

這裏，在測試時，將代碼中 `sleep` 註釋掉了。以便於加快交互速度。利用代碼如下

```python
from pwn import *
import base64, time, random, string
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, MD5
#context.log_level = 'debug'

p = remote('127.0.0.1', 7777)


def strxor(str1, str2):
    return ''.join([chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(str1, str2)])


def pad(msg):
    pad_length = 16 - len(msg) % 16
    return msg + chr(pad_length) * pad_length


def unpad(msg):
    return msg[:-ord(msg[-1])]  # remove pad


def flipplain(oldplain, newplain, iv):
    """flip oldplain to new plain, return proper iv"""
    return strxor(strxor(oldplain, newplain), iv)


def bypassproof():
    p.recvuntil('SHA256(XXXX+')
    lastdata = p.recvuntil(')', drop=True)
    p.recvuntil(' == ')
    digest = p.recvuntil('\nGive me XXXX:', drop=True)

    def proof(s):
        return SHA256.new(s + lastdata).hexdigest() == digest

    data = pwnlib.util.iters.mbruteforce(
        proof, string.ascii_letters + string.digits, 4, method='fixed')
    p.sendline(data)


def sendmsg(iv, cipher):
    payload = iv + cipher
    payload = base64.b64encode(payload)
    p.sendline(payload)


def recvmsg():
    data = p.recvuntil("\n", drop=True)
    data = base64.b64decode(data)
    return data[:16], data[16:]


def getmd5enc(i, cipher_token, cipher_welcome, iv):
    """return encrypt( md5( token[:i+1] ) )"""
    ## keep iv[7:] do not change, so decrypt msg[7:] won't change
    get_md5_iv = flipplain("token: ".ljust(16, '\x00'), "get-md5".ljust(
        16, '\x00'), iv)
    payload = cipher_token
    ## calculate the proper last byte number
    last_byte_iv = flipplain(
        pad("Welcome!!"),
        "a" * 15 + chr(len(cipher_token) + 16 + 16 - (7 + i + 1)), iv)
    payload += last_byte_iv + cipher_welcome
    sendmsg(get_md5_iv, payload)
    return recvmsg()


def get_md5_token_indexi(iv_encrypt, cipher_welcome, cipher_token):
    md5_token_idxi = []
    for i in range(len(cipher_token) - 7):
        log.info("idx i: {}".format(i))
        _, md5_indexi = getmd5enc(i, cipher_token, cipher_welcome, iv_encrypt)
        assert (len(md5_indexi) == 32)
        # remove the last 16 byte for padding
        md5_token_idxi.append(md5_indexi[:16])
    return md5_token_idxi


def doin(unpadcipher, md5map, candidates, flag):
    if unpadcipher in md5map:
        lastbyte = md5map[unpadcipher]
    else:
        lastbyte = 0
    if flag == 0:
        lastbyte ^= 0x80
    newcandidates = []
    for x in candidates:
        for c in range(256):
            if MD5.new(x + chr(c)).digest()[-1] == chr(lastbyte):
                newcandidates.append(x + chr(c))
    candidates = newcandidates
    print candidates
    return candidates


def main():
    bypassproof()

    # result of encrypted Welcome!!
    iv_encrypt, cipher_welcome = recvmsg()
    log.info("cipher welcome is : " + cipher_welcome)

    # execute get-token
    get_token_iv = flipplain(pad("Welcome!!"), pad("get-token"), iv_encrypt)
    sendmsg(get_token_iv, cipher_welcome)
    _, cipher_token = recvmsg()
    token_len = len(cipher_token)
    log.info("cipher token is : " + cipher_token)

    # get command not found cipher
    sendmsg(iv_encrypt, cipher_welcome)
    _, cipher_notfound = recvmsg()

    # get encrypted(token[:i+1]),57 times
    md5_token_idx_list = get_md5_token_indexi(iv_encrypt, cipher_welcome,
                                              cipher_token)
    # get md5map for each unpadsize, 209-17 times
    # when upadsize>208, it will unpad ciphertoken
    # then we can reuse
    md5map = dict()
    for unpadsize in range(17, 209):
        log.info("get unpad size {} cipher".format(unpadsize))
        get_md5_iv = flipplain("token: ".ljust(16, '\x00'), "get-md5".ljust(
            16, '\x00'), iv_encrypt)
        ## padding 16*11 bytes
        padding = 16 * 11 * "a"
        ## calculate the proper last byte number, only change the last byte
        ## set last_byte_iv = iv_encrypted[:15] | proper byte
        last_byte_iv = flipplain(
            pad("Welcome!!"),
            pad("Welcome!!")[:15] + chr(unpadsize), iv_encrypt)
        cipher = cipher_token + padding + last_byte_iv + cipher_welcome
        sendmsg(get_md5_iv, cipher)
        _, unpadcipher = recvmsg()
        md5map[unpadcipher] = unpadsize

    # reuse encrypted(token[:i+1])
    for i in range(209, 256):
        target = md5_token_idx_list[56 - (i - 209)]
        md5map[target] = i

    candidates = [""]
    # get the byte token[i], only 56 byte
    for i in range(token_len - 7):
        log.info("get token[{}]".format(i))
        get_md5_iv = flipplain("token: ".ljust(16, '\x00'), "get-md5".ljust(
            16, '\x00'), iv_encrypt)
        ## padding 16*11 bytes
        padding = 16 * 11 * "a"
        cipher = cipher_token + padding + iv_encrypt + md5_token_idx_list[i]
        sendmsg(get_md5_iv, cipher)
        _, unpadcipher = recvmsg()
        # already in or md5[token[:i]][-1]='\x00'
        if unpadcipher in md5map or unpadcipher == cipher_notfound:
            candidates = doin(unpadcipher, md5map, candidates, 1)
        else:
            log.info("unpad size 1-16")
            # flip most significant bit of last byte to move it in a good range
            cipher = cipher[:-17] + strxor(cipher[-17], '\x80') + cipher[-16:]
            sendmsg(get_md5_iv, cipher)
            _, unpadcipher = recvmsg()
            if unpadcipher in md5map or unpadcipher == cipher_notfound:
                candidates = doin(unpadcipher, md5map, candidates, 0)
            else:
                log.info('oh my god,,,, it must be in...')
                exit()
    print len(candidates)
    # padding 0x01
    candidates = filter(lambda x: x[-1] == chr(0x01), candidates)
    # only 56 bytes
    candidates = [x[:-1] for x in candidates]
    print len(candidates)
    assert (len(candidates[0]) == 56)

    # check-token
    check_token_iv = flipplain(
        pad("Welcome!!"), pad("check-token"), iv_encrypt)
    sendmsg(check_token_iv, cipher_welcome)
    p.recvuntil("Give me the token!\n")
    p.sendline(base64.b64encode(candidates[0]))
    print p.recv()

    p.interactive()


if __name__ == "__main__":
    main()
```

效果如下

```shell
...
79
1
hitcon{uNp@d_M3th0D_i5_am4Z1n9!}
```

## Teaser Dragon CTF 2018 AES-128-TSB

這個題目還是蠻有意思的，題目描述如下

```
Haven't you ever thought that GCM mode is overcomplicated and there must be a simpler way to achieve Authenticated Encryption? Here it is!

Server: aes-128-tsb.hackable.software 1337

server.py
```

附件以及最後的 exp 自行到 ctf-challenge 倉庫下尋找。

題目的基本流程爲

- 不斷接收 a 和 b 兩個字符串，其中 a 爲明文，b 爲密文，注意
  - b 在解密後需要滿足尾部恰好等於 iv。
- 如果 a 和 b 相等，那麼根據
  - a 爲 `gimme_flag` ，輸出加密後的 flag。
  - 否則，輸出一串隨機加密的字符串。
- 否則輸出一串明文的字符串。

此外，我們還可以發現題目中的 unpad 存在問題，可以截斷指定長度。

```python
def unpad(msg):
    if not msg:
        return ''
    return msg[:-ord(msg[-1])]
```

一開始，很直接的思路是 a 和 b 的長度都輸入 0 ，那麼可以直接繞過 `a==b` 檢查，獲取一串隨機密文加密的字符串。然而似乎並沒有什麼作用，我們來分析一下加密的流程

```python
def tsb_encrypt(aes, msg):
    msg = pad(msg)
    iv = get_random_bytes(16)
    prev_pt = iv
    prev_ct = iv
    ct = ''
    for block in split_by(msg, 16) + [iv]:
        ct_block = xor(block, prev_pt)
        ct_block = aes.encrypt(ct_block)
        ct_block = xor(ct_block, prev_ct)
        ct += ct_block
        prev_pt = block
        prev_ct = ct_block
    return iv + ct
```

不妨假設 $P_0=iv,C_0=iv$，則

 $C_i=C_{i-1}\oplus E(P_{i-1} \oplus P_i)$

那麼，假設消息長度爲 16，與我們想要得到的`gimme_flag` padding 後長度類似，則

 $C_1=IV\oplus E( IV \oplus P_1)$

 $C_2=C_1 \oplus E(P_1 \oplus IV)$

可以很容易的發現 $C_2=IV$。

（[盜圖](https://github.com/pberba/ctf-solutions/tree/master/20180929_teaser_dragon/aes_128_tsb)，下面的圖片更加清晰

![](figure/aes-tsb-encryption.png)

反過來想，如果我們向服務器發送 `iv+c+iv`，那麼總能繞過 `tsb_decrypt` 的 mac 檢查

```python
def tsb_decrypt(aes, msg):
    iv, msg = msg[:16], msg[16:]
    prev_pt = iv
    prev_ct = iv
    pt = ''
    for block in split_by(msg, 16):
        pt_block = xor(block, prev_ct)
        pt_block = aes.decrypt(pt_block)
        pt_block = xor(pt_block, prev_pt)
        pt += pt_block
        prev_pt = pt_block
        prev_ct = block
    pt, mac = pt[:-16], pt[-16:]
    if mac != iv:
        raise CryptoError()
    return unpad(pt)
```

那麼此時，服務器解密後的消息則是

$unpad(IV \oplus D(C_1 \oplus IV))$

### 獲取明文最後一個字節

我們可以考慮控制 D 解密的消息爲常數值，比如全零，即`C1=IV`，那麼我們就可以從 0 到 255 枚舉 IV 的最後一個字節，得到 $IV \oplus D(C_1 \oplus IV)$ 的最後一個字節也是 0~255。而只有是 1~15 的時候，`unpad` 操作過後，消息長度不爲 0。因此，我們可以在枚舉時統計究竟哪些數字導致了長度不爲零，並標記爲 1，其餘標記爲 0。

```python
def getlast_byte(iv, block):
    iv_pre = iv[:15]
    iv_last = ord(iv[-1])
    tmp = []
    print('get last byte')
    for i in range(256):
        send_data('')
        iv = iv_pre + chr(i)
        tmpblock = block[:15] + chr(i ^ ord(block[-1]) ^ iv_last)
        payload = iv + tmpblock + iv
        send_data(payload)
        length, data = recv_data()
        if 'Looks' in data:
            tmp.append(1)
        else:
            tmp.append(0)
    last_bytes = []
    for i in range(256):
        if tmp == xor_byte_map[i][0]:
            last_bytes.append(xor_byte_map[i][1])
    print('possible last byte is ' + str(last_bytes))
    return last_bytes
```

此外，我們可以在最初的時候打表獲取最後一個字節所有的可能情況，記錄在 xor_byte_map 中。

```python
"""
every item is a pair [a,b]
a is the xor list
b is the idx which is zero when xored
"""
xor_byte_map = []
for i in range(256):
    a = []
    b = 0
    for j in range(256):
        tmp = i ^ j
        if tmp > 0 and tmp <= 15:
            a.append(1)
        else:
            a.append(0)
        if tmp == 0:
            b = j
    xor_byte_map.append([a, b])
```

通過與這個表進行對比，我們就可以知道最後一個字節可能的情況。

### 解密任意加密塊

在獲取了明文最後一個字節後，我們就可以利用  unpad 的漏洞，從長度 1 枚舉到長度 15 來獲得對應的明文內容。

```python
def dec_block(iv, block):
    last_bytes = getlast_byte(iv, block)

    iv_pre = iv[:15]
    iv_last = ord(iv[-1])
    print('try to get plain')
    plain0 = ''
    for last_byte in last_bytes:
        plain0 = ''
        for i in range(15):
            print 'idx:', i
            tag = False
            for j in range(256):
                send_data(plain0 + chr(j))
                pad_size = 15 - i
                iv = iv_pre + chr(pad_size ^ last_byte)
                tmpblock = block[:15] + chr(
                    pad_size ^ last_byte ^ ord(block[-1]) ^ iv_last
                )
                payload = iv + tmpblock + iv
                send_data(payload)
                length, data = recv_data()
                if 'Looks' not in data:
                    # success
                    plain0 += chr(j)
                    tag = True
                    break
            if not tag:
                break
        # means the last byte is ok
        if plain0 != '':
            break
    plain0 += chr(iv_last ^ last_byte)
    return plain0
```

### 解密出指定明文

這一點比較簡單，我們希望利用這一點來獲取 `gimme_flag` 的密文

```python
    print('get the cipher of flag')
    gemmi_iv1 = xor(pad('gimme_flag'), plain0)
    gemmi_c1 = xor(gemmi_iv1, cipher0)
    payload = gemmi_iv1 + gemmi_c1 + gemmi_iv1
    send_data('gimme_flag')
    send_data(payload)
    flag_len, flag_cipher = recv_data()
```

其中 plain0 和 cipher0 是我們獲取的 AES 加密的明密文對，不包括之前和之後的兩個異或。

### 解密 flag

這一點，其實就是利用解密任意加密塊的功能實現的，如下

```python
    print('the flag cipher is ' + flag_cipher.encode('hex'))
    flag_cipher = split_by(flag_cipher, 16)

    print('decrypt the blocks one by one')
    plain = ''
    for i in range(len(flag_cipher) - 1):
        print('block: ' + str(i))
        if i == 0:
            plain += dec_block(flag_cipher[i], flag_cipher[i + 1])
        else:
            iv = plain[-16:]
            cipher = xor(xor(iv, flag_cipher[i + 1]), flag_cipher[i])
            plain += dec_block(iv, cipher)
            pass
        print('now plain: ' + plain)
    print plain
```

可以思考一下爲什麼第二塊之後的密文操作會有所不同。

完整的代碼參考 ctf-challenge 倉庫。

## 參考資料

- [分組加密模式](https://zh.wikipedia.org/wiki/%E5%88%86%E7%BB%84%E5%AF%86%E7%A0%81%E5%B7%A5%E4%BD%9C%E6%A8%A1%E5%BC%8F)
- https://en.wikipedia.org/wiki/Padding_oracle_attack
- http://netifera.com/research/poet/PaddingOraclesEverywhereEkoparty2010.pdf
- https://ctftime.org/writeup/7975
- https://ctftime.org/writeup/7974
