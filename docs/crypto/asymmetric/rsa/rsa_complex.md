## 2016 ASIS Find the flag

这里我们以 ASIS 2016 线上赛中 Find the flag 为例进行介绍。

文件解压出来，有一个密文，一个公钥，一个 py 脚本。看一下公钥。

```bash
➜  RSA openssl rsa -pubin -in pubkey.pem -text -modulus
Public-Key: (256 bit)
Modulus:
    00:d8:e2:4c:12:b7:b9:9e:fe:0a:9b:c0:4a:6a:3d:
    f5:8a:2a:94:42:69:b4:92:b7:37:6d:f1:29:02:3f:
    20:61:b9
Exponent: 12405943493775545863 (0xac2ac3e0ca0f5607)
Modulus=D8E24C12B7B99EFE0A9BC04A6A3DF58A2A944269B492B7376DF129023F2061B9
```

这么小的一个 $N$，先分解一下。

```
p = 311155972145869391293781528370734636009
q = 315274063651866931016337573625089033553
```

再看给的 py 脚本。

```python
#!/usr/bin/python
import gmpy
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

flag = open('flag', 'r').read() * 30

def ext_rsa_encrypt(p, q, e, msg):
    m = bytes_to_long(msg)
    while True:
        n = p * q
        try:
            phi = (p - 1)*(q - 1)
            d = gmpy.invert(e, phi)
            pubkey = RSA.construct((long(n), long(e)))
            key = PKCS1_v1_5.new(pubkey)
            enc = key.encrypt(msg).encode('base64')
            return enc
        except:
            p = gmpy.next_prime(p**2 + q**2)
            q = gmpy.next_prime(2*p*q)
            e = gmpy.next_prime(e**2)

p = getPrime(128)
q = getPrime(128)
n = p*q
e = getPrime(64)
pubkey = RSA.construct((long(n), long(e)))
f = open('pubkey.pem', 'w')
f.write(pubkey.exportKey())
g = open('flag.enc', 'w')
g.write(ext_rsa_encrypt(p, q, e, flag))
```

逻辑很简单，读取 flag，重复 30 遍为密文。随机取 $p$ 和 $q$，生成一个公钥，写入 `pubkey.pem`，再用脚本中的 `ext_rsa_encrypt` 函数进行加密，最后将密文写入 `flag.enc`。

尝试一下解密，提示密文过长，再看加密函数，原来当加密失败时，函数会跳到异常处理，以一定算法重新取更大的 $p$ 和 $q$，直到加密成功。

那么我们只要也写一个相应的解密函数即可。

```python
#!/usr/bin/python
import gmpy
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

def ext_rsa_decrypt(p, q, e, msg):
    m = bytes_to_long(msg)
    while True:
        n = p * q
        try:
            phi = (p - 1)*(q - 1)
            d = gmpy.invert(e, phi)
            privatekey = RSA.construct((long(n), long(e), long(d), long(p), long(q)))
            key = PKCS1_v1_5.new(privatekey)
            de_error = ''
            enc = key.decrypt(msg.decode('base64'), de_error)
            return enc
        except Exception as error:
            print error
            p = gmpy.next_prime(p**2 + q**2)
            q = gmpy.next_prime(2*p*q)
            e = gmpy.next_prime(e**2)

p = 311155972145869391293781528370734636009
q = 315274063651866931016337573625089033553
n = p*q
e = 12405943493775545863 
# pubkey = RSA.construct((long(n), long(e)))
# f = open('pubkey.pem', 'w')
# f.write(pubkey.exportKey())
g = open('flag.enc', 'r')
msg = g.read()
flag = ext_rsa_decrypt(p, q, e, msg)
print flag
```

拿到 flag

```
ASIS{F4ct0R__N_by_it3rat!ng!}
```

## SCTF RSA1

这里我们以 SCTF RSA1 为例进行介绍，首先解压压缩包后，得到如下文件

```shell
➜  level0 git:(master) ✗ ls -al
总用量 4
drwxrwxrwx 1 root root    0 7月  30 16:36 .
drwxrwxrwx 1 root root    0 7月  30 16:34 ..
-rwxrwxrwx 1 root root  349 5月   2  2016 level1.passwd.enc
-rwxrwxrwx 1 root root 2337 5月   6  2016 level1.zip
-rwxrwxrwx 1 root root  451 5月   2  2016 public.key
```

尝试解压缩了一下 level1.zip 现需要密码。然后根据 level1.passwd.enc 可知，应该是我们需要解密这个文件才能得到对应的密码。查看公钥

```shell
➜  level0 git:(master) ✗ openssl rsa -pubin -in public.key -text -modulus 
Public-Key: (2048 bit)
Modulus:
    00:94:a0:3e:6e:0e:dc:f2:74:10:52:ef:1e:ea:a8:
    89:d6:f9:8d:01:11:51:db:5e:90:92:48:fd:39:0c:
    70:87:24:d8:98:3c:f3:33:1c:ba:c5:61:c2:ce:2c:
    5a:f1:5e:65:b2:b2:46:91:56:b6:19:d5:d3:b2:a6:
    bb:a3:7d:56:93:99:4d:7e:4c:2f:aa:60:7b:3e:c8:
    fc:90:b2:00:62:4b:53:18:5b:a2:30:10:60:a8:21:
    ab:61:57:d7:e7:cc:67:1b:4d:cd:66:4c:7d:f1:1a:
    2a:1d:5e:50:80:c1:5e:45:12:3a:ba:4a:53:64:d8:
    72:1f:84:4a:ae:5c:55:02:e8:8e:56:4d:38:70:a5:
    16:36:d3:bc:14:3e:2f:ae:2f:31:58:ba:00:ab:ac:
    c0:c5:ba:44:3c:29:70:56:01:6b:57:f5:d7:52:d7:
    31:56:0b:ab:0a:e6:8d:ad:08:22:a9:1f:cb:6e:49:
    cc:01:4c:12:d2:ab:a3:a5:97:e5:10:49:19:7f:69:
    d9:3b:c5:53:53:71:00:18:60:cc:69:1a:06:64:3b:
    86:94:70:a9:da:82:fc:54:6b:06:23:43:2d:b0:20:
    eb:b6:1b:91:35:5e:53:a6:e5:d8:9a:84:bb:30:46:
    b8:9f:63:bc:70:06:2d:59:d8:62:a5:fd:5c:ab:06:
    68:81
Exponent: 65537 (0x10001)
Modulus=94A03E6E0EDCF2741052EF1EEAA889D6F98D011151DB5E909248FD390C708724D8983CF3331CBAC561C2CE2C5AF15E65B2B2469156B619D5D3B2A6BBA37D5693994D7E4C2FAA607B3EC8FC90B200624B53185BA2301060A821AB6157D7E7CC671B4DCD664C7DF11A2A1D5E5080C15E45123ABA4A5364D8721F844AAE5C5502E88E564D3870A51636D3BC143E2FAE2F3158BA00ABACC0C5BA443C297056016B57F5D752D731560BAB0AE68DAD0822A91FCB6E49CC014C12D2ABA3A597E51049197F69D93BC5535371001860CC691A06643B869470A9DA82FC546B0623432DB020EBB61B91355E53A6E5D89A84BB3046B89F63BC70062D59D862A5FD5CAB066881
writing RSA key
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlKA+bg7c8nQQUu8e6qiJ
1vmNARFR216Qkkj9OQxwhyTYmDzzMxy6xWHCzixa8V5lsrJGkVa2GdXTsqa7o31W
k5lNfkwvqmB7Psj8kLIAYktTGFuiMBBgqCGrYVfX58xnG03NZkx98RoqHV5QgMFe
RRI6ukpTZNhyH4RKrlxVAuiOVk04cKUWNtO8FD4vri8xWLoAq6zAxbpEPClwVgFr
V/XXUtcxVgurCuaNrQgiqR/LbknMAUwS0qujpZflEEkZf2nZO8VTU3EAGGDMaRoG
ZDuGlHCp2oL8VGsGI0MtsCDrthuRNV5TpuXYmoS7MEa4n2O8cAYtWdhipf1cqwZo
gQIDAQAB
-----END PUBLIC KEY-----
```

发现虽然说是 2048 位，但是显然模数没有那么长，尝试分解下，得到

```
p=250527704258269
q=74891071972884336452892671945839935839027130680745292701175368094445819328761543101567760612778187287503041052186054409602799660254304070752542327616415127619185118484301676127655806327719998855075907042722072624352495417865982621374198943186383488123852345021090112675763096388320624127451586578874243946255833495297552979177208715296225146999614483257176865867572412311362252398105201644557511678179053171328641678681062496129308882700731534684329411768904920421185529144505494827908706070460177001921614692189821267467546120600239688527687872217881231173729468019623441005792563703237475678063375349
```

然后就可以构造，并且解密，代码如下

```python
from Crypto.PublicKey import RSA
import gmpy2
from base64 import b64decode
p = 250527704258269
q = 74891071972884336452892671945839935839027130680745292701175368094445819328761543101567760612778187287503041052186054409602799660254304070752542327616415127619185118484301676127655806327719998855075907042722072624352495417865982621374198943186383488123852345021090112675763096388320624127451586578874243946255833495297552979177208715296225146999614483257176865867572412311362252398105201644557511678179053171328641678681062496129308882700731534684329411768904920421185529144505494827908706070460177001921614692189821267467546120600239688527687872217881231173729468019623441005792563703237475678063375349
e = 65537
n = p * q


def getprivatekey(n, e, p, q):
    phin = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phin)
    priviatekey = RSA.construct((long(n), long(e), long(d)))
    with open('private.pem', 'w') as f:
        f.write(priviatekey.exportKey())


def decrypt():
    with open('./level1.passwd.enc') as f:
        cipher = f.read()
    cipher = b64decode(cipher)
    with open('./private.pem') as f:
        key = RSA.importKey(f)
    print key.decrypt(cipher)


#getprivatekey(n, e, p, q)
decrypt()

```

发现不对

```shell
➜  level0 git:(master) ✗ python exp.py
一堆乱码。。

```

这时候就要考虑其他情况了，一般来说现实中实现的 RSA 都不会直接用原生的 RSA，都会加一些填充比如 OAEP，我们这里试试，修改代码

```shell
def decrypt1():
    with open('./level1.passwd.enc') as f:
        cipher = f.read()
    cipher = b64decode(cipher)
    with open('./private.pem') as f:
        key = RSA.importKey(f)
        key = PKCS1_OAEP.new(key)
    print key.decrypt(cipher)

```

果然如此，得到

```shell
➜  level0 git:(master) ✗ python exp.py
FaC5ori1ati0n_aTTA3k_p_tOO_sma11
```

得到解压密码。继续，查看 level1 中的公钥

```shell
➜  level1 git:(master) ✗ openssl rsa -pubin -in public.key -text -modulus
Public-Key: (2048 bit)
Modulus:
    00:c3:26:59:69:e1:ed:74:d2:e0:b4:9a:d5:6a:7c:
    2f:2a:9e:c3:71:ff:13:4b:10:37:c0:6f:56:19:34:
    c5:cb:1f:6d:c0:e3:57:3b:47:c4:76:3e:21:a3:b0:
    11:11:78:d4:ee:4f:e8:99:2b:15:cb:cb:d7:73:e4:
    f9:a6:28:20:fd:db:8c:ea:16:ed:67:c2:48:12:6e:
    4b:01:53:4a:67:cb:22:23:3b:34:2e:af:13:ef:93:
    45:16:2b:00:9f:e0:4b:d1:90:c9:2c:27:9a:34:c3:
    3f:d7:ee:40:f5:82:50:39:aa:8c:e9:c2:7b:f4:36:
    e3:38:9d:04:50:db:a9:b7:3f:4b:2a:d6:8a:2a:5c:
    87:2a:eb:74:35:98:6a:9c:e4:52:cb:93:78:d2:da:
    39:83:f3:0c:d1:65:1e:66:9c:40:56:06:0d:58:fc:
    41:64:5e:06:da:83:d0:3b:06:42:70:da:38:53:e0:
    54:35:53:ce:de:79:4a:bf:f5:3b:e5:53:7f:6c:18:
    12:67:a9:de:37:7d:44:65:5e:68:0a:78:39:3d:bb:
    00:22:35:0e:a3:94:e6:94:15:1a:3d:39:c7:50:0e:
    b1:64:a5:29:a3:69:41:40:69:94:b0:0d:1a:ea:9a:
    12:27:50:ee:1e:3a:19:b7:29:70:b4:6d:1e:9d:61:
    3e:7d
Exponent: 65537 (0x10001)
Modulus=C3265969E1ED74D2E0B49AD56A7C2F2A9EC371FF134B1037C06F561934C5CB1F6DC0E3573B47C4763E21A3B0111178D4EE4FE8992B15CBCBD773E4F9A62820FDDB8CEA16ED67C248126E4B01534A67CB22233B342EAF13EF9345162B009FE04BD190C92C279A34C33FD7EE40F5825039AA8CE9C27BF436E3389D0450DBA9B73F4B2AD68A2A5C872AEB7435986A9CE452CB9378D2DA3983F30CD1651E669C4056060D58FC41645E06DA83D03B064270DA3853E0543553CEDE794ABFF53BE5537F6C181267A9DE377D44655E680A78393DBB0022350EA394E694151A3D39C7500EB164A529A36941406994B00D1AEA9A122750EE1E3A19B72970B46D1E9D613E7D
writing RSA key
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwyZZaeHtdNLgtJrVanwv
Kp7Dcf8TSxA3wG9WGTTFyx9twONXO0fEdj4ho7AREXjU7k/omSsVy8vXc+T5pigg
/duM6hbtZ8JIEm5LAVNKZ8siIzs0Lq8T75NFFisAn+BL0ZDJLCeaNMM/1+5A9YJQ
OaqM6cJ79DbjOJ0EUNuptz9LKtaKKlyHKut0NZhqnORSy5N40to5g/MM0WUeZpxA
VgYNWPxBZF4G2oPQOwZCcNo4U+BUNVPO3nlKv/U75VN/bBgSZ6neN31EZV5oCng5
PbsAIjUOo5TmlBUaPTnHUA6xZKUpo2lBQGmUsA0a6poSJ1DuHjoZtylwtG0enWE+
fQIDAQAB
-----END PUBLIC KEY-----

```

似乎还是不是很大，再次分解，然后试了 factordb 不行，试试 yafu。结果分解出来了。

```shell
P309 = 156956618844706820397012891168512561016172926274406409351605204875848894134762425857160007206769208250966468865321072899370821460169563046304363342283383730448855887559714662438206600780443071125634394511976108979417302078289773847706397371335621757603520669919857006339473738564640521800108990424511408496383

P309 = 156956618844706820397012891168512561016172926274406409351605204875848894134762425857160007206769208250966468865321072899370821460169563046304363342283383730448855887559714662438206600780443071125634394511976108979417302078289773847706397371335621757603520669919857006339473738564640521800108990424511408496259

```

可以发现这两个数非常相近，可能是 factordb 没有实现这类分解。

继而下面的操作类似于 level0。只是这次是直接解密就好，没啥填充，试了填充反而错

得到密码 `fA35ORI11TLoN_Att1Ck_cL0sE_PrI8e_4acTorS`。继续下一步，查看公钥

```shell
➜  level2 git:(master) ✗ openssl rsa -pubin -in public.key -text -modulus
Public-Key: (1025 bit)
Modulus:
    01:ba:0c:c2:45:b4:5c:e5:b5:f5:6c:d5:ca:a5:90:
    c2:8d:12:3d:8a:6d:7f:b6:47:37:fb:7c:1f:5a:85:
    8c:1e:35:13:8b:57:b2:21:4f:f4:b2:42:24:5f:33:
    f7:2c:2c:0d:21:c2:4a:d4:c5:f5:09:94:c2:39:9d:
    73:e5:04:a2:66:1d:9c:4b:99:d5:38:44:ab:13:d9:
    cd:12:a4:d0:16:79:f0:ac:75:f9:a4:ea:a8:7c:32:
    16:9a:17:d7:7d:80:fd:60:29:64:c7:ea:50:30:63:
    76:59:c7:36:5e:98:d2:ea:5b:b3:3a:47:17:08:2d:
    d5:24:7d:4f:a7:a1:f0:d5:73
Exponent:
    01:00:8e:81:dd:a0:e3:19:28:e8:ee:51:11:08:c7:
    50:5f:61:31:05:d2:e2:ff:9b:83:71:e4:29:c2:dd:
    92:70:65:d4:09:6d:58:c3:76:31:07:f1:d4:fc:cf:
    2d:b3:0a:6d:02:7c:56:61:7c:be:7e:0b:7e:d9:22:
    28:66:9e:fb:3d:2f:2c:20:59:3c:21:ef:ff:31:00:
    6a:fb:a7:68:de:4a:0a:4c:1a:a7:09:d5:48:98:c8:
    1f:cf:fb:dd:f7:9c:ae:ae:0b:15:f4:b2:c7:e0:bc:
    ba:31:4f:5e:07:83:ad:0e:7f:b9:82:a4:d2:01:fa:
    68:29:6d:66:7c:cf:57:b9:4b
Modulus=1BA0CC245B45CE5B5F56CD5CAA590C28D123D8A6D7FB64737FB7C1F5A858C1E35138B57B2214FF4B242245F33F72C2C0D21C24AD4C5F50994C2399D73E504A2661D9C4B99D53844AB13D9CD12A4D01679F0AC75F9A4EAA87C32169A17D77D80FD602964C7EA5030637659C7365E98D2EA5BB33A4717082DD5247D4FA7A1F0D573
writing RSA key
-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKBgQG6DMJFtFzltfVs1cqlkMKN
Ej2KbX+2Rzf7fB9ahYweNROLV7IhT/SyQiRfM/csLA0hwkrUxfUJlMI5nXPlBKJm
HZxLmdU4RKsT2c0SpNAWefCsdfmk6qh8MhaaF9d9gP1gKWTH6lAwY3ZZxzZemNLq
W7M6RxcILdUkfU+nofDVcwKBgQEAjoHdoOMZKOjuUREIx1BfYTEF0uL/m4Nx5CnC
3ZJwZdQJbVjDdjEH8dT8zy2zCm0CfFZhfL5+C37ZIihmnvs9LywgWTwh7/8xAGr7
p2jeSgpMGqcJ1UiYyB/P+933nK6uCxX0ssfgvLoxT14Hg60Of7mCpNIB+mgpbWZ8
z1e5Sw==
-----END PUBLIC KEY-----

```

发现私钥 e 和 n 几乎一样大，考虑 d 比较小，使用 Wiener's Attack。得到 d，当然也可以再次验证一遍。

```shell
➜  level2 git:(master) ✗ python RSAwienerHacker.py
Testing Wiener Attack
Hacked!
('hacked_d = ', 29897859398360008828023114464512538800655735360280670512160838259524245332403L)
-------------------------
Hacked!
('hacked_d = ', 29897859398360008828023114464512538800655735360280670512160838259524245332403L)
-------------------------
Hacked!
('hacked_d = ', 29897859398360008828023114464512538800655735360280670512160838259524245332403L)
-------------------------
Hacked!
('hacked_d = ', 29897859398360008828023114464512538800655735360280670512160838259524245332403L)
-------------------------
Hacked!
('hacked_d = ', 29897859398360008828023114464512538800655735360280670512160838259524245332403L)
-------------------------
```

这时我们解密密文，解密代码如下

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
import gmpy2
from base64 import b64decode
d = 29897859398360008828023114464512538800655735360280670512160838259524245332403L
with open('./public.key') as f:
    key = RSA.importKey(f)
    n = key.n
    e = key.e


def getprivatekey(n, e, d):
    priviatekey = RSA.construct((long(n), long(e), long(d)))
    with open('private.pem', 'w') as f:
        f.write(priviatekey.exportKey())


def decrypt():
    with open('./level3.passwd.enc') as f:
        cipher = f.read()
    with open('./private.pem') as f:
        key = RSA.importKey(f)
    print key.decrypt(cipher)


getprivatekey(n, e, d)
decrypt()
```

利用末尾的字符串 `wIe6ER1s_1TtA3k_e_t00_larg3` 解密压缩包，注意去掉 B。至此全部解密结束，得到 flag。
