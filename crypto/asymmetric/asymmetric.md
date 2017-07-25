在非对称密码中，加密者与解密者所使用的秘钥并不一样，典型的有 RSA 加密，椭圆曲线加密。

## RSA

[RSA 加密算法 - 维基百科](https://zh.wikipedia.org/wiki/RSA%E5%8A%A0%E5%AF%86%E6%BC%94%E7%AE%97%E6%B3%95)

RSA 加密算法是一种非对称加密算法。在公开密钥加密和电子商业中 RSA 被广泛使用。RSA 是 1977 年由罗纳德·李维斯特（Ron Rivest）、阿迪·萨莫尔（Adi Shamir）和伦纳德·阿德曼（Leonard Adleman）一起提出的。当时他们三人都在麻省理工学院工作。RSA 就是他们三人姓氏开头字母拼在一起组成的。

对极大整数做因数分解的难度决定了 RSA 算法的可靠性。换言之，对一极大整数做因数分解愈困难，RSA 算法愈可靠。假如有人找到一种快速因数分解的算法的话，那么用 RSA 加密的信息的可靠性就肯定会极度下降。但找到这样的算法的可能性是非常小的。今天只有短的 RSA 钥匙才可能被强力方式解破。到 2016 年为止，世界上还没有任何可靠的攻击 RSA 算法的方式。只要其钥匙的长度足够长，用 RSA 加密的信息实际上是不能被解破的。

### 原理

#### 公钥与私钥的产生

1. 随机选择两个不同大质数 $p$ 和 $q$，计算 $N=p \times q$。
2. 根据欧拉函数，求得 $r=\varphi (N)=\varphi (p)\varphi (q)=(p-1)(q-1)$。
3. 选择一个小于 $r$ 的整数 $e$，使 $e$ 和 $r$ 互质。并求得 $e$ 关于 $r$ 的模反元素，命名为 $d$（求 $d$ 令 $ed\equiv 1 \pmod r$）。
4. 将 $p$ 和 $q$ 的记录销毁。

此时，$(N,e)$ 是公钥，$(N,d)$ 是私钥。

#### 消息加密

首先需要将消息 $m$ 以一个双方约定好的格式转化为一个小于 $N$，且与 $N$ 互质的整数 $n$。如果消息太长，可以将消息分为几段。

然后利用如下公式加密：
$$
n^{e}\equiv c\pmod N
$$

#### 消息解密

利用密钥 $d$ 进行解密。
$$
c^{d}\equiv n\pmod N
$$

#### 简单练手

- Jarvis OJ - Basic - veryeasyRSA

### 基本工具

#### RSAtool

- 安装

  ```bash
  git clone https://github.com/ius/rsatool.git
  cd rsatool
  python rsatool.py -h
  ```

- 生成私钥

  ```bash
  python rsatool.py -f PEM -o private.pem -p 1234567-q 7654321
  ```

#### RSA Converter

- 根据给定密钥对，生成 pem 文件
- 根据 n，e，d 生成 p，q

#### openssl

更加具体的细节请参考 `openssl --help`。

- 查看公钥文件

  ```bash
  openssl rsa -pubin -in pubkey.pem -text -modulus
  ```

- 解密

  ```bash
  rsautl -decrypt -inkey private.pem -in flag.enc -out flag
  ```

#### 分解大整数

- [factor.db](http://factordb.com/)
- [yafu](https://sourceforge.net/projects/yafu/)

#### python 库

##### gmpy

- Python gmpy 库，`gmpy.root(a, b)`，返回一个元组 `(x, y)`，其中 `x` 为 `a` 开 `b` 次方的值，`y`是判断 `x` 是否为整数的布尔型变量。

##### gmpy2

- Python gmpy2 库，`gmpy2.iroot(a, b)`

##### pycrypto

- 安装

  ```bash
  sudo pip install pycrypto
  ```

- 使用

  ```python
  import gmpy
  from Crypto.Util.number import *
  from Crypto.PublicKey import RSA
  from Crypto.Cipher import PKCS1_v1_5

  msg = 'crypto here'
  p = getPrime(128)
  q = getPrime(128)
  n = p*q
  e = getPrime(64)
  pubkey = RSA.construct((long(n), long(e)))
  privatekey = RSA.construct((long(n), long(e), long(d), long(p), long(q)))
  key = PKCS1_v1_5.new(pubkey)
  enc = key.encrypt(msg).encode('base64')
  key = PKCS1_v1_5.new(privatekey)
  msg = key.decrypt(enc.decode('base64'), e)
  ```

### 攻击

#### 分解 N

##### 攻击条件

在 N 的比特位数小于 512 的时候，可以采用大整数分解的策略获取 p 和 q。

##### 题目

- JarvisOJ - Medium RSA

#### 共模攻击

##### 攻击条件

当两个用户使用相同的模数 $N$、不同的私钥时，即存在共模攻击。

##### 攻击原理

设两个用户的公钥分别为 $e_1$ 和 $e_2$，且两者互质。明文消息为 $m$，密文分别为：
$$
c_1 = m^{e_1}\bmod N \\\\ c_2 = m^{e_2}\bmod N
$$
当攻击者截获 $c_1$ 和 $c_2$ 后，就可以恢复出明文。用扩展欧几里得算法求出 $re_1+se_2=1\bmod n$ 的两个整数 $r$ 和 $s$，由此可得：
$$
\begin{align}
c\_{1}^{r}c\_{2}^{s} &\equiv m^{re_1}m^{se_2}\bmod n\\\\
&\equiv m^{(re_1+se_2)} \bmod n\\\\
&\equiv m\bmod n
\end{align}
$$

##### 范例

题目描述：

```
{6266565720726907265997241358331585417095726146341989755538017122981360742813498401533594757088796536341941659691259323065631249,773}

{6266565720726907265997241358331585417095726146341989755538017122981360742813498401533594757088796536341941659691259323065631249,839}

message1=3453520592723443935451151545245025864232388871721682326408915024349804062041976702364728660682912396903968193981131553111537349

message2=5672818026816293344070119332536629619457163570036305296869053532293105379690793386019065754465292867769521736414170803238309535
```

> 题目来源：XMan 一期夏令营课堂练习 

写一个脚本跑一下：

```python
#coding=utf-8
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
def main():
    n = 6266565720726907265997241358331585417095726146341989755538017122981360742813498401533594757088796536341941659691259323065631249
    c1 = 3453520592723443935451151545245025864232388871721682326408915024349804062041976702364728660682912396903968193981131553111537349
    c2 = 5672818026816293344070119332536629619457163570036305296869053532293105379690793386019065754465292867769521736414170803238309535
    e1 = 773
    e2 = 839
    s = egcd(e1, e2)
    s1 = s[1]
    s2 = s[2]
    # 求模反元素
    if s1<0:
        s1 = - s1
        c1 = modinv(c1, n)
    elif s2<0:
        s2 = - s2
        c2 = modinv(c2, n)
    m = (c1**s1)*(c2**s2)%n
    print m
if __name__ == '__main__':
    main()
```

得到明文的 ASCII 码串，解码即可。

```python
# coding=utf-8
a = '102 108 97 103 123 119 104 101 110 119 101 116 104 105 110 107 105 116 105 115 112 111 115 115 105 98 108 101 125'
b = a.split()

flag = ''
for i in b:
    flag += chr(int(i))

print flag

flag{whenwethinkitispossible}
```

##### 题目

- Jarvis OJ very hard RSA

#### 小公钥指数攻击

##### 攻击条件

e 特别小，比如 e 为 3。

##### 攻击原理

假设用户使用的密钥 $e=3$。考虑到加密关系满足：
$$
c\equiv m^3 \bmod N
$$
则：
$$
\begin{align}
m^3 &= c+k\times N\\\\
m &= \sqrt[3]{c+k\times n}
\end{align}
$$
攻击者可以从小到大枚举 $n$，依次开三次根，直到开出整数为止。

##### 范例

- 题目描述：[附件下载](http://xman.xctf.org.cn/media/task/86113c26-c6b7-43b1-a3ab-a16ff90157ee.zip)

  > 题目来源：XMan 一期夏令营课堂练习

  附件中有一个 `flag.enc` 和 `pubkey.pem`，很明显是密文和公钥了，先用 `openssl` 读一下公钥。

  ```bash
  ➜  RSA小公钥指数攻击 openssl rsa -pubin -in pubkey.pem -text -modulus
  Public-Key: (4096 bit)
  Modulus:
      00:b0:be:e5:e3:e9:e5:a7:e8:d0:0b:49:33:55:c6:
      18:fc:8c:7d:7d:03:b8:2e:40:99:51:c1:82:f3:98:
      de:e3:10:45:80:e7:ba:70:d3:83:ae:53:11:47:56:
      56:e8:a9:64:d3:80:cb:15:7f:48:c9:51:ad:fa:65:
      db:0b:12:2c:a4:0e:42:fa:70:91:89:b7:19:a4:f0:
      d7:46:e2:f6:06:9b:af:11:ce:bd:65:0f:14:b9:3c:
      97:73:52:fd:13:b1:ee:a6:d6:e1:da:77:55:02:ab:
      ff:89:d3:a8:b3:61:5f:d0:db:49:b8:8a:97:6b:c2:
      05:68:48:92:84:e1:81:f6:f1:1e:27:08:91:c8:ef:
      80:01:7b:ad:23:8e:36:30:39:a4:58:47:0f:17:49:
      10:1b:c2:99:49:d3:a4:f4:03:8d:46:39:38:85:15:
      79:c7:52:5a:69:98:4f:15:b5:66:7f:34:20:9b:70:
      eb:26:11:36:94:7f:a1:23:e5:49:df:ff:00:60:18:
      83:af:d9:36:fe:41:1e:00:6e:4e:93:d1:a0:0b:0f:
      ea:54:1b:bf:c8:c5:18:6c:b6:22:05:03:a9:4b:24:
      13:11:0d:64:0c:77:ea:54:ba:32:20:fc:8f:4c:c6:
      ce:77:15:1e:29:b3:e0:65:78:c4:78:bd:1b:eb:e0:
      45:89:ef:9a:19:7f:6f:80:6d:b8:b3:ec:d8:26:ca:
      d2:4f:53:24:cc:de:c6:e8:fe:ad:2c:21:50:06:86:
      02:c8:dc:dc:59:40:2c:ca:c9:42:4b:79:00:48:cc:
      dd:93:27:06:80:95:ef:a0:10:b7:f1:96:c7:4b:a8:
      c3:7b:12:8f:9e:14:11:75:16:33:f7:8b:7b:9e:56:
      f7:1f:77:a1:b4:da:ad:3f:c5:4b:5e:7e:f9:35:d9:
      a7:2f:b1:76:75:97:65:52:2b:4b:bc:02:e3:14:d5:
      c0:6b:64:d5:05:4b:7b:09:6c:60:12:36:e6:cc:f4:
      5b:5e:61:1c:80:5d:33:5d:ba:b0:c3:5d:22:6c:c2:
      08:d8:ce:47:36:ba:39:a0:35:44:26:fa:e0:06:c7:
      fe:52:d5:26:7d:cf:b9:c3:88:4f:51:fd:df:df:4a:
      97:94:bc:fe:0e:15:57:11:37:49:e6:c8:ef:42:1d:
      ba:26:3a:ff:68:73:9c:e0:0e:d8:0f:d0:02:2e:f9:
      2d:34:88:f7:6d:eb:62:bd:ef:7b:ea:60:26:f2:2a:
      1d:25:aa:2a:92:d1:24:41:4a:80:21:fe:0c:17:4b:
      98:03:e6:bb:5f:ad:75:e1:86:a9:46:a1:72:80:77:
      0f:12:43:f4:38:74:46:cc:ce:b2:22:2a:96:5c:c3:
      0b:39:29
  Exponent: 3 (0x3)
  Modulus=B0BEE5E3E9E5A7E8D00B493355C618FC8C7D7D03B82E409951C182F398DEE3104580E7BA70D383AE5311475656E8A964D380CB157F48C951ADFA65DB0B122CA40E42FA709189B719A4F0D746E2F6069BAF11CEBD650F14B93C977352FD13B1EEA6D6E1DA775502ABFF89D3A8B3615FD0DB49B88A976BC20568489284E181F6F11E270891C8EF80017BAD238E363039A458470F1749101BC29949D3A4F4038D463938851579C7525A69984F15B5667F34209B70EB261136947FA123E549DFFF00601883AFD936FE411E006E4E93D1A00B0FEA541BBFC8C5186CB6220503A94B2413110D640C77EA54BA3220FC8F4CC6CE77151E29B3E06578C478BD1BEBE04589EF9A197F6F806DB8B3ECD826CAD24F5324CCDEC6E8FEAD2C2150068602C8DCDC59402CCAC9424B790048CCDD9327068095EFA010B7F196C74BA8C37B128F9E1411751633F78B7B9E56F71F77A1B4DAAD3FC54B5E7EF935D9A72FB176759765522B4BBC02E314D5C06B64D5054B7B096C601236E6CCF45B5E611C805D335DBAB0C35D226CC208D8CE4736BA39A0354426FAE006C7FE52D5267DCFB9C3884F51FDDFDF4A9794BCFE0E1557113749E6C8EF421DBA263AFF68739CE00ED80FD0022EF92D3488F76DEB62BDEF7BEA6026F22A1D25AA2A92D124414A8021FE0C174B9803E6BB5FAD75E186A946A17280770F1243F4387446CCCEB2222A965CC30B3929
  ```

  看到 $e=3$，很明显是小公钥指数攻击了。

  ```python
  # coding=utf-8
  import gmpy
  import string

  e=3
  n=0xB0BEE5E3E9E5A7E8D00B493355C618FC8C7D7D03B82E409951C182F398DEE3104580E7BA70D383AE5311475656E8A964D380CB157F48C951ADFA65DB0B122CA40E42FA709189B719A4F0D746E2F6069BAF11CEBD650F14B93C977352FD13B1EEA6D6E1DA775502ABFF89D3A8B3615FD0DB49B88A976BC20568489284E181F6F11E270891C8EF80017BAD238E363039A458470F1749101BC29949D3A4F4038D463938851579C7525A69984F15B5667F34209B70EB261136947FA123E549DFFF00601883AFD936FE411E006E4E93D1A00B0FEA541BBFC8C5186CB6220503A94B2413110D640C77EA54BA3220FC8F4CC6CE77151E29B3E06578C478BD1BEBE04589EF9A197F6F806DB8B3ECD826CAD24F5324CCDEC6E8FEAD2C2150068602C8DCDC59402CCAC9424B790048CCDD9327068095EFA010B7F196C74BA8C37B128F9E1411751633F78B7B9E56F71F77A1B4DAAD3FC54B5E7EF935D9A72FB176759765522B4BBC02E314D5C06B64D5054B7B096C601236E6CCF45B5E611C805D335DBAB0C35D226CC208D8CE4736BA39A0354426FAE006C7FE52D5267DCFB9C3884F51FDDFDF4A9794BCFE0E1557113749E6C8EF421DBA263AFF68739CE00ED80FD0022EF92D3488F76DEB62BDEF7BEA6026F22A1D25AA2A92D124414A8021FE0C174B9803E6BB5FAD75E186A946A17280770F1243F4387446CCCEB2222A965CC30B3929

  c= """85 c0 de 5f 89 e8 87 20 af d4 85 f9 1d ed 38 e9
   ea ed a3 a6 1d de e7 08 7b bd 29 92 0e e4 0b 6d
   53 56 5e dd 1e 41 80 95 58 6b d4 f3 30 15 72 9d
   43 3a f4 13 c6 60 e4 c0 b1 64 ed 02 5f 91 21 6d
   90 45 78 f7 f2 0c 5f b1 e0 9e 71 99 21 98 d8 e8
   d7 fb d9 17 59 7a ee 45 eb f4 ca 80 12 4c e9 b4
   7e d1 63 f0 b9 d5 71 6a 9d 6e 1f 5b 8a e0 9b 16
   ca e3 0b bd 64 a1 5e 17 cc 39 a9 0f b6 25 36 ad
   94 3c dd a9 a4 aa c5 97 8e 3c 93 54 e4 9b d1 d8
   6f 84 cf 7e df ce e1 69 76 69 f8 d3 01 ab ea 5c
   28 9f 09 bd 65 08 69 6c d0 d2 39 9e 12 06 49 7c
   de 9f 8a 02 4f 91 bf ae 68 2b f0 b0 fe f1 f0 16
   cd 27 58 fd c8 9b 0b 26 34 39 66 72 bb 66 43 e6
   43 7f 51 db 85 ab 30 cb aa 2a 9a f1 f5 50 a5 f8
   e4 e2 bb 12 76 aa a9 c2 65 91 56 f1 8d a0 14 2e
   48 93 ed 2c 93 71 61 f4 63 72 fd 81 bd 1b 9d d7
   fa b2 df 74 d8 ec a1 7a ac ed 31 f7 34 da 34 7b
   af b3 d6 c9 02 f8 ca 43 1c 10 06 22 6b 75 73 01
   b6 2e dc 86 e9 a9 ae e0 fb 42 34 58 25 21 76 ec
   cd 10 b7 16 fd e1 e1 13 64 de 07 34 5d 8e 1a ff
   0c 60 67 3f 88 c1 65 fd 66 6f b9 e2 07 61 99 3d
   7a 06 1a 78 c9 d5 3e c5 c8 b0 21 dc 59 d7 83 ee
   03 78 98 31 bc d5 9a 69 13 ba 92 2a f5 3f ea 3a
   ac 62 a6 8d 9d aa 3d ae 98 bb 9b 54 8d be 58 a8
   c8 ec 7a 27 88 c1 92 8e de 27 0c 21 6f 7c 6b a8
   e2 9c bb 90 61 66 ab 07 f3 dc ac 47 b7 e5 75 e6
   13 85 9f 08 91 0e 26 65 6f d2 ea b4 24 86 f1 01
   a5 6d 41 5a 75 49 99 36 f0 95 35 d8 87 5c 68 21
   bd 4d eb 69 89 b0 11 1b 6c ff 49 e8 be 1d 76 da
   58 67 ac ac 0f 8b db 65 ce af 4c 47 66 3c fd f1
   d4 58 db dd 3f ae 61 81 bb c2 0e b3 e6 a2 50 11
   b8 e9 03 45 37 c0 e5 80 a0 ee 8f 15 53 80 5b e8"""
  c=c.replace(' ','').replace('\n','')
  c='0X'+c
  c=string.atoi(c,16)
  # print c

  k=118700000

  while 1:
    a,b=gmpy.root(c+k*n,3)
    if b>0:
        m=a
        break
    print k
    k += 1

  print m

  flag = str(hex(int(m)))[2:-1].decode('hex')
  print flag
  ```

  拿到 flag

  ```
  Didn't you know RSA padding is really important? Now you see a non-padding message is so dangerous. And you should notice this in future.Fl4g: flag{Sm4ll_3xpon3nt_i5_W3ak}
  ```

##### 题目

- JarvisOJ extreamly hard rsa

#### RSA 衍生算法——Rabin 算法

##### 攻击条件

Rabin 算法的特征在于 $e=2$。

##### 攻击原理

密文：
$$
c = m^2\bmod n
$$
解密：

- 计算出 $m_p$ 和 $m_q$：

$$
\begin{align}
m_p &= \sqrt{c} \bmod p\\\\
m_q &= \sqrt{c} \bmod q
\end{align}
$$

- 用扩展欧几里得计算出 $y_p$ 和 $y_q$：

$$
y_p \cdot p + y_q \cdot q = 1
$$

- 解出四个明文：

$$
\begin{align}
a &= (y_p \cdot p \cdot m_q + y_q \cdot q \cdot m_p) \bmod n\\\\
b &= n - a\\\\
c &= (y_p \cdot p \cdot m_q - y_q \cdot q \cdot m_p) \bmod n\\\\
d &= n - c
\end{align}
$$

注意：如果 $p \equiv q \equiv 3 \pmod 4$，则
$$
\begin{align}
m_p &= c^{\frac{1}{4}(p + 1)} \bmod p\\\\
m_q &= c^{\frac{1}{4}(q + 1)} \bmod q
\end{align}
$$

##### 范例

题目描述：[附件下载](http://xman.xctf.org.cn/media/task/506d3331-94f1-426c-90f6-b853535d8088.zip)

> 题目来源：XMan 一期夏令营课堂练习

读一下公钥。

```bash
➜  Rabin openssl rsa -pubin -in public.pem -text -modulus
Public-Key: (256 bit)
Modulus:
00:c2:63:6a:e5:c3:d8:e4:3f:fb:97:ab:09:02:8f:
1a:ac:6c:0b:f6:cd:3d:70:eb:ca:28:1b:ff:e9:7f:
be:30:dd
Exponent: 2 (0x2)
Modulus=C2636AE5C3D8E43FFB97AB09028F1AAC6C0BF6CD3D70EBCA281BFFE97FBE30DD
writing RSA key
-----BEGIN PUBLIC KEY-----
MDowDQYJKoZIhvcNAQEBBQADKQAwJgIhAMJjauXD2OQ/+5erCQKPGqxsC/bNPXDr
yigb/+l/vjDdAgEC
-----END PUBLIC KEY-----
```

$e=2$，考虑 Rabin 算法。

```python
import string
import gmpy
n=0xC2636AE5C3D8E43FFB97AB09028F1AAC6C0BF6CD3D70EBCA281BFFE97FBE30DD
c=0x1c746c54a516da3e055f3a442b42508df8ad58ee40e08b0b1090310401de5d39
c= int(c)
p=275127860351348928173285174381581152299
pp = (p+1)/4
q=319576316814478949870590164193048041239
qq = (q+1)/4
n=int(n)
print n
print qq
print pp


def quickpow(a,b,c):
   ans =1
   while (b>0):
       if (b%2==1):
           ans=(ans*a)%c
           b=b-1
       b=b/2
       a=a*a%c
   return ans
mp = quickpow(c,pp,p)
mq = quickpow(c,qq,q)
print mp,mq

def toasc(x):
    str=''
    while len(x)>1:
        t=''
        t=x[0:2]
        str = str + chr(string.atoi(t,16))
        x=x[2:len(x)]
    return str

def ext_euclid(a, b):
    if b == 0:
        return (a, 1, 0)
    d, x, y = ext_euclid(b, a%b)
    return (d, y, x-a//b*y)

def linear_equation(a, b, c):
    d, x, y = ext_euclid(a, b)
    if c%d:
        raise 'no solution'
    k = c//d
    return d, x*k, y*k

yy,yp,yq=linear_equation(p,q,1)
aa = (yp*p*mq+yq*q*mp)%n
bb = n-int(aa)
cc = (yp*p*mq-yq*q*mp)%n
dd = n -int(cc)


print hex(aa)
print hex(bb)
print hex(cc)
print hex(dd)


print toasc(str(hex(aa))[2:])
print toasc(str(hex(bb))[2:])
print toasc(str(hex(cc))[2:])
print toasc(str(hex(dd))[2:])
```

拿到 flag。

```
flag{Rab1n_i5_c00l}
```

##### 题目

- JarvisOJ hard RSA

#### 综合题目

##### 范例 1

题目描述：Find the [flag](http://asis-ctf。ir/tasks/rsa。txz_93b525e771c284b7a3f0bb45b290ce56987c5834).

> 题目来源：ASIS 2016 线上赛

文件解压出来，有一个密文，一个公钥，一个 py 脚本。

看一下公钥。

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

逻辑很简单，读取 flag，重复 30 遍为密文。

随机取 $p$ 和 $q$，生成一个公钥，写入 `pubkey.pem`，再用脚本中的 `ext_rsa_encrypt` 函数进行加密，最后将密文写入 `flag.enc`。

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

拿到 flag。

```
ASIS{F4ct0R__N_by_it3rat!ng!}
```