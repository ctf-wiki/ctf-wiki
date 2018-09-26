# RSA 复杂题目

## 2018 Tokyo Western Mixed Cipher

题目给的信息如下所示：


- 每次交互可以维持的时间长度约为 5 分钟
- 每次交互中中n是确定的 1024 bit，但是未知， e 为 65537
- 使用 aes 加密了 flag，密钥和 IV 均不知道
- 每次密钥是固定的，但是 IV 每次都会随机
- 可以使用 encrypt 功能随意使用 rsa 和 aes 进行加密，其中每次加密都会对 aes 的 iv 进行随机
- 可以使用 decrypt 对随意的密文进行解密，但是只能知道最后一个字节是什么
- 可以使用 print_flag 获取 flag 密文
- 可以使用 print_key 获取 rsa 加密的 aes 密钥

本题目看似一个题目，实则是 3 个题目，需要分步骤解决。在此之前，我們準備好交互的函數

```python
def get_enc_key(io):
    io.read_until("4: get encrypted keyn")
    io.writeline("4")
    io.read_until("here is encrypted key :)n")
    c=int(io.readline()[:-1],16)
    return c

def encrypt_io(io,p):
    io.read_until("4: get encrypted keyn")
    io.writeline("1")
    io.read_until("input plain text: ")
    io.writeline(p)
    io.read_until("RSA: ")
    rsa_c=int(io.readline()[:-1],16)
    io.read_until("AES: ")
    aes_c=io.readline()[:-1].decode("hex")
    return rsa_c,aes_c

def decrypt_io(io,c):
    io.read_until("4: get encrypted keyn")
    io.writeline("2")
    io.read_until("input hexencoded cipher text: ")
    io.writeline(long_to_bytes(c).encode("hex"))
    io.read_until("RSA: ")
    return io.read_line()[:-1].decode("hex")
```

### GCD attack n

第一步我们需要把没有给出的 n 算出来，因为我们可以利用 encrypt 功能对我们输入的明文 x 进行 rsa 加密，那么可以利用整除的性质算 n

```python
因为x ^ e = c mod n
所以 n | x ^ e - c
```
我们可以构造足够多的 x，算出最够多的 x ^ e - c，从而计算最大公约数，得到 n。

```
def get_n(io):
    rsa_c,aes_c=encrypt_io(io,long_to_bytes(2))
    n=pow(2,65537)-rsa_c
    for i in range(3,6):
        rsa_c, aes_c = encrypt_io(io, long_to_bytes(i))
        n=primefac.gcd(n,pow(i,65537)-rsa_c)
    return n
```

可以利用加密进行 check

```python
def check_n(io,n):
    rsa_c, aes_c = encrypt_io(io, "123")
    if pow(bytes_to_long("123"), e, n)==rsa_c:
        return True
    else:
        return False
```

### RSA parity oracle

利用 leak 的的最后一个字节，我们可以进行选择密文攻击，使用 RSA parity oracle 回复 aes 的秘钥

```python
def guess_m(io,n,c):
    k=1
    lb=0
    ub=n
    while ub!=lb:
        print lb,ub
        tmp = c * gmpy2.powmod(2, k*e, n) % n
        if ord(decrypt_io(io,tmp)[-1])%2==1:
            lb = (lb + ub) / 2
        else:
            ub = (lb + ub) / 2
        k+=1
    print ub,len(long_to_bytes(ub))
    return ub
```

### PRNG Predict

这里我们可以解密 flag 的16字节之后的内容了，但是前16个字节没有 IV 是解密不了的。这时我们可以发现，IV 生成使用的随机数使用了 getrandbits，并且我们可以获取到足够多的随机数量，那么我们可以进行 PRNG 的 predict，从而直接获取随机数

这里使用了一个现成的的 java 进行 PRNG 的 Predict

```java
public class Main {

   static int[] state;
   static int currentIndex;
40huo
   public static void main(String[] args) {
      state = new int[624];
      currentIndex = 0;

//    initialize(0);

//    for (int i = 0; i < 5; i++) {
//       System.out.println(state[i]);
//    }

      // for (int i = 0; i < 5; i++) {
      // System.out.println(nextNumber());
      // }

      if (args.length != 624) {
         System.err.println("must be 624 args");
         System.exit(1);
      }
      int[] arr = new int[624];
      for (int i = 0; i < args.length; i++) {
         arr[i] = Integer.parseInt(args[i]);
      }


      rev(arr);

      for (int i = 0; i < 6240huo4; i++) {
         System.out.println(state[i]);
      }

//    System.out.println("currentIndex " + currentIndex);
//    System.out.println("state[currentIndex] " + state[currentIndex]);
//    System.out.println("next " + nextNumber());

      // want -2065863258
   }

   static void nextState() {
      // Iterate through the state
      for (int i = 0; i < 624; i++) {
         // y is the first bit of the current number,
         // and the last 31 bits of the next number
         int y = (state[i] & 0x80000000)
               + (state[(i + 1) % 624] & 0x7fffffff);
         // first bitshift y by 1 to the right
         int next = y >>> 1;
         // xor it with the 397th next number
         next ^= state[(i + 397) % 624];
         // if y is odd, xor with magic number
         if ((y & 1L) == 1L) {
            next ^= 0x9908b0df;
         }
         // now we have the result
         state[i] = next;
      }
   }

   static int nextNumber() {
      currentIndex++;
      int tmp = state[currentIndex];
      tmp ^= (tmp >>> 11);
      tmp ^= (tmp << 7) & 0x9d2c5680;
      tmp ^= (tmp << 15) & 0xefc60000;
      tmp ^= (tmp >>> 18);
      return tmp;
   }

   static void initialize(int seed) {

      // http://code.activestate.com/recipes/578056-mersenne-twister/

      // global MT
      // global bitmask_1
      // MT[0] = seed
      // for i in xrange(1,624):
      // MT[i] = ((1812433253 * MT[i-1]) ^ ((MT[i-1] >> 30) + i)) & bitmask_1

      // copied Python 2.7's impl (probably uint problems)
      state[0] = seed;
      for (int i = 1; i < 624; i++) {
         state[i] = ((1812433253 * state[i - 1]) ^ ((state[i - 1] >> 30) + i)) & 0xffffffff;
      }
   }

   static int unBitshiftRightXor(int value, int shift) {
      // we part of the value we are up to (with a width of shift bits)
      int i = 0;
      // we accumulate the result here
      int result = 0;
      // iterate until we've done the full 32 bits
      while (i * shift < 32) {
         // create a mask for this part
         int partMask = (-1 << (32 - shift)) >>> (shift * i);
         // obtain the part
         int part = value & partMask;
         // unapply the xor from the next part of the integer
         value ^= part >>> shift;
         // add the part to the result
         result |= part;
         i++;
      }
      return result;
   }

   static int unBitshiftLeftXor(int value, int shift, int mask) {
      // we part of the value we are up to (with a width of shift bits)
      int i = 0;
      // we accumulate the result here
      int result = 0;
      // iterate until we've done the full 32 bits
      while (i * shift < 32) {
         // create a mask for this part
         int partMask = (-1 >>> (32 - shift)) << (shift * i);
         // obtain the part
         int part = value & partMask;
         // unapply the xor from the next part of the integer
         value ^= (part << shift) & mask;
         // add the part to the result
         result |= part;
         i++;
      }
      return result;
   }

   static void rev(int[] nums) {
      for (int i = 0; i < 624; i++) {

         int value = nums[i];
         value = unBitshiftRightXor(value, 18);
         value = unBitshiftLeftXor(value, 15, 0xefc60000);
         value = unBitshiftLeftXor(value, 7, 0x9d2c5680);
         value = unBitshiftRightXor(value, 11);

         state[i] = value;
      }
   }
}
```

写了一个 python 直接调用 java

```
from Crypto.Util.number import long_to_bytes,bytes_to_long



def encrypt_io(io,p):
    io.read_until("4: get encrypted keyn")
    io.writeline("1")
    io.read_until("input plain text: ")
    io.writeline(p)
    io.read_until("RSA: ")
    rsa_c=int(io.readline()[:-1],16)
    io.read_until("AES: ")
    aes_c=io.readline()[:-1].decode("hex")
    return rsa_c,aes_c
import subprocess
import random
def get_iv(io):
    rsa_c, aes_c=encrypt_io(io,"1")
    return bytes_to_long(aes_c[0:16])
def splitInto32(w128):
    w1 = w128 & (2**32-1)
    w2 = (w128 >> 32) & (2**32-1)
    w3 = (w128 >> 64) & (2**32-1)
    w4 = (w128 >> 96)
    return w1,w2,w3,w4
def sign(iv):
    # converts a 32 bit uint to a 32 bit signed int
    if(iv&0x80000000):
        iv = -0x100000000 + iv
    return iv
def get_state(io):
    numbers=[]
    for i in range(156):
        print i
        numbers.append(get_iv(io))
    observedNums = [sign(w) for n in numbers for w in splitInto32(n)]
    o = subprocess.check_output(["java", "Main"] + map(str, observedNums))
    stateList = [int(s) % (2 ** 32) for s in o.split()]
    r = random.Random()
    state = (3, tuple(stateList + [624]), None)
    r.setstate(state)
    return r.getrandbits(128)
```

### EXP

整体攻击代码如下：

```python
from zio import *
import primefac
from Crypto.Util.number import long_to_bytes,bytes_to_long
target=("crypto.chal.ctf.westerns.tokyo",5643)
e=65537

def get_enc_key(io):
    io.read_until("4: get encrypted keyn")
    io.writeline("4")
    io.read_until("here is encrypted key :)n")
    c=int(io.readline()[:-1],16)
    return c

def encrypt_io(io,p):
    io.read_until("4: get encrypted keyn")
    io.writeline("1")
    io.read_until("input plain text: ")
    io.writeline(p)
    io.read_until("RSA: ")
    rsa_c=int(io.readline()[:-1],16)
    io.read_until("AES: ")
    aes_c=io.readline()[:-1].decode("hex")
    return rsa_c,aes_c

def decrypt_io(io,c):
    io.read_until("4: get encrypted keyn")
    io.writeline("2")
    io.read_until("input hexencoded cipher text: ")
    io.writeline(long_to_bytes(c).encode("hex"))
    io.read_until("RSA: ")
    return io.read_line()[:-1].decode("hex")

def get_n(io):
    rsa_c,aes_c=encrypt_io(io,long_to_bytes(2))
    n=pow(2,65537)-rsa_c
    for i in range(3,6):
        rsa_c, aes_c = encrypt_io(io, long_to_bytes(i))
        n=primefac.gcd(n,pow(i,65537)-rsa_c)
    return n

def check_n(io,n):
    rsa_c, aes_c = encrypt_io(io, "123")
    if pow(bytes_to_long("123"), e, n)==rsa_c:
        return True
    else:
        return False


import gmpy2
def guess_m(io,n,c):
    k=1
    lb=0
    ub=n
    while ub!=lb:
        print lb,ub
        tmp = c * gmpy2.powmod(2, k*e, n) % n
        if ord(decrypt_io(io,tmp)[-1])%2==1:
            lb = (lb + ub) / 2
        else:
            ub = (lb + ub) / 2
        k+=1
    print ub,len(long_to_bytes(ub))
    return ub


io = zio(target, timeout=10000, print_read=COLORED(NONE, 'red'),print_write=COLORED(NONE, 'green'))
n=get_n(io)
print check_n(io,n)
c=get_enc_key(io)
print len(decrypt_io(io,c))==16


m=guess_m(io,n,c)
for i in range(m - 50000,m+50000):
    if pow(i,e,n)==c:
        aeskey=i
        print long_to_bytes(aeskey)[-1]==decrypt_io(io,c)[-1]
        print "found aes key",hex(aeskey)

import fuck_r
next_iv=fuck_r.get_state(io)
print "##########################################"
print next_iv
print aeskey
io.interact()
```


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

## 2018 WCTF RSA

题目基本描述为

```
Description:
Encrypted message for user "admin":

<<<320881698662242726122152659576060496538921409976895582875089953705144841691963343665651276480485795667557825130432466455684921314043200553005547236066163215094843668681362420498455007509549517213285453773102481574390864574950259479765662844102553652977000035769295606566722752949297781646289262341623549414376262470908749643200171565760656987980763971637167709961003784180963669498213369651680678149962512216448400681654410536708661206594836597126012192813519797526082082969616915806299114666037943718435644796668877715954887614703727461595073689441920573791980162741306838415524808171520369350830683150672985523901>>>

admin public key:

n = 483901264006946269405283937218262944021205510033824140430120406965422208942781742610300462772237450489835092525764447026827915305166372385721345243437217652055280011968958645513779764522873874876168998429546523181404652757474147967518856439439314619402447703345139460317764743055227009595477949315591334102623664616616842043021518775210997349987012692811620258928276654394316710846752732008480088149395145019159397592415637014390713798032125010969597335893399022114906679996982147566245244212524824346645297637425927685406944205604775116409108280942928854694743108774892001745535921521172975113294131711065606768927
e = 65537

Service: http://36.110.234.253

```

这个题目现在已经没有办法在线获取 binary 了，现在得到的 binary 是之前已经下载好的，我们当时需要登录用户的 admin 来下载对应的 generator。

通过简单逆向这个 generator，我们可以发现这个程序是这么工作的

- 利用用户给定的 license（32 个字节），迭代解密某个**固定位置**之后的数据，每 32 个字节一组，与密钥相异或得到结果。
- 密钥的生成方法为 
    - $k_1=key$
    - $k_2 =sha256(k_1)$
    - ...
    - $k_n=sha256(k_{n-1})$

其中，固定位置就是在找源文件 `generator` 中第二次出现 `ENCRYPTED` 的位置，然后再次偏移 32 个字节。

```python
    _ENCRYPT_STR = ENCRYPTED_STR;
    v10 = 0;
    ENCRYPTED_LEN = strlen(ENCRYPTED_STR);
    do
    {
      do
        ++v9;
      while ( strncmp(&file_contents[v9], _ENCRYPT_STR, ENCRYPTED_LEN) );
      ++v10;
    }
    while ( v10 <= 1 );
    v11 = &file_start_off_32[loc2 + ENCRYPTED_LEN];
    v12 = loc2 + ENCRYPTED_LEN;
    len = file_size - (loc2 + ENCRYPTED_LEN) - 32;
    decrypt(&file_start_off_32[v12], &license, len);
    sha256_file_start(v11, len, &output);
    if ( !memcmp(&output, &file_contents[v12], 0x20u) )
    {
      v14 = fopen("out.exe", "wb");
      fwrite(v11, 1u, len, v14);
      fclose(v14);
      sprintf(byte_406020, "out.exe %s", argv[1]);
      system(byte_406020);
    }
```

同时，我们需要确保生成的文件的校验对应的哈希值恰好为指定的值，由于文件最后是一个 exe 文件，所以我们可以认为最后的文件头就是标准的 exe 文件，因此就不需要知道原始的 license 文件，进而我们可以编写 python 脚本生成 exe。

在生成的 exe 中，我们分析出程序的基本流程为

1. 读取 license
2. 使用 license 作为 seed 分别生成 pq
3. 利用 p，q 生成 n，e，d。

其漏洞出现在生成 p，q 的方法上，而且生成 p 和 q 的方法类似。

我们如果仔细分析下生成素数的函数的话，可以看到每个素数都是分为两部分生成的

1. 生成左半部分 512 位。
2. 生成右半部分 512 位。
3. 左右构成 1024 比特位，判断是不是素数，是素数就成功，不是素数，继续生成。

其中生成每部分的方式相同，方式为

```python
sha512(const1|const2|const3|const4|const5|const6|const7|const8|v9)
v9=r%1000000007
```

 只有 v9 会有所变化，但是它的范围却是固定的。

那么，如果我们表示 p，q 为

$p=a*2^{512}+b$

$q=c*2^{512}+d$

那么

$n=pq=ac*2^{1024}+(ad+bc)*2^{512}+bd$

那么

$n \equiv bd \bmod 2^{512}$

而且由于 p 和 q 在生成时，a，b，c，d 均只有 1000000007 种可能性。

进而，我们可以枚举所有的可能性，首先计算出 b 可能的集合为 S，同时我们使用中间相遇攻击，计算

$n/d \equiv b \bmod 2^{512}$

这里由于 b 和 d 都是 p 的尾数，所以一定不会是 2 的倍数，进而必然存在逆元。

这样做虽然可以，然而，我们可以简单算一下存储空间

$64*1000000007 / 1024 / 1024 / 1024=59$

也就是说需要 59 G，太大了，，所以我们仍然需要进一步考虑

$n \equiv bd \bmod 2^{64}$

这样，我们的内存需求瞬间就降到了 8 G左右。我们仍然使用枚举的方法进行运算。

其次，我们不能使用 python，，python 占据空间太大，因此需要使用 c/c++ 编写。

枚举所有可能的 d 计算对应的值 $n/d$ 如果对应的值在集合 S 中，那么我们就可以认为找到了一对合法的 b 和 d，因此我们就可以恢复 p 和 q 的一半。

之后，我们根据

$n-bd=ac*2^{1024}+(ad+bc)*2^{512}$

可以得到

$\frac{n-bd}{2^{512}} = ac*2^{512}+ad+bc$

$\frac{n-bd}{2^{512}} \equiv ad+bc \bmod 2^{512}$

类似地，我们可以计算出 a 和 c，从而我们就可以完全恢复出 p 和 q。

在具体求解的过程中，在求 p 和 q 的一部分时，可以发现因为是模 $2^{64}$，所以可能存在碰撞（但其实就是一个是 p，另外一个是q，恰好对称。）。下面我们就求得了 b 对应的 v9。

**注意：这里枚举出来的空间大约占用 11 个 G（包括索引），所以请选择合适的位置。**

```
b64: 9646799660ae61bd idx_b: 683101175 idx_d: 380087137
search 23000000
search 32000000
search 2b000000
search d000000
search 3a000000
search 1c000000
search 6000000
search 24000000
search 15000000
search 33000000
search 2c000000
search e000000
b64: 9c63259ccab14e0b idx_b: 380087137 idx_d: 683101175
search 1d000000
search 3b000000
search 7000000
search 16000000
search 25000000
search 34000000
```

其实，我们在真正得到 p 或者 q 的一部分后，另外一部分完全可以使用暴力枚举的方式获取，因为计算量几乎都是一样的，最后结果为

```python
...
hash 7000000
hash 30000000
p = 13941980378318401138358022650359689981503197475898780162570451627011086685747898792021456273309867273596062609692135266568225130792940286468658349600244497842007796641075219414527752166184775338649475717002974228067471300475039847366710107240340943353277059789603253261584927112814333110145596444757506023869
q = 34708215825599344705664824520726905882404144201254119866196373178307364907059866991771344831208091628520160602680905288551154065449544826571548266737597974653701384486239432802606526550681745553825993460110874794829496264513592474794632852329487009767217491691507153684439085094523697171206345793871065206283
plain text 13040004482825754828623640066604760502140535607603761856185408344834209443955563791062741885
hash 16000000
hash 25000000
hash b000000
hash 34000000
hash 1a000000
...
➜  2018-WCTF-rsa git:(master) ✗ python
Python 2.7.14 (default, Mar 22 2018, 14:43:05)
[GCC 4.2.1 Compatible Apple LLVM 9.0.0 (clang-900.0.39.2)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> p=13040004482825754828623640066604760502140535607603761856185408344834209443955563791062741885
>>> hex(p)[2:].decode('hex')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/local/Cellar/python@2/2.7.14_3/Frameworks/Python.framework/Versions/2.7/lib/python2.7/encodings/hex_codec.py", line 42, in hex_decode
    output = binascii.a2b_hex(input)
TypeError: Odd-length string
>>> hex(p)[2:-1].decode('hex')
'flag{fa6778724ed740396fc001b198f30313}'
```

最后我们便拿到 flag 了。

**详细的利用代码请参见 ctf-challenge 仓库。**

相关编译指令，需要链接相关的库。

```shell
g++  exp2.cpp -std=c++11 -o main2 -lgmp -lcrypto -pthread
```

## 参考

- https://upbhack.de/posts/wctf-2018-writeup-rsa/
