[EN](./rsa_e_attack.md) | [ZH](./rsa_e_attack-zh.md)
## Small public key index attack


### Attack conditions


e is very small, such as e is 3.


### Attack principle


Suppose the user uses the key $e=3$. Considering that the encryption relationship is satisfied:


$$

c\equiv m^3 \bmod N

$$



then:


$$

\begin{align*}

m^3 &= c+k\times N\\

m &= \sqrt[3]{c+k\times n}

\end{align*}

$$



An attacker can enumerate $k$ from small to large and open three roots in turn until an integer is opened.


### Examples


Here we take the XMan Summer Camp class exercise as an example (Jarvis OJ has a recurrence), the attachment has a `flag.enc` and `pubkey.pem`, which is obviously a ciphertext and a public key. Openssl` Read the public key.


```bash

➜  Jarvis OJ-Extremely hard RSA git:(master) ✗ openssl rsa -pubin -in pubkey.pem -text -modulus       

Public-Key: (4096 bit)

Modulus:

    00:b0:be:e5:e3:e9:e5:a7:e8:d0:0b:49:33:55:c6:

18: fc: 8c: 7d: 7d: 03: b8: 2e: 40: 99: 51: c1: 82: f3: 98:
from: e3: 10: 45: 80: e7: no: 70: d3: 83: yes: 53: 11: 47: 56:
    56:e8:a9:64:d3:80:cb:15:7f:48:c9:51:ad:fa:65:

db: 0b: 12: 2c: a4: 0e: 42: fa: 70: 91: 89: b7: 19:
d7: 46: E2: F6: 06: 9b: of: 11: ce: bd: 65: 0f: 14: b9: 3c:
97: 73: 52: fd: 13: b1: yes: a6: d6: e1: da: 77: 55: 02: ab:
    ff:89:d3:a8:b3:61:5f:d0:db:49:b8:8a:97:6b:c2:

05: 68: 48: 92: 84: e1: 81: f6, f1: 1E: 27: 08: 91: c8: if:
80: 01: 7b: ad: 23: 8e: 36: 30: 39: a:
    10:1b:c2:99:49:d3:a4:f4:03:8d:46:39:38:85:15:

79: c7: 52: 5a: 69: 98: 4f: 15: b5: 66: 7f: 34: 20:
eb: 26: 11: 36: 94: 7f: a1: 23: e5: 49: df: ff: 00: 60: 18:
83: of: D9: 36: fe: 41: 1e: 00: 6e: 4e: 93: D1: A0: 0b: 0f:
ea: 54: 1b: bf: c8: c5: 18: 6c: b6: 22: 05: 03:
13: 11: 0d: 64: 0c: 77: ea: 54: no: 32: 20: fc: 8f: 4c: c6:
what: 77: 15: 1e: 29: b3: e0: 65: 78: c4: 78:
    45:89:ef:9a:19:7f:6f:80:6d:b8:b3:ec:d8:26:ca:

    d2:4f:53:24:cc:de:c6:e8:fe:ad:2c:21:50:06:86:

    02:c8:dc:dc:59:40:2c:ca:c9:42:4b:79:00:48:cc:

dd: 93: 27: 06: 80: 95: ef: a0: 10: b7: f1: 96: c7: 4b:
c3: 7b: 12: 8f: 9e: 14: 11: 75: 16: 33: f7: 8b: 7b: 9e: 56:
f7: 1f: 77: a1: b4: da: ad: 3f: c5: 4b: 5e: 7e:
    a7:2f:b1:76:75:97:65:52:2b:4b:bc:02:e3:14:d5:

    c0:6b:64:d5:05:4b:7b:09:6c:60:12:36:e6:cc:f4:

    5b:5e:61:1c:80:5d:33:5d:ba:b0:c3:5d:22:6c:c2:

08: d8: the 47: 36: ba: 39: A0: 35: 44: 26: fa: e0: 06: 7:
fe: 52: d5: 26: 7d: cf: b9: c3: 88: 4f: 51: fd: df: df: 4a:
97: 94: bc: fe: 0e: 15: 57: 11: 37: 49: e6: c8: ef: 42: 1d:
You do not know how to do this.
2d: 34: 88: f7: 6d: eb: 62: bd: ef: 7b: ea: 60: 26: f2: 2a:
1d: 25: aa: 2a: 92: d1: 17: 4b:
98: 03: e6: bb: 5f: ad: 75: e1: 86: a9: 46: a1:
0f: 12: 43: f4: 38: 74: 46: cc: this: b2: 22: 2a: 96: 5c: c3:
    0b:39:29

Exponent: 3 (0x3)

Modulus=B0BEE5E3E9E5A7E8D00B493355C618FC8C7D7D03B82E409951C182F398DEE3104580E7BA70D383AE5311475656E8A964D380CB157F48C951ADFA65DB0B122CA40E42FA709189B719A4F0D746E2F6069BAF11CEBD650F14B93C977352FD13B1EEA6D6E1DA775502ABFF89D3A8B3615FD0DB49B88A976BC20568489284E181F6F11E270891C8EF80017BAD238E363039A458470F1749101BC29949D3A4F4038D463938851579C7525A69984F15B5667F34209B70EB261136947FA123E549DFFF00601883AFD936FE411E006E4E93D1A00B0FEA541BBFC8C5186CB6220503A94B2413110D640C77EA54BA3220FC8F4CC6CE77151E29B3E06578C478BD1BEBE04589EF9A197F6F806DB8B3ECD826CAD24F5324CCDEC6E8FEAD2C2150068602C8DCDC59402CCAC9424B790048CCDD9327068095EFA010B7F196C74BA8C37B128F9E1411751633F78B7B9E56F71F77A1B4DAAD3FC54B5E7EF935D9A72FB176759765522B4BBC02E314D5C06B64D5054B7B096C601236E6CCF45B5E611C805D335DBAB0C35D226CC208D8CE4736BA39A0354426FAE006C7FE52D5267DCFB9C3884F51FDDFDF4A9794BCFE0E1557113749E6C8EF421DBA263AFF68739CE00ED80FD0022EF92D3488F76DEB62BDEF7BEA6026F22A1D25AA2A92D124414A8021FE0C174B9803E6BB5FAD75E186A946A17280770F1243F4387446CCCEB2222A965CC30B3929

writing RSA key

-----BEGIN PUBLIC KEY-----

MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAsL7l4 + nlp + jQC0kzVcYY
/Ix9fQO4LkCZUcGC85je4xBFgOe6cNODrlMRR1ZW6Klk04DLFX9IyVGt+mXbCxIs

pA5C+nCRibcZpPDXRuL2BpuvEc69ZQ8UuTyXc1L9E7Huptbh2ndVAqv/idOos2Ff

0NtJuIqXa8IFaEiShOGB9vEeJwiRyO+AAXutI442MDmkWEcPF0kQG8KZSdOk9AON

Rjk4hRV5x1JaaZhPFbVmfzQgm3DrJhE2lH + hI + VJ3 / 8AYBiDr9k2 / kEeAG5Ok9Gg
Cw/qVBu/yMUYbLYiBQOpSyQTEQ1kDHfqVLoyIPyPTMbOdxUeKbPgZXjEeL0b6+BF

ie+aGX9vgG24s+zYJsrST1MkzN7G6P6tLCFQBoYCyNzcWUAsyslCS3kASMzdkycG

gJXvoBC38ZbHS6jDexKPnhQRdRYz94t7nlb3H3ehtNqtP8VLXn75NdmnL7F2dZdl

UitLvALjFNXAa2TVBUt7CWxgEjbmzPRbXmEcgF0zXbqww10ibMII2M5HNro5oDVE

JvrgBsf+UtUmfc+5w4hPUf3f30qXlLz+DhVXETdJ5sjvQh26Jjr/aHOc4A7YD9AC

LvktNIj3betive976mAm8iodJaoqktEkQUqAIf4MF0uYA+a7X6114YapRqFygHcP

EkP0OHRGzM6yIiqWXMMLOSkCAQM=

-----END PUBLIC KEY-----

```



Seeing $e=3$, it is clear that the small public key index attacked. Here we use the Crypto library to read the public key and use multiprocessing to speed up the crack.


```python

#/usr/bin/python

# coding=utf-8

import gmpy2

from Crypto.PublicKey import RSA

from multiprocessing import Pool

pool = Pool(4)



with open('./pubkey.pem', 'r') as f:

    key = RSA.importKey(f)

    N = key.n

e = key.e
with open('flag.enc', 'r') as f:

    cipher = f.read().encode('hex')

    cipher = int(cipher, 16)





def calc(j):

    print j

    a, b = gmpy2.iroot(cipher + j * N, 3)

    if b == 1:

        m = a

        print '{:x}'.format(int(m)).decode('hex')

        pool.terminate()

        exit()





def SmallE():

    inputs = range(0, 130000000)

    pool.map(calc, inputs)

    pool.close()

    pool.join()





if __name__ == '__main__':

    print 'start'

SmallE ()
```


The blasting time is a bit long, get the flag


```

Didn't you know RSA padding is really important? Now you see a non-padding message is so dangerous. And you should notice this in future.Fl4g: flag{Sm4ll_3xpon3nt_i5_W3ak}

```



### Title


## RSA Derivative Algorithm - Rabin Algorithm


### Attack conditions


The Rabin algorithm is characterized by $e=2$.


### Attack principle


Ciphertext:


$$

c = m ^ 2 \ n way
$$



Decryption:


- Calculate $m_p$ and $m_q$:


$$

\begin{align*}

m_p &amp; = \ sqrt {c} \ p \\ way
m_q &amp; = \ sqrt {c} \ q way
\end{align*}

$$



- Calculate $y_p$ and $y_q$ with extended Euclidean:


$$

y_p \cdot p + y_q \cdot q = 1

$$



- Solve four plaintexts:


$$

\begin{align*}

a &= (y_p \cdot p \cdot m_q + y_q \cdot q \cdot m_p) \bmod n\\

b &= n - a\\

c &= (y_p \cdot p \cdot m_q - y_q \cdot q \cdot m_p) \bmod n\\

d &= n - c

\end{align*}

$$



Note: If $p \equiv q \equiv 3 \pmod 4$, then


$$

\begin{align*}

m_p &amp; c = ^ {\ frac {1} {4} (p + 1)} \ p \\ way
m_q &amp; c = ^ {\ frac {1} {4} (q + 1)} \ q way
\end{align*}

$$



In general, $p \equiv q \equiv 3 \pmod 4$ is satisfied. For cases that are not met, please refer to the corresponding algorithm.


### Examples


Here we take the XMan Summer Camp class exercise (Jarvis OJ has a recurrence) as an example, read the public key.


```bash

➜  Jarvis OJ-hard RSA git:(master) ✗ openssl rsa -pubin -in pubkey.pem -text -modulus 

Public-Key: (256 bit)

Modulus:

00: c2: 63: 6a: e5: c3: d8: e4: 3f: fb: 97: ab:
    1a:ac:6c:0b:f6:cd:3d:70:eb:ca:28:1b:ff:e9:7f:

    be:30:dd

Exponent: 2 (0x2)

Modulus=C2636AE5C3D8E43FFB97AB09028F1AAC6C0BF6CD3D70EBCA281BFFE97FBE30DD

writing RSA key

-----BEGIN PUBLIC KEY-----

MDowDQYJKoZIhvcNAQEBBQADKQAwJgIhAMJjauXD2OQ / + 5erCQKPGqxsC / bNPXDr
yigb / + l / vjDdAgEC
-----END PUBLIC KEY-----

```



$e=2$, consider the Rabin algorithm. First, let&#39;s break down p and q first.


```text

p=275127860351348928173285174381581152299

q=319576316814478949870590164193048041239

```



Write code


```python

#!/usr/bin/python

# coding=utf-8

import gmpy2

import string

from Crypto.PublicKey import RSA



# Read public key parameters
with open('pubkey.pem', 'r') as f:

    key = RSA.importKey(f)

    N = key.n

e = key.e
with open('flag.enc', 'r') as f:

    cipher = f.read().encode('hex')

    cipher = string.atoi(cipher, base=16)

    # print cipher

print "please input p"

p = int(raw_input(), 10)

print 'please input q'

q = int(raw_input(), 10)

#算 yp和yq
inv_p = gmpy2.invert(p, q)

inv_q = gmpy2.invert(q, p)



#算mp mp and mq
mp = pow(cipher, (p + 1) / 4, p)

mq = pow(cipher, (q + 1) / 4, q)



# Calculate a, b, c, d
a = (inv_p * p * mq + inv_q * q * mp) % N

b = N - int(a)

c = (inv_p * p * mq - inv_q * q * mp) % N

D = N - int (c)


for i in (a, b, c, d):

    s = '%x' % i
if len (s)% 2! = 0:
        s = '0' + s

    print s.decode('hex')

```



Get the flag, `PCTF{sp3ci4l_rsa}`.


### Title