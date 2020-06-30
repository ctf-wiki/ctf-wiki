[EN](./rsa_module_attack.md) | [ZH](./rsa_module_attack-zh.md)

## Bruteforcing Factors of N 


### Attack Prerequisite


1. N is efficiently small (less than 512 bits, for example).


### JarvisOJ - Easy RSA



Here we take "JarvisOJ - Easy RSA" as an example, the challenge description is the following:


&gt; Remember the veryeasy RSA? Is it not difficult? Then continue to look at this question, this question is not difficult.
&gt; Known piece of RSA encrypted information is: 0xdc2eeeb2782c and the public key used for encryption is known:
&gt; N = 322831561921859 and = 23
&gt; Please decrypt the plaintext, please convert the number into ascii code submission when submitting
&gt; For example, if the plaintext you solved is 0x6162, please submit the string ab
&gt; Submit format: `PCTF{clear text string}`


We can see that our N is small. Here we can query the factors of N manually from [factordb](http://factordb.com/):


$$
322831561921859 = 13574881 \times 23781539
$$



But a better solution is to utilize [factordb-python](https://github.com/ryosan-470/factordb-python) for factoring automation:


```python
#!/usr/bin/env python3
from Crypto.Util.number import inverse, long_to_bytes
from factordb.factordb import FactorDB

#--------data--------#

N = 322831561921859
e = 23
c = 0xdc2eeeb2782c

#--------factordb--------#

f = FactorDB(N)
f.connect()
factors = f.get_factor_list()

#--------rsa--------#

phi = 1
for factor in factors:
    phi *= factor - 1

d = inverse(e, phi)
m = pow(c, d, N)
flag = long_to_bytes(m).decode()

print(flag)
```

Run the script and grab your flag.


## p &amp; q Improper decomposition N


### Attack conditions


We can also attack when p and q are not selected properly in RSA.


### |pq| Very large


When pq is large, there must be a certain parameter is small, here we assume p, then we can try to divide the modulus by exhaustive method, and then decompose the modulus, get the confidential parameters and plaintext information. Basically, it is not very feasible.


### |pq| Smaller


First of all


$$
\frac{(p+q)^2}{4}-n=\frac{(p+q)^2}{4}-pq=\frac{(p-q)^2}{4}
$$



Since |pq| is small, $\frac{(pq)^2}{4}$ is naturally small, and $\frac{(p+q)^2}{4}$ is only slightly larger than N. , so $\frac{p+q}{2}$ is similar to $\sqrt{n}$. Then we can decompose as follows


- Check each integer x of $\sqrt{n}$ in sequence until you find an x such that $x^2-n$ is the square number, denoted as $y^2$
- Then $x^2-n=y^2$, and then decompose N according to the squared difference formula


### p - 1 Smooth


When p is a factor of N and p - 1 is smooth, it is possible to use the Pollard&#39;s p − 1 algorithm to decompose N, but it is not entirely successful.


!!! warning

Principle analysis to be completed


### p + 1 Smooth


When p is a factor of n and p + 1 is smooth, it may be possible to use the Williams&#39;s p + 1 algorithm to decompose N, but it is not entirely successful.


### 2017 SECCON very smooth



The program gives an HTTPS encrypted traffic packet, first getting the certificate from it.


```shell

➜  2017_SECCON_verysmooth git:(master) binwalk -e s.pcap      



DECIMAL       HEXADECIMAL     DESCRIPTION

--------------------------------------------------------------------------------

2292          0x8F4           Certificate in DER format (x509 v3), header length: 4, sequence length: 467

4038          0xFC6           Certificate in DER format (x509 v3), header length: 4, sequence length: 467

5541          0x15A5          Certificate in DER format (x509 v3), header length: 4, sequence length: 467



➜ 2017_SECCON_verysmooth git: (master) ls
s.pcap  _s.pcap.extracted  very_smooth.zip

```



Here are three certificates, three modules are the same, only one example is given here.


```

➜  _s.pcap.extracted git:(master) openssl x509 -inform DER -in FC6.crt  -pubkey -text -modulus -noout 

-----BEGIN PUBLIC KEY-----

MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVRqqCXPYd6Xdl9GT7/kiJrYvy

8lohddAsi28qwMXCe2cDWuwZKzdB3R9NEnUxsHqwEuuGJBwJwIFJnmnvWurHjcYj
DUddp + 4X8C9jtvCaLTgd + baSjo2eB0f + uiSL / 9 / 4NN + vR3FliRm2mByeFCjppTQl
yioxCqbXYIMxGO4NcQIDAQAB
-----END PUBLIC KEY-----

Certificate:

    Data:

        Version: 1 (0x0)

        Serial Number: 11640506567126718943 (0xa18b630c7b3099df)

    Signature Algorithm: sha256WithRSAEncryption

        Issuer: C=JP, ST=Kawasaki, O=SRL

        Validity

            Not Before: Oct  8 02:47:17 2017 GMT

            Not After : Oct  8 02:47:17 2018 GMT

        Subject: C=JP, ST=Kawasaki, O=SRL

        Subject Public Key Info:

            Public Key Algorithm: rsaEncryption

                Public-Key: (1024 bit)

                Modulus:

                    00:d5:46:aa:82:5c:f6:1d:e9:77:65:f4:64:fb:fe:

                    48:89:ad:8b:f2:f2:5a:21:75:d0:2c:8b:6f:2a:c0:

c5: c2: 7b: 67: 03: 5a: ec: 19: 2b: 37: 41: dd: 1f: 4d: 12:
75: 31: b0: 7a: b0: 12: eb: 86: 24: 1c: 09: c0: 81: 49: 9e:
69: ef: 5a: ea: c7: 8d: c6: 23: 0d: 47: 5d: a7: ee: 17: f0:
2f: 63: b6: f0: 9a: 2d: 38: 1d: f9: b6: 92: 8e: 8d: 9e:47: fe: ba: 24: 8b: ff: df: f8: 9c: df: af: 47: 71: 65: 89:
19: b6: 98: 1: 9e: 14: 28: e9: a5: 34: 25: ca: 2a: 31: 0a:
a6: d7: 60: 83: 31: 18: in: 0d: 71
                Exponent: 65537 (0x10001)

    Signature Algorithm: sha256WithRSAEncryption

78: 92: 11: fb: 6c: e1: 7a: f7: 2a: 33: b8: 8b: 08: a7: f7: 5b: de: cf:
         62:0b:a0:ed:be:d0:69:88:38:93:94:9d:05:41:73:bd:7e:b3:

         32:ec:8e:10:bc:3a:62:b0:56:c7:c1:3f:60:66:a7:be:b9:46:

         f7:46:22:6a:f3:5a:25:d5:66:94:57:0e:fc:b5:16:33:05:1c:

         6f:f5:85:74:57:a4:a0:c6:ce:4f:fd:64:53:94:a9:83:b8:96:

bf: 5b: a7: ee: 8b: 1e: 48: a7: d2: 43: 06: 0e: 4f: 5a: 86: 62: 69:
e2: c0: bd: 4e: 89: c9: af: 04: 4a: 77: a2:
b7: 39
Modulus=D546AA825CF61DE97765F464FBFE4889AD8BF2F25A2175D02C8B6F2AC0C5C27B67035AEC192B3741DD1F4D127531B07AB012EB86241C09C081499E69EF5AEAC78DC6230D475DA7EE17F02F63B6F09A2D381DF9B6928E8D9E0747FEBA248BFFDFF89CDFAF4771658919B6981C9E1428E9A53425CA2A310AA6D760833118EE0D71

```



It can be seen that the modulus is only 1024 bits. Moreover, according to the title name very smooth, it should be one of the factors comparing smooth, here we use the primaryfac to try Pollard&#39;s p − 1 and Williams&#39;s p + 1 algorithm respectively, as follows


```shell

➜  _s.pcap.extracted git:(master) python -m primefac -vs -m=p+1  149767527975084886970446073530848114556615616489502613024958495602726912268566044330103850191720149622479290535294679429142532379851252608925587476670908668848275349192719279981470382501117310509432417895412013324758865071052169170753552224766744798369054498758364258656141800253652826603727552918575175830897



149767527975084886970446073530848114556615616489502613024958495602726912268566044330103850191720149622479290535294679429142532379851252608925587476670908668848275349192719279981470382501117310509432417895412013324758865071052169170753552224766744798369054498758364258656141800253652826603727552918575175830897: p+1 11807485231629132025602991324007150366908229752508016230400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001 12684117323636134264468162714319298445454220244413621344524758865071052169170753552224766744798369054498758364258656141800253652826603727552918575175830897

Z309  =  P155 x P155  =  11807485231629132025602991324007150366908229752508016230400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001 x 12684117323636134264468162714319298445454220244413621344524758865071052169170753552224766744798369054498758364258656141800253652826603727552918575175830897

```



It can be found that when using the Williams&#39;s *p* + 1 algorithm, it is directly decomposed. It is reasonable to say that this factor is p-1 seems to be smoother, but it cannot be decomposed using the Pollard&#39;s p − 1 algorithm. Further testing is done here.


```shell

➜  _s.pcap.extracted git:(master) python -m primefac -vs 1180748523162913202560299132400715036690822975250801623040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002



1180748523162913202560299132400715036690822975250801623040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002: 2 7 43 503 761429 5121103123294685745276806480148867612214394022184063853387799606010231770631857868979139305712805242051823263337587909550709296150544706624823

Z154  =  P1 x P1 x P2 x P3 x P6 x P142  =  2 x 7 x 43 x 503 x 761429 x 5121103123294685745276806480148867612214394022184063853387799606010231770631857868979139305712805242051823263337587909550709296150544706624823



➜  _s.pcap.extracted git:(master) python -m primefac -vs 1180748523162913202560299132400715036690822975250801623040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 



1180748523162913202560299132400715036690822975250801623040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000: 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5 5

Z154  =  P1^185 x P1^62 x P1^97  =  2^185 x 3^62 x 5^97

```



It can be seen that there are indeed many small factors for p-1, but the number is too large, which will cause an exponential explosion when enumerating, so it is not decomposed.


And construct a private key based on the decomposed number


```python

from Crypto.PublicKey import RSA

import gmpy2





def main():

    n = 149767527975084886970446073530848114556615616489502613024958495602726912268566044330103850191720149622479290535294679429142532379851252608925587476670908668848275349192719279981470382501117310509432417895412013324758865071052169170753552224766744798369054498758364258656141800253652826603727552918575175830897L

    p = 11807485231629132025602991324007150366908229752508016230400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001L

    q = 12684117323636134264468162714319298445454220244413621344524758865071052169170753552224766744798369054498758364258656141800253652826603727552918575175830897L

e = 65537L
    priv = RSA.construct((n, e, long(gmpy2.invert(e, (p - 1) * (q - 1)))))

    open('private.pem', 'w').write(priv.exportKey('PEM'))





main()

```



Finally, import the private key into wireshark to get the plain text (Edit -&gt; Preferences -&gt; Protocols -&gt; SSL -&gt; RSA Key List).


```html

<html>

<head><title>Very smooth</title></head>

<body>

<h1>

Answer: One of these primes is very smooth.

</h1>

</body>

</html>

```



### Extension


For more on some methods of decomposing the modulus N, please refer to https://en.wikipedia.org/wiki/Integer_factorization.


## Non-coprime Moduli


### Attack Prerequisite


When there are two public keys, N is not mutually prime, we can obviously obtain the greatest common factor directly for these two numbers, and then directly obtain p, q, and then obtain the corresponding private key.


### SCTF RSA2 



Here we take SCTF rsa2 as an example. Open the pcap package directly and find that there are a bunch of messages, including N and e, and then try to test whether the different N is mutual. I tried the first two.


```python

import gmpy2

n1 =
n2 =
print gmpy2.gcd(n1, n2)

```



The results found that they were not mutually exclusive.


```shell

➜  scaf-rsa2 git:(master) ✗ python exp.py

122281872221091773923842091258531471948886120336284482555605167683829690073110898673260712865021244633908982705290201598907538975692920305239961645109897081011524485706755794882283892011824006117276162119331970728229108731696164377808170099285659797066904706924125871571157672409051718751812724929680249712137

```



Then we can decrypt it directly, here we use the first pair of public key ciphers. code show as below


```python

from Crypto.PublicKey import RSA

from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP

import gmpy2

from base64 import b64decode

n1 =
n2 =
p1 = gmpy2.gcd(n1, n2)

q1 = n1 / p1

e = 65537
phin = (p1 - 1) * (q1 - 1)
d = gmpy2.invert (e, phin)
cipher = 0x68d5702b70d18238f9d4a3ac355b2a8934328250efd4efda39a4d750d80818e6fe228ba3af471b27cc529a4b0bef70a2598b80dd251b15952e6a6849d366633ed7bb716ed63c6febd4cd0621b0c4ebfe5235de03d4ee016448de1afbbe61144845b580eed8be8127a8d92b37f9ef670b3cdd5af613c76f58ca1a9f6f03f1bc11addba30b61bb191efe0015e971b8f78375faa257a60b355050f6435d94b49eab07075f40cb20bb8723d02f5998d5538e8dafc80cc58643c91f6c0868a7a7bf3bf6a9b4b6e79e0a80e89d430f0c049e1db4883c50db066a709b89d74038c34764aac286c36907b392bc299ab8288f9d7e372868954a92cdbf634678f7294096c7

plain = gmpy2.powmod(cipher, d, n1)

plain = hex(plain)[2:]

if len (plain)% 2! = 0:
    plain = '0' + plain

print plain.decode('hex')

```



Finally decrypted as follows


```shell

➜  scaf-rsa2 git:(master) ✗ python exp.py       
sH1R3_PRlME_1N_rsA_iS_4ulnEra5le

```



Unzip the package.


## Common Modulus Attack


### Attack Prerequisite


1. Same modulus N is used multiple times to encrypt the same plaintext m (only e is different for each encryption).
2. e1 and e2 are coprime.

### Theory

Suppose the public exponents of two users are $e_1$ and $e_2$, where $e_1$ and $e_2$ are coprime. If the plaintext $m$, then the ciphertext is:

$$
c_1 = m^{e_1}\bmod N \\
c_2 = m^{e_2}\bmod N
$$

Attack could recover the plaintext if he/she obtained $c_1$ and $c_2$. Compute the two coefficients $r$ and $s$ of $re_1+se_2=1\bmod n$ using extended Euclidean Algorithm, we have:

$$
\begin{align*}
c_{1}^{r}c_{2}^{s} &\equiv m^{re_1}m^{se_2}\bmod n\\
&\equiv m^{(re_1+se_2)} \bmod n\\
&\equiv m\bmod n
\end{align*}
$$


### Jarvis OJ Crypto - very hard RSA

Check out the given source code:

```python
#!/usr/bin/env python

import random

N = 0x00b0bee5e3e9e5a7e8d00b493355c618fc8c7d7d03b82e409951c182f398dee3104580e7ba70d383ae5311475656e8a964d380cb157f48c951adfa65db0b122ca40e42fa709189b719a4f0d746e2f6069baf11cebd650f14b93c977352fd13b1eea6d6e1da775502abff89d3a8b3615fd0db49b88a976bc20568489284e181f6f11e270891c8ef80017bad238e363039a458470f1749101bc29949d3a4f4038d463938851579c7525a69984f15b5667f34209b70eb261136947fa123e549dfff00601883afd936fe411e006e4e93d1a00b0fea541bbfc8c5186cb6220503a94b2413110d640c77ea54ba3220fc8f4cc6ce77151e29b3e06578c478bd1bebe04589ef9a197f6f806db8b3ecd826cad24f5324ccdec6e8fead2c2150068602c8dcdc59402ccac9424b790048ccdd9327068095efa010b7f196c74ba8c37b128f9e1411751633f78b7b9e56f71f77a1b4daad3fc54b5e7ef935d9a72fb176759765522b4bbc02e314d5c06b64d5054b7b096c601236e6ccf45b5e611c805d335dbab0c35d226cc208d8ce4736ba39a0354426fae006c7fe52d5267dcfb9c3884f51fddfdf4a9794bcfe0e1557113749e6c8ef421dba263aff68739ce00ed80fd0022ef92d3488f76deb62bdef7bea6026f22a1d25aa2a92d124414a8021fe0c174b9803e6bb5fad75e186a946a17280770f1243f4387446ccceb2222a965cc30b3929L

def pad_even(x):
    return ('', '0')[len(x)%2] + x

e1 = 17
e2 = 65537


fi = open('flag.txt','rb')
fo1 = open('flag.enc1','wb')
fo2 = open('flag.enc2','wb')


data = fi.read()
fi.close()

while (len(data)<512-11):
    data  =  chr(random.randint(0,255))+data

data_num = int(data.encode('hex'),16)

encrypt1 = pow(data_num,e1,N)
encrypt2 = pow(data_num,e2,N)


fo1.write(pad_even(format(encrypt1,'x')).decode('hex'))
fo2.write(pad_even(format(encrypt2,'x')).decode('hex'))

fo1.close()
fo2.close()
```

Take a look at this part:

```python
encrypt1 = pow(data_num,e1,N)
encrypt2 = pow(data_num,e2,N)
```

We can see that the same modulus N is used twice, and e1 and e2 are coprime. Proceed with common modulus attack:

```python
#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes, bytes_to_long
from sympy import gcdex
from sys import exit

#--------data--------#

N = 0x00b0bee5e3e9e5a7e8d00b493355c618fc8c7d7d03b82e409951c182f398dee3104580e7ba70d383ae5311475656e8a964d380cb157f48c951adfa65db0b122ca40e42fa709189b719a4f0d746e2f6069baf11cebd650f14b93c977352fd13b1eea6d6e1da775502abff89d3a8b3615fd0db49b88a976bc20568489284e181f6f11e270891c8ef80017bad238e363039a458470f1749101bc29949d3a4f4038d463938851579c7525a69984f15b5667f34209b70eb261136947fa123e549dfff00601883afd936fe411e006e4e93d1a00b0fea541bbfc8c5186cb6220503a94b2413110d640c77ea54ba3220fc8f4cc6ce77151e29b3e06578c478bd1bebe04589ef9a197f6f806db8b3ecd826cad24f5324ccdec6e8fead2c2150068602c8dcdc59402ccac9424b790048ccdd9327068095efa010b7f196c74ba8c37b128f9e1411751633f78b7b9e56f71f77a1b4daad3fc54b5e7ef935d9a72fb176759765522b4bbc02e314d5c06b64d5054b7b096c601236e6ccf45b5e611c805d335dbab0c35d226cc208d8ce4736ba39a0354426fae006c7fe52d5267dcfb9c3884f51fddfdf4a9794bcfe0e1557113749e6c8ef421dba263aff68739ce00ed80fd0022ef92d3488f76deb62bdef7bea6026f22a1d25aa2a92d124414a8021fe0c174b9803e6bb5fad75e186a946a17280770f1243f4387446ccceb2222a965cc30b3929
e1 = 17
e2 = 65537

with open("flag.enc1","rb") as f1, open("flag.enc2", "rb") as f2:
    c1 = bytes_to_long(f1.read())
    c2 = bytes_to_long(f2.read())

#--------common modulus--------#

r, s, gcd = gcdex(e1, e2)
r = int(r)
s = int(s)

# test if e1 and e2 are coprime
if gcd != 1:
    print("e1 and e2 must be coprime")
    exit()

m = (pow(c1, r, N) * pow(c2, s, N)) % N
flag = long_to_bytes(m)

print(flag)
```

Run the script and grab your flag.

