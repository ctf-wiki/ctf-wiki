[EN](./rsa_complex.md) | [ZH](./rsa_complex-zh.md)
# RSA Complex topic


## 2018 Tokyo Western Mixed Cipher



The information given by the title is as follows:




- The length of time each interaction can last is approximately 5 minutes
- n is a certain 1024 bit in each interaction, but unknown, e is 65537
- Encrypted flag with aes, neither key nor IV
- Each time the key is fixed, but the IV will be random each time
- You can use rsa and aes for encryption with the encrypt function, where each encryption will randomly random es of aes
- You can use decrypt to decrypt random ciphertext, but only know what the last byte is.
- You can use the print_flag to get the flag ciphertext
- sa encrypted aes key can be obtained using print_key


This topic looks like a topic, but in fact it is 3 topics, which need to be solved step by step. Before that, we are ready to interact with the function


```python

def get_enc_key(io):

    io.read_until("4: get encrypted keyn")

io.writeline ( &quot;4&quot;)
    io.read_until("here is encrypted key :)n")

c = int (io.readline () [: - 1], 16)
    return c



def encrypt_io (io, p):
    io.read_until("4: get encrypted keyn")

io.writeline ( &quot;1&quot;)
    io.read_until("input plain text: ")

    io.writeline(p)

    io.read_until("RSA: ")

rsa_c = int (io.readline () [: - 1], 16)
    io.read_until("AES: ")

    aes_c=io.readline()[:-1].decode("hex")

    return rsa_c,aes_c



def decrypt_io (io, c):
    io.read_until("4: get encrypted keyn")

io.writeline ( &quot;2&quot;)
    io.read_until("input hexencoded cipher text: ")

    io.writeline(long_to_bytes(c).encode("hex"))

    io.read_until("RSA: ")

    return io.read_line()[:-1].decode("hex")

```



### GCD attack n


In the first step, we need to calculate the n that is not given, because we can use the encrypt function to rsa encrypt the plaintext x we input, then we can use the nature of the divisibility to calculate n.


```python

Because x ^ e = c mod n
So n | x ^ e - c
```

We can construct enough x to calculate the most x ^ e - c to calculate the greatest common divisor and get n.


```

def get_n(io):

    rsa_c,aes_c=encrypt_io(io,long_to_bytes(2))

    n=pow(2,65537)-rsa_c

    for i in range(3,6):

        rsa_c, aes_c = encrypt_io(io, long_to_bytes(i))

        n=primefac.gcd(n,pow(i,65537)-rsa_c)

    return n

```



Can use encryption to check


```python

def check_n (io, n):
rsa_c, aes_c = encrypt_io (io, &quot;123&quot;)
    if pow(bytes_to_long("123"), e, n)==rsa_c:

        return True

    else:

        return False

```



### RSA parity oracle



Using the last byte of leave, we can choose to ciphertext attack, use RSA parity oracle to reply to the key of aes


```python

def guess_m(io,n,c):

k = 1
    lb=0

ub = n
    while ub!=lb:

Print LB, UB
        tmp = c * gmpy2.powmod(2, k*e, n) % n

        if ord(decrypt_io(io,tmp)[-1])%2==1:

lb = (lb + ub) / 2
        else:

UB = (Ib + UB) / 2
k + = 1
print ub, len (long_to_bytes (ub))
    return ub

```



### PRNG Predict


Here we can decrypt the contents of the 16 bytes of the flag, but the first 16 bytes without the IV can not be decrypted. At this point we can find that the random number used by IV generation uses getrandbits, and we can get enough random numbers, then we can make the PRNG prediction, and then get the random number directly.


Here I use a ready-made java for Predict of PRNG.


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





breaking (scarring);


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



Wrote a python and call java directly


```

from Crypto.Util.number import long_to_bytes,bytes_to_long






def encrypt_io (io, p):
    io.read_until("4: get encrypted keyn")

io.writeline ( &quot;1&quot;)
    io.read_until("input plain text: ")

    io.writeline(p)

    io.read_until("RSA: ")

rsa_c = int (io.readline () [: - 1], 16)
    io.read_until("AES: ")

    aes_c=io.readline()[:-1].decode("hex")

    return rsa_c,aes_c

import subprocess

import random

def get_iv(io):

rsa_c, aes_c = encrypt_io (io, &quot;1&quot;)
    return bytes_to_long(aes_c[0:16])

def splitInto32(w128):

    w1 = w128 & (2**32-1)

    w2 = (w128 >> 32) & (2**32-1)

w3 = (w128 &gt;&gt; 64) &amp; (2 ** 32-1)
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



The overall attack code is as follows:


```python

from zio import *

import import
from Crypto.Util.number import long_to_bytes,bytes_to_long

target=("crypto.chal.ctf.westerns.tokyo",5643)

e = 65537


def get_enc_key(io):

    io.read_until("4: get encrypted keyn")

io.writeline ( &quot;4&quot;)
    io.read_until("here is encrypted key :)n")

c = int (io.readline () [: - 1], 16)
    return c



def encrypt_io (io, p):
    io.read_until("4: get encrypted keyn")

io.writeline ( &quot;1&quot;)
    io.read_until("input plain text: ")

    io.writeline(p)

    io.read_until("RSA: ")

rsa_c = int (io.readline () [: - 1], 16)
    io.read_until("AES: ")

    aes_c=io.readline()[:-1].decode("hex")

    return rsa_c,aes_c



def decrypt_io (io, c):
    io.read_until("4: get encrypted keyn")

io.writeline ( &quot;2&quot;)
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



def check_n (io, n):
rsa_c, aes_c = encrypt_io (io, &quot;123&quot;)
    if pow(bytes_to_long("123"), e, n)==rsa_c:

        return True

    else:

        return False





import gmpy2

def guess_m(io,n,c):

k = 1
    lb=0

ub = n
    while ub!=lb:

Print LB, UB
        tmp = c * gmpy2.powmod(2, k*e, n) % n

        if ord(decrypt_io(io,tmp)[-1])%2==1:

lb = (lb + ub) / 2
        else:

UB = (Ib + UB) / 2
k + = 1
print ub, len (long_to_bytes (ub))
    return ub





io = zio(target, timeout=10000, print_read=COLORED(NONE, 'red'),print_write=COLORED(NONE, 'green'))

n=get_n(io)

print check_n (io, n)
c=get_enc_key(io)

print len (decrypt_io (io, c)) == 16




m=guess_m(io,n,c)

for i in range(m - 50000,m+50000):

    if pow(i,e,n)==c:

aeskey = i
        print long_to_bytes(aeskey)[-1]==decrypt_io(io,c)[-1]

        print "found aes key",hex(aeskey)



import fuck_r
next_iv=fuck_r.get_state(io)

print "##########################################"

print next_iv

print aeskey

io.interact ()
```





## 2016 ASIS Find the flag



Here we take the example of Find the flag in the ASIS 2016 online game.


The file is extracted and has a ciphertext, a public key, and a py script. Take a look at the public key.


```bash

➜  RSA openssl rsa -pubin -in pubkey.pem -text -modulus

Public-Key: (256 bit)

Modulus:

00: d8: e2: 4c: 12: b7: b9: 9e: fe: 0a: 9b: c0: 4a:
f5: 8a: 2a: 94: 42: 69: b4: 92: b7: 37: 6d: f1: 29:
20: 61: b9
Exponent: 12405943493775545863 (0xac2ac3e0ca0f5607)

Modulus=D8E24C12B7B99EFE0A9BC04A6A3DF58A2A944269B492B7376DF129023F2061B9

```



Such a small $N$, first break it down.


```

p = 311155972145869391293781528370734636009

q = 315274063651866931016337573625089033553

```



Look at the py script again.


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

phi = (p - 1) * (q - 1)
d = gmpy.invert (e, phi)
            pubkey = RSA.construct((long(n), long(e)))

            key = PKCS1_v1_5.new(pubkey)

            enc = key.encrypt(msg).encode('base64')

            return enc

        except:

            p = gmpy.next_prime(p**2 + q**2)

            q = gmpy.next_prime(2*p*q)

e = gmpy.next_prime (e ** 2)


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



The logic is very simple, read the flag and repeat 30 times for the ciphertext. Randomly take $p$ and $q$, generate a public key, write `pubkey.pem`, encrypt it with the `ext_rsa_encrypt` function in the script, and finally write the ciphertext to `flag.enc`.


Try decryption, suggest that the ciphertext is too long, and then look at the encryption function. When the encryption fails, the function will jump to the exception handling and re-take the larger $p$ and $q$ with a certain algorithm until the encryption succeeds.


Then we just need to write a corresponding decryption function.


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

phi = (p - 1) * (q - 1)
d = gmpy.invert (e, phi)
            privatekey = RSA.construct((long(n), long(e), long(d), long(p), long(q)))

            key = PKCS1_v1_5.new(privatekey)

de_error = &#39;&#39;
            enc = key.decrypt(msg.decode('base64'), de_error)

            return enc

        except Exception as error:

            print error

            p = gmpy.next_prime(p**2 + q**2)

            q = gmpy.next_prime(2*p*q)

e = gmpy.next_prime (e ** 2)


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



Get the flag


```

ASIS {F4ct0R__N_by_it3rat! Ng!}
```



## SCTF RSA1



Here we take SCTF RSA1 as an example. After decompressing the compressed package, we get the following file.


```shell

➜ level0 git: (master) ✗ ls -al
Total dosage 4drwxrwxrwx 1 root root    0 7月  30 16:36 .

drwxrwxrwx 1 root root    0 7月  30 16:34 ..

-rwxrwxrwx 1 root root  349 5月   2  2016 level1.passwd.enc

-rwxrwxrwx 1 root root 2337 5月   6  2016 level1.zip

-rwxrwxrwx 1 root root  451 5月   2  2016 public.key

```



Try to unzip the level1.zip now requires a password. Then according to level1.passwd.enc, we should decrypt the file to get the corresponding password. View public key


```shell

➜  level0 git:(master) ✗ openssl rsa -pubin -in public.key -text -modulus 

Public-Key: (2048 bit)

Modulus:

    00:94:a0:3e:6e:0e:dc:f2:74:10:52:ef:1e:ea:a8:

    89:d6:f9:8d:01:11:51:db:5e:90:92:48:fd:39:0c:

70: 87: 24: D8: 98: 3C: F3: 33: 1c: BA: 5: 61: c2: EC: 2c:
    5a:f1:5e:65:b2:b2:46:91:56:b6:19:d5:d3:b2:a6:

bb: a3: 7d: 56: 93: 99: 4d: 7e: 4c: 2f: aa: 60: 7b: 3e: c8:
    fc:90:b2:00:62:4b:53:18:5b:a2:30:10:60:a8:21:

ab: 61: 57: d7: e7: cc: 67: 1b: 4d: cd: 66: 4c: 7d: f1: 1a:
    2a:1d:5e:50:80:c1:5e:45:12:3a:ba:4a:53:64:d8:

(A5: 1: 84: 4a: a: 5c: 55: 02: e8: 8e: 56: 4d: 38: 70: a5:
16: 36: d3: bc: 14: 3e: 2f: ae: 2f: 31: 58: ba: 00: ab: ac:
    c0:c5:ba:44:3c:29:70:56:01:6b:57:f5:d7:52:d7:

31: 56: 0b: ab: 0a: e6: 8d: ad: 08: 22: a9: 1f:
cc: 01: 4c: 12: d2: ab: a3: a5: 97: e5: 10: 49: 19: 7f:
    d9:3b:c5:53:53:71:00:18:60:cc:69:1a:06:64:3b:

86: 94: 70: a9: yes: 82: fc: 54: 6b: 06: 23: 43:
eb: b6: 1b: 91: 35: 5e: 53: a6: e5: d8: 9a: 84:
b8: 9f: 63: bc: 70: 06: 2d: 59: d8: 62: a5: fd: 5c: ab: 06:
    68:81

Exponent: 65537 (0x10001)

Modulus=94A03E6E0EDCF2741052EF1EEAA889D6F98D011151DB5E909248FD390C708724D8983CF3331CBAC561C2CE2C5AF15E65B2B2469156B619D5D3B2A6BBA37D5693994D7E4C2FAA607B3EC8FC90B200624B53185BA2301060A821AB6157D7E7CC671B4DCD664C7DF11A2A1D5E5080C15E45123ABA4A5364D8721F844AAE5C5502E88E564D3870A51636D3BC143E2FAE2F3158BA00ABACC0C5BA443C297056016B57F5D752D731560BAB0AE68DAD0822A91FCB6E49CC014C12D2ABA3A597E51049197F69D93BC5535371001860CC691A06643B869470A9DA82FC546B0623432DB020EBB61B91355E53A6E5D89A84BB3046B89F63BC70062D59D862A5FD5CAB066881

writing RSA key

-----BEGIN PUBLIC KEY-----

MIIBIjANBgkqkkiG9w0BAQEFAAOCAQ8AMIIBCgKCQQll + bg7c8nQQUu8e6qiJ
1vmNARFR216Qkkj9OQxwhyTYmDzzMxy6xWHCzixa8V5lsrJGkVa2GdXTsqa7o31W

k5lNfkwvqmB7Psj8kLIAYktTGFuiMBBgqCGrYVfX58xnG03NZkx98RoqHV5QgMFe

RRI6ukpTZNhyH4RKrlxVAuiOVk04cKUWNtO8FD4vri8xWLoAq6zAxbpEPClwVgFr

V / XXUtcxVgurCuaNrQgiqR / LbknMAUwS0qujpZflEEkZf2nZO8VTU3EAGGDMaRoG
ZDuGlHCp2oL8VGsGI0MtsCDrthuRNV5TpuXYmoS7MEa4n2O8cAYtWdhipf1cqwZo

DOWNLOAD
-----END PUBLIC KEY-----

```



It is found that although it is 2048 bits, it is obvious that the modulus is not so long. Try to decompose and get


```

p=250527704258269

q=74891071972884336452892671945839935839027130680745292701175368094445819328761543101567760612778187287503041052186054409602799660254304070752542327616415127619185118484301676127655806327719998855075907042722072624352495417865982621374198943186383488123852345021090112675763096388320624127451586578874243946255833495297552979177208715296225146999614483257176865867572412311362252398105201644557511678179053171328641678681062496129308882700731534684329411768904920421185529144505494827908706070460177001921614692189821267467546120600239688527687872217881231173729468019623441005792563703237475678063375349

```



Then you can construct and decrypt, the code is as follows


```python

from Crypto.PublicKey import RSA

import gmpy2

from base64 import b64decode

p = 250527704258269

q = 74891071972884336452892671945839935839027130680745292701175368094445819328761543101567760612778187287503041052186054409602799660254304070752542327616415127619185118484301676127655806327719998855075907042722072624352495417865982621374198943186383488123852345021090112675763096388320624127451586578874243946255833495297552979177208715296225146999614483257176865867572412311362252398105201644557511678179053171328641678681062496129308882700731534684329411768904920421185529144505494827908706070460177001921614692189821267467546120600239688527687872217881231173729468019623441005792563703237475678063375349

e = 65537
n = p * q





def getprivatekey(n, e, p, q):

Phin = (p - 1) * (q - 1)
d = gmpy2.invert (e, phin)
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



Found wrong


```shell

➜  level0 git:(master) ✗ python exp.py

A bunch of garbled. .


```



At this time, we must consider other situations. Generally speaking, the RSA implemented in reality will not directly use the original RSA, and will add some padding such as OAEP. Let&#39;s try and modify the code here.


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



Sure enough, get


```shell

➜  level0 git:(master) ✗ python exp.py

FaC5ori1ati0n_aTTA3k_p_tOO_sma11

```



Get the decompression password. Go ahead and look at the public key in level1


```shell

➜  level1 git:(master) ✗ openssl rsa -pubin -in public.key -text -modulus

Public-Key: (2048 bit)

Modulus:

00: c3: 26: 59: 69: e1: ed: 74: d2: e0: b4: 9a: d5: 6a:
2f: 2a: 9e: c3: 71: ff: 13: 4b: 10: 37: c0: 6f: 56: 19: 34:
c5: cb: 1f: 6d: c0: e3: 57: 3b: 47: c4:
    11:11:78:d4:ee:4f:e8:99:2b:15:cb:cb:d7:73:e4:

    f9:a6:28:20:fd:db:8c:ea:16:ed:67:c2:48:12:6e:

4b: 01: 53: 4a: 67: cb: 22: 23: 3b: 34: 2e: af: 13: ef: 93:45: 16: 2b: 00: 9f: e0: 4b: d1: 90: c9: 2c:
3f: d7: ee: 40: f5: aa: 8c: e9: c2: 7b: f4: 36:
e3: 38: 9d: 04: 50: db: a9: b7: 3f: 4b: 2a: d6:
87: 2a: eb: 74: 35: 98: 6a: 9c: e4: 52: cb: 93: 78:
    39:83:f3:0c:d1:65:1e:66:9c:40:56:06:0d:58:fc:

41: 64: 5e: 06: yes: 83: d0: 3b: 06: 42: 70:
    54:35:53:ce:de:79:4a:bf:f5:3b:e5:53:7f:6c:18:

12: 67: a9: de: 37: 7d: 44: 65: 5e: 68: 0: 78: 39: 3d: bb:
00: 22: 35: 0e: a3: 94: e6: 94: 15: 1a: 3d: 39: c7: 50: 0e:
b1: 64: a5: 29: 40: 69: 94: b0: 0d: 1a: ea: 9a:
And it&#39;s not like that.
3e: 7d
Exponent: 65537 (0x10001)

Modulus=C3265969E1ED74D2E0B49AD56A7C2F2A9EC371FF134B1037C06F561934C5CB1F6DC0E3573B47C4763E21A3B0111178D4EE4FE8992B15CBCBD773E4F9A62820FDDB8CEA16ED67C248126E4B01534A67CB22233B342EAF13EF9345162B009FE04BD190C92C279A34C33FD7EE40F5825039AA8CE9C27BF436E3389D0450DBA9B73F4B2AD68A2A5C872AEB7435986A9CE452CB9378D2DA3983F30CD1651E669C4056060D58FC41645E06DA83D03B064270DA3853E0543553CEDE794ABFF53BE5537F6C181267A9DE377D44655E680A78393DBB0022350EA394E694151A3D39C7500EB164A529A36941406994B00D1AEA9A122750EE1E3A19B72970B46D1E9D613E7D

writing RSA key

-----BEGIN PUBLIC KEY-----

MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwyZZaeHtdNLgtJrVan
Kp7Dcf8TSxA3wG9WGTTFyx9twONXO0fEdj4ho7AREXjU7k/omSsVy8vXc+T5pigg

/duM6hbtZ8JIEm5LAVNKZ8siIzs0Lq8T75NFFisAn+BL0ZDJLCeaNMM/1+5A9YJQ

OaqM6cJ79DbjOJ0EUNuptz9LKtaKKlyHKut0NZhqnORSy5N40to5g/MM0WUeZpxA

VgYNWPxBZF4G2oPQOwZCcNo4U + BUNVPO3nlKv / U75VN / bBgSZ6neN31EZV5oCng5
PbsAIjUOo5TmlBUaPTnHUA6xZKUpo2lBQGmUsA0a6poSJ1DuHjoZtylwtG0enWE+

FQIDAQAB
-----END PUBLIC KEY-----



```



It seems that it is still not very big, break down again, and then try the factordb not, try yafu. The result is broken down.


```shell

P309 = 156956618844706820397012891168512561016172926274406409351605204875848894134762425857160007206769208250966468865321072899370821460169563046304363342283383730448855887559714662438206600780443071125634394511976108979417302078289773847706397371335621757603520669919857006339473738564640521800108990424511408496383



P309 = 156956618844706820397012891168512561016172926274406409351605204875848894134762425857160007206769208250966468865321072899370821460169563046304363342283383730448855887559714662438206600780443071125634394511976108979417302078289773847706397371335621757603520669919857006339473738564640521800108990424511408496259



```



It can be found that these two numbers are very similar, and it may be that factordb does not implement this type of decomposition.


Then the following operation is similar to level0. Just this time it is just a direct decryption, no filling, try to fill but wrong


Get the password `fA35ORI11TLoN_Att1Ck_cL0sE_PrI8e_4acTorS`. Continue to the next step to view the public key


```shell

➜  level2 git:(master) ✗ openssl rsa -pubin -in public.key -text -modulus

Public-Key: (1025 bit)

Modulus:

01: ba: 0c: c2: 45: b4: 5c: e5: b5: f5: 6c: d5: ca: a5: 90:
    c2:8d:12:3d:8a:6d:7f:b6:47:37:fb:7c:1f:5a:85:

    8c:1e:35:13:8b:57:b2:21:4f:f4:b2:42:24:5f:33:

f7: 2c: 2c: 0d: 21: c2: 4a: d4: c5: f5: 09: 94: c2: 39: 9d:
73: e5: 04: a2: 66: 1d: 9c: 4b: 99: d5: 38: 44:
cd: 12: a4: d0: 16: 79: f0: ac: 75: f9: a4: ea: a8: 7c: 32:
16: 9: 17: d7: 7d: 80: f: 60: 29: 64: c7: ea: 50: 30: 63:
    76:59:c7:36:5e:98:d2:ea:5b:b3:3a:47:17:08:2d:

d5: 24: 7d: 4f: a7: a1: f0: d5: 73
Exponent:

    01:00:8e:81:dd:a0:e3:19:28:e8:ee:51:11:08:c7:

    50:5f:61:31:05:d2:e2:ff:9b:83:71:e4:29:c2:dd:

    92:70:65:d4:09:6d:58:c3:76:31:07:f1:d4:fc:cf:

2d: b3: 0a: 6d: 02: 7c: 56: 61: 7c: 7e: db:
28: 66: 9e: fb: 3d: 2f: 2c: 20: 59: 3c: 21: ef: ff: 31: 00:
6a: 68: 4a: 0a: 4c: 1a: a7: 09: d5: 48: 98: c8:
    1f:cf:fb:dd:f7:9c:ae:ae:0b:15:f4:b2:c7:e0:bc:

ba: 31: 4f: 5e: 07: 83: to: 0e: 7f: b9: 82: a4: d2: 01: ago:
68: 29: 6d: 66: 7c: cf: 57: b9: 4b
Modulus=1BA0CC245B45CE5B5F56CD5CAA590C28D123D8A6D7FB64737FB7C1F5A858C1E35138B57B2214FF4B242245F33F72C2C0D21C24AD4C5F50994C2399D73E504A2661D9C4B99D53844AB13D9CD12A4D01679F0AC75F9A4EAA87C32169A17D77D80FD602964C7EA5030637659C7365E98D2EA5BB33A4717082DD5247D4FA7A1F0D573

writing RSA key

-----BEGIN PUBLIC KEY-----

MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKBgQG6DMJFtFzltfVs1cqlkMKN
Ej2KbX+2Rzf7fB9ahYweNROLV7IhT/SyQiRfM/csLA0hwkrUxfUJlMI5nXPlBKJm

HZxLmdU4RKsT2c0SpNAWefCsdfmk6qh8MhaaF9d9gP1gKWTH6lAwY3ZZxzZemNLq

W7M6RxcILdUkfU+nofDVcwKBgQEAjoHdoOMZKOjuUREIx1BfYTEF0uL/m4Nx5CnC

3ZJwZdQJbVjDdjEH8dT8zy2zCm0CfFZhfL5 + C37ZIihmnvs9LywgWTwh7 / 8xAGr7
p2jeSgpMGqcJ1UiYyB/P+933nK6uCxX0ssfgvLoxT14Hg60Of7mCpNIB+mgpbWZ8

z1e5Sw==

-----END PUBLIC KEY-----



```



It is found that the private keys e and n are almost the same size. Considering that d is relatively small, use Wiener&#39;s Attack. Get d, of course, you can verify it again.


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



At this time we decrypt the ciphertext and decrypt the code as follows


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



Use the string `wIe6ER1s_1TtA3k_e_t00_larg3` at the end to decrypt the compressed package, taking care to remove B. At this point, all decryption ends and a flag is obtained.


## 2018 WCTF RSA


The basic description of the topic is


```

Description:

Encrypted message for user "admin":



<<<320881698662242726122152659576060496538921409976895582875089953705144841691963343665651276480485795667557825130432466455684921314043200553005547236066163215094843668681362420498455007509549517213285453773102481574390864574950259479765662844102553652977000035769295606566722752949297781646289262341623549414376262470908749643200171565760656987980763971637167709961003784180963669498213369651680678149962512216448400681654410536708661206594836597126012192813519797526082082969616915806299114666037943718435644796668877715954887614703727461595073689441920573791980162741306838415524808171520369350830683150672985523901>>>



admin public key:



n = 483901264006946269405283937218262944021205510033824140430120406965422208942781742610300462772237450489835092525764447026827915305166372385721345243437217652055280011968958645513779764522873874876168998429546523181404652757474147967518856439439314619402447703345139460317764743055227009595477949315591334102623664616616842043021518775210997349987012692811620258928276654394316710846752732008480088149395145019159397592415637014390713798032125010969597335893399022114906679996982147566245244212524824346645297637425927685406944205604775116409108280942928854694743108774892001745535921521172975113294131711065606768927

e = 65537


Service: http://36.110.234.253



```



There is no way to get the binary online now. The binary obtained is now downloaded. We need to log in to the user&#39;s admin to download the corresponding generator.


By simply reversing this generator, we can see that this program works like this.


- Iteratively decrypts the data after a certain fixed location** with a user-specified license (32 bytes), each set of 32 bytes, different from the key or the result.
- The key is generated by
    - $k_1=key$

    - $k_2 =sha256(k_1)$

    - ...

    - $k_n=sha256(k_{n-1})$



Among them, the fixed position is the position where the `ENCRYPTED` appears for the second time in the source file `generator`, and then offset by 32 bytes.


```python

    _ENCRYPT_STR = ENCRYPTED_STR;

    v10 = 0;

    ENCRYPTED_LEN = strlen(ENCRYPTED_STR);

    do

    {

      do

++ v9;
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

fwrite (v11, 1u, len, v14);
      fclose(v14);

      sprintf(byte_406020, "out.exe %s", argv[1]);

      system(byte_406020);

    }

```



At the same time, we need to ensure that the hash of the generated file is exactly the specified value. Since the file is an exe file at the end, we can think that the last file header is the standard exe file, so we don&#39;t need to know the original. The license file, and then we can write a python script to generate the exe.


In the generated exe, we analyze the basic flow of the program as


Read the license
2. Use the license as the seed to generate pq separately.
3. Use p,q to generate n,e,d.


The vulnerability appears on the method of generating p, q, and the method of generating p and q is similar.


If we carefully analyze the function of generating prime numbers, we can see that each prime number is generated in two parts.


1. Generate 512 bits in the left half.
2. Generate the right half of the 512 bits.
3. The left and right 1024 bits are determined to determine whether it is a prime number. If the prime number is successful, it is not a prime number and continues to be generated.


The way to generate each part is the same, in the way


```python

sha512 (const1 | const2 | const3 | const4 | const5 | const6 | const7 | const8 | v9)
v9 = r% 1000000007
```



Only v9 will change, but its scope is fixed.


So if we say p,q is


$p=a*2^{512}+b$



$q=c*2^{512}+d$



Then


$ n = pq = a * 2 ^ {1024} + (ad + bc) * 2 ^ {512} + bd $


Then


$ N \ equiv bd \ way 2 ^ {512} $


And since p and q are generated, a, b, c, and d have only 1000000007 possibilities.


Furthermore, we can enumerate all the possibilities, first calculate the possible set of b as S, and we use the intermediate encounter attack to calculate


$n/d \equiv b \bmod 2^{512}$



Since b and d are both the mantissa of p, they must not be a multiple of 2, and there must be an inverse.


Although this can be done, however, we can simply calculate the storage space.


$64*1000000007 / 1024 / 1024 / 1024=59$



That means 59 G is needed, too big, so we still need to think further


$ N \ equiv bd \ way 2 ^ {64} $


In this way, our memory demand dropped to around 8 G in an instant. We still use the enumeration method to perform the operation.


Second, we can&#39;t use python, python takes up too much space, so it needs to be written in c/c++.


Enumerate all possible d to calculate the corresponding value $n/d$ If the corresponding value is in set S, then we can think of finding a pair of legal b and d, so we can recover half of p and q.

After that, we


$ B = n ^ {1024} and * 2 + (a + b) * 2 ^ {$ 512}


Can get


$ \ Frac {n} {2-b ^} = {512} and {512} * 2 ^ + b + for $


$ \ Frac {n} {2-bd} ^ {512} \ equiv ad + bc \ way 2 ^ {512} $


Similarly, we can calculate a and c so that we can fully recover p and q.


In the process of solving the concrete, when we find part of p and q, we can find that because it is modulo $2^{64}$, there may be a collision (but in fact, one is p, the other is q, just symmetry.). Below we find the v9 corresponding to b.


**Note: The space enumerated here takes up approximately 11 Gs (including the index), so choose the appropriate location. **


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



In fact, after we actually get a part of p or q, the other part can be obtained by violent enumeration, because the calculation is almost the same, and the final result is


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

➜ 2018-WCTF-rsa go to: (master) ✗ python
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



Finally we got the flag.


**Please refer to the ctf-challenge repository for detailed utilization code. **


Related compilation instructions need to link related libraries.


```shell

g++  exp2.cpp -std=c++11 -o main2 -lgmp -lcrypto -pthread

```



## Reference


- https://upbhack.de/posts/wctf-2018-writeup-rsa/
