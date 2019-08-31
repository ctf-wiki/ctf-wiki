[EN](./rsa_chosen_plain_cipher.md) | [ZH](./rsa_chosen_plain_cipher-zh.md)
# RSA Selecting a clear ciphertext attack


## Select plaintext attack


Here is an example, if we have an encryption oracle, but we don&#39;t know n and e, then


1. We can get n by encrypting oracle.
2. When e is small ( $e&lt;2^{64}$), we can use the *Pollard&#39;s kangaroo algorithm* algorithm to get e. This is more obvious.


We can encrypt 2, 4, 8, and 16. Then we can know


$ C_2 = 2 ^ {e} \ n $ way


C_4 = $ 4 ^ {e} \ n $ way


$ C_8 = 8 ^ {e} \ n $ way


Then


$c_2^2 \equiv c_4 \bmod n$



$c_2^3 \equiv c_8 \bmod n$



Therefore


$c_2^2-c_4=kn$



$ c_2 ^ 3-c_8 = tn $


We can find the greatest common factor of kn and tn, and the big probability is n. We can also construct more examples to find n more deterministically.


## Any ciphertext decryption


Suppose Alice creates the ciphertext $C = P^e \bmod n$ and sends C to Bob, and assuming we want to decrypt any ciphertext encrypted by Alice, instead of just decrypting C, then we can intercept C, and use the following steps to find P:


1. Select any $X\in Z_n^{*}$, ie X and N.
2. Calculate $Y=C \times X^e \bmod n$
3. Since we can choose to ciphertext attack, we find the decryption result corresponding to Y$Z=Y^d$
4. Then, since $Z=Y^d=(C \times X^e)^d=C^d X=P^{ed} X= PX\bmod n$, since X and N are mutually prime, we are very It is easy to find the corresponding inverse element, and then you can get P


## RSA parity oracle



Suppose there is currently an Oracle that decrypts a given ciphertext and checks the parity of the decrypted plaintext and returns the corresponding value based on parity, such as 1 for odd numbers and 0 for even numbers. Then given an encrypted ciphertext, we only need log(N) times to know the plaintext message corresponding to this ciphertext.


### Principle


Hypothesis


P $ C = e ^ \ N $ way


The first time we can send to the server


$ C * 2 ^ = e (2P) e ^ \ N $ way


The server will calculate


2P $ \ N $ way


Here


- 2P is an even number and its power is even.
- N is an odd number because it is multiplied by two large prime numbers.


Then




- The server returns an odd number, ie $2P \bmod N$ is an odd number, indicating that 2P is greater than N, and an odd number of Ns is subtracted, and because $2P&lt;2N$, an N is subtracted, ie $\frac{N }{2} \leq P &lt; N$, we can also consider rounding down.
- If the server returns an even number, then 2P is less than N. That is, $0\leq P &lt; \frac{N}{2}$, we can also round down.


Here we use mathematical induction, which assumes that at the ith time, $\frac{xN}{2^{i}} \leq P &lt; \frac{xN+N}{2^{i}}$




Further, at the i+1th time, we can send


$C*2^{(i+1)e}$



The server will calculate


$ 2 ^ {i + 1} P \ way N = 2 ^ {i + 1} P $ kN


$0 \leq 2^{i+1}P-kN<N$ 



$ \ frac {kN} {2 ^ {i + 1}} \ leq P &lt;\ frac {kN + N}


According to the result of the ith


$\frac{2xN}{2^{i+1}} \leq P < \frac{2xN+2N}{2^{i+1}}$



Then


- If the server returns an odd number, then k must be an odd number, k=2y+1, then $\frac{2yN+N}{2^{i+1}} \leq P &lt; \frac{2yN+2N}{2^ {i+1}}$. At the same time, since P necessarily exists, the range obtained by the i+1 and the range obtained by the i-th must have an intersection. So y must be equal to x.
- If the server returns an even number, then k must be an even number, k=2y, where y must also be equal to x, then $\frac{2xN}{2^{i+1}} \leq P &lt; \frac{2xN+ N}{2^{i+1}}$


Further we can conclude


```c

lb = 0

ub = N
if server returns 1

lb = (lb + ub) / 2
else:

UB = (Ib + UB) / 2
```



Although it is divisible, that is, it is rounded down, but it does not matter that we have analyzed this problem at the beginning.


### 2018 Google CTF Perfect Secrecy



Here is an example of the 2018 Google CTF topic.


```python

#!/usr/bin/env python3

import sys

import random



from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.backends import default_backend





def ReadPrivateKey(filename):

  return serialization.load_pem_private_key(

      open(filename, 'rb').read(), password=None, backend=default_backend())





def RsaDecrypt(private_key, ciphertext):

  assert (len(ciphertext) <=

          (private_key.public_key().key_size // 8)), 'Ciphertext too large'
  return pow(

      int.from_bytes(ciphertext, 'big'),

      private_key.private_numbers().d,

      private_key.public_key().public_numbers().n)





def Challenge(private_key, reader, writer):

  try:

    m0 = reader.read(1)

    m1 = reader.read(1)

    ciphertext = reader.read(private_key.public_key().key_size // 8)

    dice = RsaDecrypt(private_key, ciphertext)

    for rounds in range(100):

      p = [m0, m1][dice & 1]

k = random.randint (0, 2)
c = (word (p) + k)% 2
      writer.write(bytes((c,)))

    writer.flush()

    return 0



  except Exception as e:

    return 1





def main():

  private_key = ReadPrivateKey(sys.argv[1])

  return Challenge(private_key, sys.stdin.buffer, sys.stdout.buffer)





if __name__ == '__main__':

  sys.exit(main())

```



As can be seen


- We can give the server two numbers, and the server will decide which one to use based on the decrypted ciphertext content.
- The server will use `random.randint(0, 2)` to generate a random number and output the associated random 01 byte c.


At first glance, it seems to be completely random. Check out `random.randint(0, 2)` to know that the generated random number is bounded, so the probability of generating an even number is greater than the probability of generating an odd number, then c and p The probability of the same parity is 2/3. Furthermore, by setting m0 and m1, we can know whether the last digit of the decrypted ciphertext is 0 or 1. This is actually the RSA parity oracle.


Exp is as follows


```python

import gmpy2

from pwn import *

encflag = open('./flag.txt').read()

encflag = encflag.encode('hex')

encflag = int(encflag, 16)

#context.log_level = 'debug'

m = ['\x00', '\x07']

n = 0xDA53A899D5573091AF6CC9C9A9FC315F76402C8970BBB1986BFE8E29CED12D0ADF61B21D6C281CCBF2EFED79AA7DD23A2776B03503B1AF354E35BF58C91DB7D7C62F6B92C918C90B68859C77CAE9FDB314F82490A0D6B50C5DC85F5C92A6FDF19716AC8451EFE8BBDF488AE098A7C76ADD2599F2CA642073AFA20D143AF403D1

e = 65537
flag = ""







def guessvalue(cnt):

    if cnt[0] > cnt[1]:

        return 0

    return 1





i = 0

while True:

    cnt = dict()

cnt [0] = cnt [1] = 0
    p = remote('perfect-secrecy.ctfcompetition.com', 1337)

    p.send(m[0])

    p.send(m[1])

    tmp = pow(2, i)

    two_inv = gmpy2.invert(tmp, n)

    two_cipher = gmpy2.powmod(two_inv, e, n)

    tmp = encflag * two_cipher % n

    tmp = hex(tmp)[2:].strip('L')

    tmp = '0' * (256 - len(tmp)) + tmp

    tmp = tmp.decode('hex')

assert (len (tmp) == 128)
    p.send(tmp)

    #print tmp

    data = ""

    while (len(data) != 100):

        data += p.recv()

    for c in data:

cnt [U8 (c)] + = 1
    p.close()

    flag = str(guessvalue(cnt)) + flag

    print i, flag

    i += 1

```



Results are as follows


```shell

6533021797450432625003726192285181680054061843303961161444459679874621880787893445342698029728203298974356255732086344166897556918532195998159983477294838449903429031335408290610431938507208444225296242342845578895553611385588996615744823221415296689514934439749745119968629875229882861818946483594948270 6533021797450432625003726192285181680054061843303961161444459679874621880787893445342698029728203298974356255732086344166897556918532195998159983477294838449903429031335408290610431938507208444225296242342845578895553611385588996615744823221415296689514934439749745119968629875229882861818946483594948270

```



After decoding, you can get flag


```shell

CTF {h3ll0__17_5_m3_1_w45_w0nd3r1n6_1f_4f73r_4ll_7h353_y34r5_y0u_d_l1k3_70_m337}
```



### Title


- 2016 Plaid CTF rabit

- 2016 sharif CTF lsb-oracle-150

- 2018 Backdoor CTF  BIT-LEAKER

- 2018 XMAN trials baby RSA


## RSA Byte Oracle



Suppose there is currently an Oracle that decrypts a given ciphertext and gives the last byte of the plaintext. Then given an encrypted ciphertext, we only need $\log_{256}n$ times to know the plaintext message corresponding to this ciphertext.


### Principle


This is actually an extension of RSA parity Oracle. Since the last byte can be revealed, then the number of times we get the ciphertext corresponding plaintext should be reduced.


Hypothesis


P $ C = e ^ \ N $ way


The first time we can send to the server


C $ 256 * e ^ = (256P) e ^ \ N $ way


The server will calculate

256P $ \ N $ way


Here


- 256P is an even number.
- N is an odd number because it is multiplied by two large prime numbers.


Since P is generally less than N, then $256P \bmod N=256P-kn, k&lt;256$. And for two different $k_1, k_2$, we have


$256P-k_1n \not\equiv 256P-k_2n \bmod 256$



We can use the counter-evidence method to prove the above inequality. At the same time, the last byte of $256P-kn$ is actually $-kn$ obtained in the case of modulo 256. So, in fact, we can first enumerate the last byte in the case of 0~255, construct a mapping table of k and the last byte.


When the server returns the last byte b, we can know k according to the mapping table constructed above, that is, subtract k N, that is, $kN \leq 256 P \leq (k+1)N$.


After that, we use mathematical induction to obtain the range of P, that is, assume that at the ith time, $\frac{xN}{256^{i}} \leq P &lt; \frac{xN+N}{256^{i }}$


Further, at the i+1th time, we can send


$C*256^{(i+1)e}$



The server will calculate


$ 256 ^ {i + 1} P \ way N = 256 ^ {i + 1} P $ kN


$0 \leq 256^{i+1}P-kN<N$ 



$ \ frac {kN} {256} {i + 1}} \ leq P &lt;\ frac {kN + N}


According to the result of the ith


$\frac{256xN}{256^{i+1}} \leq P < \frac{256xN+256N}{256^{i+1}}$



We can assume $k=256y+t$ here, and the t here is what we can get through the mapping table.


 $\frac{256yN+tN}{256^{i+1}} \leq P < \frac{256yN+(t+1)N}{256^{i+1}}$



At the same time, since P necessarily exists, the range obtained by the i+1 and the range obtained by the i-th must have an intersection.


So y must be equal to x.


Further we can summarize this, in the initial case


```

lb = 0

ub = N
```



Suppose the server returns b, then


```c

k = mab [b]
interval = (ub-lb)/256

lb = lb + interval * k

ub = lb + interval

```



### 2018 HITCON lost key



This is a comprehensive topic. First, we don&#39;t give n. We can use the method of selecting a plaintext attack to get n. Of course, we can further obtain e. Finally, the code is as follows.


```python

from pwn import *

import gmpy2

from fractions import Fraction

p = process('./rsa.py')

#p = remote('18.179.251.168', 21700)

#context.log_level = 'debug'

p.recvuntil('Here is the flag!\n')

flagcipher = int(p.recvuntil('\n', drop=True), 16)





def long_to_hex(n):

    s = hex(n)[2:].rstrip('L')

    if len(s) % 2: s = '0' + s

    return s





def send(ch, num):

    p.sendlineafter('cmd: ', ch)

    p.sendlineafter('input: ', long_to_hex(num))

    data = p.recvuntil('\n')

    return int(data, 16)





if __name__ == "__main__":

    # get n

    cipher2 = send('A', 2)

    cipher4 = send('A', 4)

    nset = []

    nset.append(cipher2 * cipher2 - cipher4)



    cipher3 = send('A', 3)

    cipher9 = send('A', 9)

    nset.append(cipher3 * cipher3 - cipher9)

    cipher5 = send('A', 5)

    cipher25 = send('A', 25)

    nset.append(cipher5 * cipher5 - cipher25)

    n = nset[0]

    for item in nset:

        n = gmpy2.gcd(item, n)



    # get map between k and return byte

    submap = {}

    for i in range(0, 256):

        submap[-n * i % 256] = i



    # get cipher256

    cipher256 = send('A', 256)



    back = flagcipher



    L = Fraction(0, 1)

    R = Fraction(1, 1)

    for i in range(128):

        print i

        flagcipher = flagcipher * cipher256 % n

        b = send('B', flagcipher)

        k = submap[b]

        L, R = L + (R - L) * Fraction(k, 256

                                     ), L + (R - L) * Fraction(k + 1, 256)

    low = int(L * n)

    print long_to_hex(low - low % 256 + send('B', back)).decode('hex')

```



## Reference

- https://crypto.stackexchange.com/questions/11053/rsa-least-significant-bit-oracle-attack

- https://pastebin.com/KnEUSMxp
