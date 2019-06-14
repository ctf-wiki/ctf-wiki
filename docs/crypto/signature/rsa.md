[EN](./rsa.md) | [ZH](./rsa-zh.md)
# RSA Digital Signature


## Principle


The principle is similar to RSA encryption, except that the private key is used for encryption, and the encrypted result is used as a signature.


## 2018 Backdoor Awesome mix1



First, you can easily analyze the source code. Here, the program uses RSK signature with PKCS1_V1.5, which will extend the plaintext message. For specific extension rules, please refer to https://www.emc.com/collateral/white-papers/h11300-pkcs -1v2-2-rsa-cryptography-standard-wp.pdf. Here is the corresponding extension script, corresponding to the `from Util import PKCS1_pad as pad` in the title.


```python

def PKCS1_pad(data):

    asn1 = "3021300906052b0e03021a05000414"

ans = asn1 + data
n = len (ans)
return int ((&#39;00&#39; + &#39;01&#39; + &#39;ff&#39; * (1024/8 - n / 2 - 3) + &#39;00&#39; + years), 16)
```



The program wants us to give `n,e` to make the program satisfy


$h(m)^e mod \ n=pad(m)$



Here we already know `h(m), pad(m)`. Obviously if we control `e=1`, then


$h(m)-pad(m)=kn$



Then if we can set k=1, we can get n.


Local deployment `socat TCP4-LISTEN: 12345, fork EXEC:./mix1.py`.


Exp is as follows


```python

from Crypto.Hash import SHA

from pwn import *



from Util import PKCS1_pad



#context.log_level = 'debug'





def main():

    port = 12345

    host = "127.0.0.1"

    p = remote(host, port)

    p.recvuntil('Message   -> ')

    message = p.recvuntil('\n\nSignature -> ', drop=True)

    log.info('message: ' + message)

    signature = p.recvuntil('\n', drop=True)

    log.info('signature: ' + signature)



    h = SHA.new(message)



    m = PKCS1_pad(h.hexdigest())



e = 1
    n = int(signature, 16) - m



    p.sendlineafter('Enter n:', str(n))

    p.sendlineafter('Enter e:', str(e))



    p.interactive()





main()



```



The effect is as follows


```shell

➜  2018-BackdoorCTF-Awesome-mix1 git:(master) python exp.py

[+] Opening connection to 127.0.0.1 on port 12345: Done

[*] message: super important information for admin only

[*] signature: 721af5bd401b5f2aff8e86bf811b827cdb5877ef12202f24fa914a26f235523f80c45fdbf0d3c9fa77278828ddd8ca0551a941bd57c97dd38654692568d1357a49e7a2a284d296508602ead24c91e5aa7f517b9e48422575f0dd373d00f267a206ba164ab104c488268b5f95daf490a048407773d4b1016de8ef508bf1aa678f

[*] Switching to interactive mode

CTF{cryp70_5ur3_15_w13rd}

[*] Got EOF while reading in interactive

```



## 2018 Backdoor Awesome mix2



Local deployment `socat TCP4-LISTEN: 12345, fork EXEC:./service.py`.


The topic is similar to the above question. The only difference is that there is a constraint on e, which must be greater than 3, so we can&#39;t use 1.


$h(m)^e mod \ n=pad(m)$



Here we already know `h(m), pad(m)`. We only need to construct the remaining numbers. Here we construct n as a prime number, so that n-1 is a smooth number, so we can use the pohlig_hellman algorithm.


```python

from Crypto.Hash import SHA

from pwn import *

import gmpy2

from gmpy2 import is_prime

import random





def PKCS1_pad(data):

    asn1 = "3021300906052b0e03021a05000414"

ans = asn1 + data
n = len (ans)
return int ((&#39;00&#39; + &#39;01&#39; + &#39;ff&#39; * (1024/8 - n / 2 - 3) + &#39;00&#39; + years), 16)




#context.log_level = 'debug'

def gen_smooth_num(plist, minnum=pow(2, 1020)):

lenp = len (plist)
    while True:

        n = 1

        factors = dict()

while n + 1 &lt;remember:
            tmp = random.randint(0, lenp - 1)

            n *= plist[tmp]

            if plist[tmp] in factors:

                factors[plist[tmp]] += 1

            else:

                factors[plist[tmp]] = 1

        if n.bit_length() > 1024:

            continue

        if is_prime(n + 1):

            return n + 1, factors





# http://pythonexample.com/snippet/pohligpy_neuratron_python

# solve g^x=h mod m

define log_prime_power (g, h, pf, pe, M):

    powers = [pf**k for k in range(pe)]



    gamma = gmpy2.powmod(g, powers[-1], M)



xk = gmpy2.mpz (0)
    for k in range(pe):

        if k == 0:

hk = gmpy2.powmod (h, powers [pe - k - 1], m)
        else:

            gk = gmpy2.powmod(g, xk * (M - 2), M)

hk = gmpy2.powmod (gk * h, powers [pe - k - 1], m)


        k_log_found = False

        for dk in range(pf):

yk = gmpy2.powmod (gamma, dk, M)
            if yk == hk:

                k_log_found = True

                break



        if not k_log_found:

            raise Exception("can not solve")



        xk += gmpy2.mul(powers[k], dk)



    return xk





def pohlig_hellman(g, h, M, factors):

    M1 = M - 1

    xs = []

    for f in factors:

pf = f
pe = factors [f]


        subgroup_exponent = gmpy2.div(M1, gmpy2.powmod(pf, pe, M))

        gi = gmpy2.powmod(g, subgroup_exponent, M)

        hi = gmpy2.powmod(h, subgroup_exponent, M)



xi = log_prime_power (gi, hi, pf, pe, M)
        xs.append(xi)

crt_coeffs = []


    for f in factors:

pf = f
pe = factors [f]


mi = pf ** on


bi = gmpy2.div (M, mi)
bi_inv = gmpy2.invert (bi, mi)
crt_coeffs.append (gmpy2.mul (bi, bi_inv))
    x = 0

    for i in range(len(crt_coeffs)):

        x = gmpy2.t_mod(x + gmpy2.t_mod(xs[i] * crt_coeffs[i], M1), M1)

    return x





#context.log_level = 'debug'





def main():

    port = 12345

    host = "127.0.0.1"

    p = remote(host, port)

    p.recvuntil('Message   -> ')

    message = p.recvuntil('\n\nSignature -> ', drop=True)

    log.info('message: ' + message)

    signature = p.recvuntil('\n', drop=True)

    log.info('signature: ' + signature)

    signature = int(signature, 16)

    h = SHA.new(message)



    m = PKCS1_pad(h.hexdigest())

    print m, signature

    plist = []

    for i in range(2, 1000):

        if is_prime(i):

            plist.append(i)

    while True:

        try:

            n, factors = gen_smooth_num(plist, signature)

            e = pohlig_hellman(signature, m, n, factors)

        except Exception as e:

            continue

        else:

            break

print n, e


    print m

    print gmpy2.powmod(signature, e, n)



    p.sendlineafter('Enter n:', str(n))

    p.sendlineafter('Enter e:', str(e))



    p.interactive()





main()

```



There are two points to note


1. Since both g and y in $g^x=y$ are given, the newly found n, not necessarily the power of g, will contain y, so the solution may fail, so it needs to be solved multiple times. .
2. Although `n.bit_length() &lt;= 1025` in the source code, in fact, when n satisfies the condition of not less than signature, the following conditions must be met (pycrypto source code)


```python

        modBits = Crypto.Util.number.size(self._key.n)

        k = ceil_div(modBits,8) # Convert from bits to bytes

    

        # Step 1

if len (S)! = k:
            return 0

```



So we&#39;d better set n to 1024 bits.

