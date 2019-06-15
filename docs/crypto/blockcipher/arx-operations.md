[EN](./arx-operations.md) | [ZH](./arx-operations-zh.md)
# Add-Rotate-Xor



## Overview


The ARX operation is a general term for the following three basic operations.
- Add Modification on the finite field
- Rotate circular shift
- Xor XOR


There are many common block cipher algorithms that use only these three basic operations in a round function. Typical examples are Salsa20, Speck, and so on. In addition, [IDEA] (./idea.md) also uses a similar basic operation to construct the encryption and decryption operation, but replaces the shift by multiplication.


## Advantages and disadvantages


### Advantages


- Easy operation and fast operation
- Execution time is constant to avoid time-based channel attack
- The combined function is sufficiently expressive (see example below)


### Disadvantages


- Among the three basic operations, Rotate and Xor are completely linear operations for a single bit, which may cause some vulnerability (see [Rotational cryptanalysis] (https://en.wikipedia.org/wiki/ Rotational_cryptanalysis))


## topic


### 2018 *ctf primitive



#### Analysis


This problem requires us to combine a certain number of Add-Rotate-Xor operations, so that the obtained encryption algorithm can encrypt the fixed plaintext into a specified random ciphertext, that is, construct an arbitrary permutation function through the basic operation. The flag is obtained after 3 successful builds.


#### Problem Solving


For the operation under modulo 256, a typical ARX-based transposition operation can be expressed as the following combination
```

RotateLeft_1(Add_255(RotateLeft_7(Add_2(x))))

```



The above function corresponds to a permutation operation that swaps 254 and 255 while keeping other numbers unchanged.


Intuitively, since the carry occurs in the modulo plus 2 operation of the first step, only the input is 254, 255, the combined function can treat this situation differently.


Using the above atomic operations, we can construct a permutation of any two numbers &#39;a, b`. Combined with the Xor operation, we can reduce the number of basic operations required to meet the limitations given by the title. One possible operational step is as follows:


1. For `a, b`, make `a` 0 by modular operation
2. Move to the right by making the lowest bit of b
3. If `b` is not 1, perform the `Xor 1, Add 255` operation, keeping `a` still 0 and decreasing the value of `b`
4. Repeat operation 2-3 until `b` is 1
5. Perform `Add 254` and transposition operations, exchanging `a, b`
6. For all operations except transposition, add the corresponding inverse operation to ensure that the values other than `a, b` are unchanged.


The complete solution script is as follows:


```python

from pwn import *

import string

from hashlib import sha256



#context.log_level='debug'

def dopow():

chal = c.recvline ()
post = chal [12:28]
tar = chal [33: -1]
    c.recvuntil(':')

    found = iters.bruteforce(lambda x:sha256(x+post).hexdigest()==tar, string.ascii_letters+string.digits, 4)

    c.sendline(found)



#c = remote('127.0.0.1',10001)

c = remote('47.75.4.252',10001)

doped ()
pt='GoodCipher'



def doswap(a,b):

    if a==b:

        return

    if a>b:

        tmp=b

        b=a

        a=tmp

years = []
ans.append ((0.256-a))
    b-=a

    a=0

    while b!=1:

        tmp=0

lo = 1
        while b&lo==0:

what &lt;&lt; = 1
            tmp+=1

        if b==lo:

ans.append ((1,8-tmp))
            break

        if tmp!=0:

ans.append ((1,8-tmp))
        b>>=tmp

ans.append ((2,1))
        b^=1

ans.append ((0.255))
        b-=1

ans.append ((0.254))


    for a,b in ans:

        c.sendline('%d %d'%(a,b))

        c.recvline()

    for a,b in [(0,2),(1,7),(0,255),(1,1)]:

        c.sendline('%d %d'%(a,b))

        c.recvline()

    for a,b in ans[::-1]:

        if a==0:

            c.sendline('%d %d'%(a,256-b))

elif a == 1:
            c.sendline('%d %d'%(a,8-b))

elif a == 2:
            c.sendline('%d %d'%(a,b))

        c.recvline()



for i in range(3):

    print i

    m=range(256)

    c.recvuntil('ciphertext is ')

    ct=c.recvline().strip()

    ct=ct.decode('hex')

assert len (ct) == 10
    for i in range(10):

        a=ord(ct[i])

b = ord (pt [i])
        #print m[a],b
        doswap(m[a],b)

        for j in range(256):

            if m[j]==b:

                m[j]=m[a]

                m[a]=b

                break

    c.sendline('-1')



c.recvuntil('Your flag here.\n')

print c.recvline()

```
