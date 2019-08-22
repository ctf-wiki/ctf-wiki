[EN](./elgamal.md) | [ZH](./elgamal-zh.md)
# ElGamal



## Overview


The security of the ElGamal algorithm is based on the difficulty of solving the discrete logarithm problem. It was proposed in 1984 and is also a double-key cryptosystem, which can be used for both encryption and digital signature.


If we assume that p is a decimal prime of at least 160 bits, ** and p-1 has a large prime factor**, and g is the generator of $Z_p^*$, and $y \in Z_p^*$ . So how to find a unique integer x ($0\leq x \leq p-2$) that satisfies $g^x \equiv y \bmod p$ is algorithmically difficult, here is x as $x=log_gy$ .


## Fundamental


Here we assume that A wants to send a message m to B.


### Key Generation


The basic steps are as follows


1. It is difficult to choose a prime p that is large enough to solve the discrete logarithm problem on $Z_p$.
2. Select the generator g of $Z_p^*$.
3. Randomly select the integer k, $0\leq k \leq p-2$ , and calculate $g^k \equiv y \bmod p$ .


The private key is {k} and the public key is {p,g,y}.


### Encryption


A selects the random number $r \in Z_{p-1}$ and encrypts the plaintext $E_k(m,r)=(y_1,y_2)$ . Where $y_1 \equiv g^r \bmod p$ , $y_2 \equiv my^r \bmod p$ .


### Decryption


$D_k(y_1,y_2)=y_2(y_1^k)^-1 \bmod p \equiv m(g^k)^r(g^{rk})^{-1} \equiv m \bmod p$ 。



### Difficult


Although we know y1, we have no way of knowing the corresponding r.


## 2015 MMA CTF Alicegame


Here we take Alicegame in MMA-CTF-2015 in 2015 as an example. This question was originally difficult to do when the source code was not given, because this gives an m, and gives an r to get the encrypted result, which is too difficult to think about.


Let&#39;s analyze the source code briefly. First, the program originally generated pk and sk.


```python

    (pk, sk) = genkey(PBITS)

```



Where the genkey function is as follows


```python

def genkey(k):

    p = getPrime(k)

g = random.randrange (2, p)
x = random.randrange (1, p-1)
    h = pow(g, x, p)

    pk = (p, g, h)

sk = (p, x)
    return (pk, sk)

```



p is the prime number of the k position, g is the book in the range of (2, p), and x is in the range of (1, p-1). And calculated $h \equiv g^x \bmod p$ . Seeing this, I almost know that this should be an ElGamal encryption on a number field. Where pk is the public key and sk is the private key.


The program then outputs 10 times m and r. And, use the following function to encrypt


```python

def encrypt(pk, m, r = None):

    (p, g, h) = pk

    if r is None:

r = random.randrange (1, p-1)
    c1 = pow(g, r, p)

    c2 = (m * pow(h, r, p)) % p

    return (c1, c2)

```



Its encryption method is indeed ElGamal encryption.


Finally the program encrypts the flag. At this time r is by the program itself random.


Analysis, here we can control m and r in ten rounds, and


$c_1 \equiv g^r \bmod p$



$c_2 \equiv m * h^{r} \bmod p$



If we set


1. r=1, m=1, then we can get $c_1=g, c_2=h$.
2. r=1, m=-1, then we can get $c_1=g, c_2 = ph$. Then we can get the prime number p.


What is the use of prime p? The number of bits in p is around 201, which is very big.


But ah, after it generated the prime number p, it was not checked. We have said before that p-1 must have a large factor, and if there is a small prime factor, then we can attack. The attack mainly uses the baby step-giant step and Pohlig-Hellman algorithm algorithm. If you are interested, you can look at it. Here, the sage itself has a function to calculate the discrete logarithm, which can handle such a situation. See [discrete_log]( Http://doc.sagemath.org/html/en/reference/groups/sage/groups/generic.html) .


The specific code is as follows, it should be noted that this memory consumption is relatively large, do not just take the virtual machine to run. . . There is also this Nima interaction that makes me a headache,,,,


```python

import socket

from Crypto.Util.number import *

from sage.all import *





def get_maxfactor(N):

    f = factor(N)

    print 'factor done'

    return f[-1][0]



maxnumber = 1 << 70

i = 0

while 1:

    print 'cycle: ',i

sock = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 9999))

    sock.recv(17)

    # get g,h

    sock.recv(512)

    sock.sendall("1\n")

    sock.recv(512)

    sock.sendall("1\n")

    data = sock.recv(1024)

    print data

    if '\n' in data:

        data =data[:data.index('\n')]

    else:

        # receive m=

        sock.recv(1024)

    (g,h) = eval(data)

    

    # get g,p

    sock.sendall("-1\n")

    sock.recv(512)
    sock.sendall("1\n")

    data = sock.recv(1024)

    print data

    if '\n' in data:

        data = data[:data.index('\n')]

    else:

        # receive m=

        sock.recv(512)

    (g,tmp) = eval(data)

    p = tmp+h

    tmp = get_maxfactor(p-1)

    if tmp<maxnumber:

        print 'may be success'

        # skip the for cycle

        sock.sendall('quit\n');

        data = sock.recv(1024)

        print 'receive data: ',data

        data = data[data.index(":")+1:]

        (c1,c2)=eval(data)

        # generate the group

        g = Mod(g, p)

        h = Mod(h, p)

        c1 = Mod(c1, p)

        c2 = Mod(c2, p)

        x = discrete_log(h, g)

        print "x = ", x

        print "Flag: ", long_to_bytes(long(c2 / ( c1 ** x)))

    sock.sendall('quit\n')

    sock.recv(1024)

    sock.close()

    i += 1

```



In the end, the computer is not enough memory, it is not calculated, and sometimes it will collapse and run a few times. .


## 2018 Code Blue lagalem



The title is described below


```python

from Crypto.Util.number import *

from key import FLAG



size = 2048

rand_state = getRandomInteger (size // 2)




def keygen(size):

    q = getPrime(size)

k = 2
    while True:

        p = q * k + 1

        if isPrime(p):

            break

k + = 1
    g = 2

    while True:

        if pow(g, q, p) == 1:

            break

        g += 1

    A = getRandomInteger(size) % q

    B = getRandomInteger(size) % q

    x = getRandomInteger(size) % q

    h = pow(g, x, p)

    return (g, h, A, B, p, q), (x,)





def rand(A, B, M):

    global rand_state

    rand_state, ret = (A * rand_state + B) % M, rand_state

return right




def encrypt(pubkey, m):

    g, h, A, B, p, q = pubkey

    assert 0 < m <= p

    r = rand(A, B, q)

    c1 = pow(g, r, p)

    c2 = (m * pow(h, r, p)) % p

    return (c1, c2)





# pubkey, privkey = keygen(size)



m = bytes_to_long(FLAG)

c1, c2 = encrypt(pubkey, m)

c1_, c2_ = encrypt(pubkey, m)



print pubkey

print(c1, c2)

print(c1_, c2_)

```



It can be seen that the algorithm is an ElGamal encryption, which gives the same plaintext two sets of encrypted results. The characteristic is that the random number r used is generated by the linear congruential generator, then we know


$c2 \equiv m * h^{r} \bmod p$



$c2\_ \equiv m*h^{(Ar+B) \bmod q} \equiv m*h^{Ar+B}\bmod p$



then


$c2^A*h^B/c2\_ \equiv m^{A-1}\bmod p$



Among them, c2, c2_, A, B, h are known. Then we know


$m^{A-1} \equiv t \bmod p$



We assume that we know a primitive root g of p, then we can assume


$g^x \equiv t$



$g^y \equiv m$



then


$g^{y(A-1)}\equiv g^x \bmod p$



then


$y(A-1) \equiv x \bmod p-1$



Then we know


$y(A-1)-k(p-1)=x$



Here we know A, p, x, then we can use the extended Euclidean theorem to find

$s(A-1)+w(p-1)=gcd(A-1,t-1)$



If gcd(A-1, t-1)=d, then we calculate directly


$t^s \equiv m^{s(A-1)} \equiv m^d \bmod p$



If d=1, then m is directly known.


If d is not 1, then it is a bit of a hassle. .


This problem is exactly d=1, so it can be solved easily.


```python

import gmpy2

data = open('./transcript.txt').read().split('\n')

g, h, A, B, p, q = eval(data[0])



c1, c2 = eval(data[1])

c1_, c2_ = eval(data[2])



tmp = gmpy2.powmod(c2, A, p) * gmpy2.powmod(h, B, p) * gmpy2.invert(c2_, p)

tmp = tmp % p



print 't=', tmp

print 'A=', A

Print &#39;= p, p
gg, x, y = gmpy2.gcdext(A - 1, p - 1)

print gg



m = gmpy2.powmod(tmp, x, p)

print hex(m)[2:].decode('hex')

```



flag



```shell

➜  2018-CodeBlue-lagalem git:(master) ✗ python exp.py

t= 24200833701856688878756977616650401715079183425722900529883514170904572086655826119242478732147288453761668954561939121426507899982627823151671207325781939341536650446260662452251070281875998376892857074363464032471952373518723746478141532996553854860936891133020681787570469383635252298945995672350873354628222982549233490189069478253457618473798487302495173105238289131448773538891748786125439847903309001198270694350004806890056215413633506973762313723658679532448729713653832387018928329243004507575710557548103815480626921755313420592693751934239155279580621162244859702224854316335659710333994740615748525806865323

A= 22171697832053348372915156043907956018090374461486719823366788630982715459384574553995928805167650346479356982401578161672693725423656918877111472214422442822321625228790031176477006387102261114291881317978365738605597034007565240733234828473235498045060301370063576730214239276663597216959028938702407690674202957249530224200656409763758677312265502252459474165905940522616924153211785956678275565280913390459395819438405830015823251969534345394385537526648860230429494250071276556746938056133344210445379647457181241674557283446678737258648530017213913802458974971453566678233726954727138234790969492546826523537158

p= 36416598149204678746613774367335394418818540686081178949292703167146103769686977098311936910892255381505012076996538695563763728453722792393508239790798417928810924208352785963037070885776153765280985533615624550198273407375650747001758391126814998498088382510133441013074771543464269812056636761840445695357746189203973350947418017496096468209755162029601945293367109584953080901393887040618021500119075628542529750701055865457182596931680189830763274025951607252183893164091069436120579097006203008253591406223666572333518943654621052210438476603030156263623221155480270748529488292790643952121391019941280923396132717

1

CBCTF {183a3ce8ed93df613b002252dfc741b2}
```



## Reference


- https://www.math.auckland.ac.nz/~sgal018/crypto-book/solns.pdf，20.4.1