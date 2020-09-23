[EN](./rsa_theory.md) | [ZH](./rsa_theory-zh.md)
# RSA Introduction


The RSA encryption algorithm is an asymmetric encryption algorithm. RSA is widely used in public key encryption and electronic commerce. The RSA was proposed in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman. The RSA is composed of the letters of the three names of the three of them.


The reliability of the RSA algorithm is determined by the difficulty of maximizing integer factorization. In other words, the more difficult it is to factorize a very large integer, the more reliable the RSA algorithm is. If someone finds a fast factorization algorithm, the reliability of the information encrypted with RSA will definitely drop. But the possibility of finding such an algorithm is very small. Today, only short RSA keys can be broken down in a powerful way. As of 2017, there is no reliable way to attack the RSA algorithm.


## Fundamental


### Public key and private key generation


1. Randomly select two different large prime numbers $p$ and $q$ to calculate $N = p \times q$
2. According to the Euler function, find $\varphi (N)=\varphi (p)\varphi (q)=(p-1)(q-1)$
3. Select an integer $e$ that is less than $\varphi (N)$ to make $e$ and $\varphi (N)$ mutually prime. And ask for $e$ about the inverse of $\varphi (N)$, named $d$, with $ed\equiv 1 \pmod {\varphi (N)}$
4. Destroy records of $p$ and $q$


At this point, $(N,e)$ is the public key and $(N,d)$ is the private key.


### Message Encryption

First, we need to convert the message into an integer $m$ using an agreed-upon protocol, such than $m$ is less than $N$ and $m$ is coprime to $N$. If the message is too long, we can divide the message into several segments, which is what we call block encryption, and then encrypt each part with the following formula:


$$
m^{e}\equiv c\pmod N
$$

### Message decryption

Use the private key $d$ to decrypt the message.

$$
c^{d}\equiv m\pmod N
$$


### Verification

To verify $m^{ed} \equiv m \bmod N$, we use the fact that $ed \equiv 1 \bmod \phi(N)$, then $ed=k\phi(N)+1$, it is sufficient to prove that

$$
m^{k\phi(N)+1} \equiv m \bmod N
$$

We will prove it by considering two seperate cases

In the first case, $gcd(m,N)=1$, hence $m^{\phi(N)} \equiv 1 \bmod N$, so the original claim is true.


In the second case, $gcd(m,N)\neq 1$, so $m$ must be a multiple of $p$ or $q$, and since $n=m$ is less than $N$, we can assume that


$$
m = xp
$$



Where $x$ must be less than $q$. Since $q$ is a prime number,


$$
m^{\phi(q)}\equiv 1 \bmod q
$$






$$
m^{k\phi(N)} = m {k(p-1)(q-1)} = (m^{\phi(q)})^{k(p-1)} \equiv 1 \bmod q
$$






$$
m^{k\phi(N)+1}=m+uqm
$$



$$
m^{k\phi(N)+1}=m+uqxp=m+uxN
$$

Hence it is proven to be correct.

## Basic Tools


### RSAtool



- Installation


    ```bash
    git clone https://github.com/ius/rsatool.git
    cd rsatool
    python rsatool.py -h
    ```



- Generate private key


    ```bash
    Python rsatool.py f FEM private.pem o p q 1234567 7654321
    ```



### RSA Converter



- Generate a pem file based on a given key pair
- Obtain $p$ and $q$ from $n$, $e$, $d$


### openssl



- View public key file


    ```shell

    openssl rsa -pubin -in pubkey.pem -text -modulus

    ```



- Decryption


    ```shell

    rsautl -decrypt -inkey private.pem -in flag.enc -out flag

    ```



For more specific details, please refer to `openssl --help`.


### Decomposition Integer Tool


- Website decomposition, [factor.db](http://factordb.com/)
- Command line decomposition, [factordb-pycli](https://github.com/ryosan-470/factordb-pycli), borrowing the factordb database.
- [yafu](https://sourceforge.net/projects/yafu/)



### python库


#### primefac


The integer decomposition library contains many algorithms for integer decomposition.

#### gmpy



- `gmpy.root(a, b)`, returns a tuple `(x, y)`, where `x` is the value of `a` open `b` power, `y` is the judgment `x` whether Boolean variable that is an integer


#### gmpy2



When installing, you may need to install the mpfr and mpc libraries separately.


- `gmpy2.iroot(a, b)`, similar to `gmpy.root(a,b)`


#### pycrypto



- Installation


    ```bash

    sudo pip install pycrypto

    ```



- use


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



## Jarvis OJ - Basic - veryeasyRSA



> p = 3487583947589437589237958723892346254777 q = 8767867843568934765983476584376578389
>
> e = 65537
>
> Find d =
>
> Please submit `PCTF{d}`


Using $ed\equiv 1 \pmod{\varphi(N)}$, we can obtain $d$ from $\varphi (N)=\varphi (p)\varphi (q)=(p-1)(q-1)$.


```python

import gmpy2

p = 3487583947589437589237958723892346254777

q = 8767867843568934765983476584376578389

e = 65537
phin = (p - 1) * (q - 1)
print gmpy2.invert(e, phin)

```



```shell

➜  Jarvis OJ-Basic-veryeasyRSA git:(master) ✗ python exp.py       

19178568796155560423675975774142829153827883709027717723363077606260717434369

```



## 2018 CodeGate CTF Rsababy



The program is a simple RSA, but the program also generates two strange numbers.


```python

e = 65537
n = p * q

pi_n = (p-1) * (q-1)
d = mulinv (e, pi_n)
h = (d+p)^(d-p)

g = d*(p-0xdeadbeef)

```



So, the problem should come from here, so let's start with it, let's assume that `const = 0xdeadbeef`. Then


$$
eg = ed * (p-const)
$$



Furthermore, according to RSA


$$
2^{eg}=2^{ed * (p-const)}=2^{p-const} \pmod n
$$



$$
2^{p-const} * 2^{const-1} = 2^{p-1} \pmod n
$$



So


$$
2^{p-1} = 2^{eg} * 2^{const-1}+kn
$$



At the same time, according to Fermat's little theorem, we know


$$
2^{p-1} \equiv 1 \pmod p
$$



So


$$
p|2^{p-1}-1 | 2^{eg+const-1}-1+kn
$$






$$
p|2^{eg+const-1}-1
$$






$$
p|gcd(2^{eg+const-1}-1,n)
$$



Hence the code is as follows

```python

tmp = gmpy2.powmod(2,e*g+const-1,n)-1

p = gmpy2.gcd(tmp,n)

q = n/p

Phin = (p-1) * (q-1)
d = gmpy2.invert (e, phin)
plain = gmpy2.powmod(data,d,n)

print hex(plain)[2:].decode('hex')

```



## 2018 National Security Week pure math


The basic description of the topic is like this


```

1) p ** p % q = 1137973316343089029387365135250835133803975869258714714790597743585251681751361684698632609164883988455302237641489036138661596754239799122081528662395492

2) q ** q % p = 6901383184477756324584651464895743132603115552606852729050186289748558760692261058141015199261946483809004373728135568483701274908717004197776113227815323

3) (p ** q + q ** p) % (p*q) = 16791287391494893024031688699360885996180880807427715700800644759680986120242383930558410147341340225420991368114858791447699399702390358184412301644459406

4) (p+q) ** (p+q) % (p*q) = 63112211860889153729003401381621068190906433969243079543438386686621389392583849748240273643614258173423474299387234175508649197780206757067354426424570586101908571600743792328163163458500138799976944702155779196849585083397395750018148652864158388247163109077215394538930498877175474225571393901460434679279

5) FLAG ** 31337 % (p*q) = 6931243291746179589612148118911670244427928875888377273917973305632621316868302667641610838193899081089153471883271406133321321416064760200919958612671379845738048938060512995550639898688604592620908415248701721672948126507753670027043162669545932921683579001870526727737212722417683610956855529996310258030

Now, what’s the FLAG???

```



Our goal is basically to find FLAG, but how can we find it? This question requires us to be more familiar with number theory.

From the content of the question, we can assume that $p$, $q$ are both large prime numbers, so


$p^{q-1} \equiv  1\bmod q$


Then

$p^{q} \equiv p \bmod pq$

From 3), we know that

$p^q+q^p \equiv p+q \bmod pq$

And $p+q$ is obviously smaller than $pq$, so we know the value of $p+q$.

We let $x_1$, $x_2$, $x_3$, $x_4$, $x_5$ take the values of 1) to 5) respectively.

From 4), we have

$(p+q)^{p+q} \equiv p^{p+q}+q^{p+q} \bmod pq$



And because of 1) and 2), then

$p^pp \equiv px_1\bmod pq$

$q^qq \equiv qx_2 \bmod pq$

therefore

$px_1+qx_2 \equiv x_4 \bmod pq$

From the way $x_1$ and $x_2$ are obtained, we know that $px_1+qx_2$ is also equal to $x_4$, so we get a system of linear equations in two variables and can solve it directly.


```python

import gmpy2

x1 = 1137973316343089029387365135250835133803975869258714714790597743585251681751361684698632609164883988455302237641489036138661596754239799122081528662395492

X2 = 6901383184477756324584651464895743132603115552606852729050186289748558760692261058141015199261946483809004373728135568483701274908717004197776113227815323
p_q = 16791287391494893024031688699360885996180880807427715700800644759680986120242383930558410147341340225420991368114858791447699399702390358184412301644459406

x4 = 63112211860889153729 0034062380936348635813582583974823274634293429254290729072907052006074920060749s729Readingly 97297499258793650s 8392407 3105245 94071857 531058007 518 764 579 54 0 0 0 0 0 0 0 0 0 0 0 0


if (x4 - x1 * p_q) % (x2 - x1) == 0:

    print 'True'

q = (x4 - x1 * p_q) / (x2 - x1)

print q

p = p_q - q



c = 6931243291746179589612148118911670244427928875888377273917973305632621316868302667641610838193899081089153471883271406133321321416064760200919958612671379845738048938060512995550639898688604592620908415248701721672948126507753670027043162669545932921683579001870526727737212722417683610956855529996310258030



Phin = (p - 1) * (q - 1)
d = gmpy2.invert (31337, phin)
flag = gmpy2.powmod(c, d, p * q)

flag = hex(flag)[2:]

print flag.decode('hex')

```



Flag is as follows


```shell

➜ 2018-National Security Week first game-puremath git:(master) ✗ python exp.py
True

7635093784603905632817000902311635311970645531806863592697496927519352405158721310359124595712780726701027634372170535318453656286180828724079479352052417

flag{6a66b8d5-6047-4299-a48e-4c4d1f874d12}

```



## 2018 Pwnhub LHY



First analyze this code


```python

assert gmpy.is_prime(y)**2016 + gmpy.is_prime(x + 1)**2017 + (

    (x**2 - 1)**2 % (2 * x * y - 1) + 2

)**2018 == 30097557298197417800049182668952226601954645169633891463401117760245367082644152355564014438095421962150109895432272944128252155287648477680131934943095113263121691874508742328500559321036238322775864636883202538152031804102118831278605474474352011895348919417742923873371980983336517409056008233804190890418285814476821890492630167665485823056526646050928460488168341721716361299816947722947465808004305806687049198633489997459201469227952552870291934919760829984421958853221330987033580524592596407485826446284220272614663464267135596497185086055090126893989371261962903295313304735911034185619611156742146

```



Since `gmpy.is_prime` either returns 1 or returns 0, we can easily try out that $y$ is a prime number, $x+1$ is also a prime number, and


$(x^2-1)^2 \equiv 0 \bmod(2xy-1)$


In order for the expression to be divisible, we guess that $x=2y$.


So for the following code


```python
p = gmpy.next_prime(x**3 + y**3)
q = gmpy.next_prime(x**2 * y + y**2 * x)
n = p * q
phi = (p - 1) * (q - 1)
d = gmpy.invert(0x10001, phi)
enc = pow(bytes_to_long(flag), 0x10001, n)
print 'n =', n
print 'enc =', enc
```


$p$ and $q$ are naturally

$p=next\_prime(9y^3)$


$q=next\_prime(6y^3)$


According to the interval of prime numbers, we know that $p$ and $q$ are at most a little larger than the numbers in parentheses, and generally would not exceed $1000$ here.

Then

$n \geq 54y^6$

So we know the upper bound of $y$, and the lower bound of $y$ is actually not too far from the upper bound, we probably reduce hundreds of thousands. Hence, we use binary search to find $p$ and $q$, as follows


```python
import gmpy2
tmp = 30097557298197417800049182668952226601954645169633891463401117760245367082644152355564014438095421962150109895432272944128252155287648477680131934943095113263121691874508742328500559321036238322775864636883202538152031804102118831278605474474352011895348919417742923873371980983336517409056008233804190890418285814476821890492630167665485823056526646050928460488168341721716361299816947722947465808004305806687049198633489997459201469227952552870291934919760829984421958853221330987033580524592596407485826446284220272614663464267135596497185086055090126893989371261962903295313304735911034185619611156742146

print gmpy2.iroot(tmp, 2018)
print gmpy2.iroot(tmp - 1, 2018)

print gmpy2.iroot(tmp - 2, 2018)

n = 260272753019642842691231717156206014402348296256668058656902033827190888150939144319270903947159599144884859205368557385941127216969379550487700198771513118894125094678559478972591331182960004648132846372455712958337042783083099376871113795475285658106058675217077803768944674144803250791799957440111855021945690877200606577646234107957498370758707097662736662439460472126493593605957225541979181422479704018055731221681621886820626215670393536343427267329350730257979042198593215747542270975288047196483958369426727778580292311145109908665004662296440533724591193527886702374790526322791818523938910660223971454070731594803459613066617828657725704376475527288174777197739360634209448477565044519733575375490101670974499385760735451471034271880800081246883157088501597655371430353965493264345172541221268942926210055390568364981514774743693528424196241142665685211916330254113610598390909248626686397970038848966187547231199741

y = 191904757378974300059526915134037747982760255307942501070454569331878491189601823952845623286161325306079772871025816081849039036850918375408172174102720702781463514549851887084613000000L
y = gmpy2.next_prime(y)

enc = 73933313646416156737449236838459526871566017180178176765840447023088664788672323530940171469589918772272559607026808711216932468486201094786991159096267208480969757088208089800600731106685561375522764783335332964711981392251568543122418192877756299395774738176188452197889668610818741062203831272066261677731889616150485770623945568369493256759711422067551058418926344060504112146971937651406886327429318390247733970549845424064244469193626197360072341969574784310397213033860597822010667926563087858301337091484951760613299203587677078666096526093414014637559237148644939541419075479462431789925219269815364529507771308181435591670281081465439913711912925412078002618729159141400730636976744132429329651487292506365655834202469178066850282850374067239317928012461993443785247524500680257923687511378073703423047348824611101206633407452837948194591695712958510124436821151767823443033286425729473563002691262316964646014201612

end = gmpy2.iroot(n / 54, 6)[0]
beg = end - 2000000

mid = 1
while beg < end:
    mid = (beg + end) / 2
    if gmpy2.is_prime(mid) != 1:
        mid = gmpy2.next_prime(mid)
    p = gmpy2.next_prime(9 * mid**3)
    q = gmpy2.next_prime(6 * mid**3)
    n1 = p * q
    if n1 == n:
        print p, q
        phin = (p - 1) * (q - 1)
        d = gmpy2.invert(0x10001, phin)
        m = gmpy2.powmod(enc, d, n)
        print hex(m)[2:].strip('L').decode('hex')
        print 'ok'
        exit(0)
    elif n1 < n:
        beg = mid
    else:
        end = mid
    print beg, end
```










