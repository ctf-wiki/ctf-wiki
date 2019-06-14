[EN](./monoalphabetic.md) | [ZH](./monoalphabetic-zh.md)
## General Features


In single-table replacement encryption, all encryption methods have almost one commonality, that is, the plaintext one-to-one correspondence. Therefore, there are generally two ways to crack


- In the case of a small key space, brute force
- Use word frequency analysis when the ciphertext length is long enough, http://quipqiup.com/


When the key space is large enough and the ciphertext length is short enough, the cracking is more difficult.


## Caesar Password


### Principle


When Caesar is encrypted, each letter** in the plaintext is moved backward (or forward) by a fixed number (**circular movement**) as ciphertext according to its order in the alphabet. For example, when the offset is shifted to the left by 3 (the key at decryption is 3):


```

Plaintext alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZ
The ciphertext alphabet: DEFGHIJKLMNOPQRSTUVWXYZABC
```



In use, the encryptor finds the location of each letter in the message that needs to be encrypted in the plaintext alphabet, and writes the corresponding letter in the ciphertext alphabet. The person who needs to decrypt is reversed according to the previously known key to get the original plaintext. E.g:


```

明文：THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG

Secret: WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ
```



Depending on the offset, there are also a number of specific Caesar password names**:


- Offset is 10: Avocat (A→K)
- The offset is 13: [ROT13] (https://zh.wikipedia.org/wiki/ROT13)
- Offset -5: Cassis (K 6)
- Offset -6: Cassette (K 7)


In addition, there is a key-based Caesar cipher Keyed Caesar. The basic principle is that ** use a key to convert each bit of the key into a number (generally converted into a number corresponding to the alphabet), and use this number as the key to encrypt each letter of the plaintext. **


Here is an example of the **XMan Phase I Summer Camp sharing the Kung Pao Chicken Crest Crypto 100**.


```

Ciphertext: s0a6u3u1s0bv1a
Key: guangtou
Offset: 6, 20, 0, 13, 6, 19, 14, 20
Clear text: y0u6u3h1y0uj1u
```



### 破


For Caesar passwords without keys, there are two ways to break the basics.


1. Traverse 26 offsets for general conditions
2. Using word frequency analysis, it is suitable for the case of long ciphertext.


Among them, the first way can definitely get plaintext, while the second way does not necessarily get the correct plaintext.


For a key-based Caesar cipher, it is generally necessary to know the corresponding key.


### Tools


Generally we have the following tools, of which JPK is more general.


- JPK, solvable with and without key
- http://planetcalc.com/1434/

- http://www.qqxiuzi.cn/bianma/ROT5-13-18-47.php



## Shift password


Similar to the Caesars password, the difference is that shifting passwords not only handles letters, but also numbers and special characters, which are commonly used in ASCII tables. The way to crack it is also to traverse all the possibilities to get the possible results.


## Atbash Cipher



### Principle


Atbash Cipher can actually be considered as a special case of a simple replacement password to be introduced below. It uses the last letter of the alphabet to represent the first letter, and the second to last letter represents the second letter. In the Roman alphabet, it appears like this:


```

Clear text: ABCDEFGHIJKLMNOPQRSTU VWXYZ
Ciphertext: ZYXWVUTSRQPONMLKJIHGF EDCBA
```



An example is given below:


```

明文：the quick brown fox jumps over the lazy dog

密 文 ： gsv jfrxp yildm ulc qfnkh levi gsv ozab wlt
```



### 破


It can be seen that the key space is short enough, and when the ciphertext is long enough, it can still be solved by word frequency analysis.


### Tools


- http://www.practicalcryptography.com/ciphers/classical-era/atbash-cipher/



## Simple replacement password


### Principle


When the Simple Substitution Cipher is encrypted, each plaintext letter is replaced with a letter that uniquely corresponds to it. The difference between it and the Caesar cipher is that the letters of its cipher alphabet are not simply shifted, but completely confusing, which makes it more difficult to crack than the Caesar cipher. such as:


```

Plain text: abcdefghijklmnopqrstuvwxyz
Key letter: phqgiumeaylnofdxjkrcvstzwb
```



a corresponds to p, d corresponds to h, and so on.


```

明文：the quick brown fox jumps over the lazy dog

密 文: those jvaql hkdtf udz yvoxr dsik those npbw gdm
```



When decrypting, we generally know the corresponding rules of each letter before we can decrypt it normally.


### 破


Since this encryption method results in all of its keys being $26!$, it is almost impossible to use a violent solution. So we generally use word frequency analysis.


### Tools


- http://quipqiup.com/



## affine password


### Principle


The cryptographic function of the affine password is $E(x)=(ax+b)\pmod m$, where

- $x$ indicates the number of plaintexts obtained by some encoding
- $a$ and $m$ are qualitative
- $m$ is the number of letters in the encoding system.


The decryption function is $D(x)=a^{-1}(xb)\pmod m$, where $a^{-1}$ is $a$ at $\mathbb{Z}_{m}$ Multiplication inverse.


Let&#39;s take the $E(x) = (5x + 8) \bmod 26$ function as an example. The encrypted string is `AFFINE CIPHER`. Here we use the alphabet 26 letters as the encoding system.


| 明文      | A   | F   | F   | I   | N   | E   | C   | I   | P   | H   | E   | R   |

| --------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |

| x         | 0   | 5   | 5   | 8   | 13  | 4   | 2   | 8   | 15  | 7   | 4   | 17  |

| $ y = 5x + 8 $ | 8 | 33 | 33 | 48 | 73 | 28 | 18 | 48 | 83 | 43 | 28 | 93 |
| $ y \ mod26 $ | 8 | 7 | 7 | 22 | 21 | 2 | 18 | 22 | 5 | 17 | 2 | 15 |
| 密文      | I   | H   | H   | W   | V   | C   | S   | W   | F   | R   | C   | P   |



The corresponding encryption result is `IHHWVCSWFRCP`.


For the decryption process, the normal decrypter has a and b, and can calculate $a^{-1}$ to be 21, so its decryption function is $D(x)=21(x-8)\pmod {26}$ , Decrypt as follows


| 密文        | I    | H    | H   | W   | V   | C    | S   | W   | F   | R   | C    | P   |

| ----------- | :--- | :--- | --- | --- | --- | ---- | --- | --- | --- | --- | ---- | --- |

| $ y $ | 8 | 7 | 7 | 22 | 21 | 2 | 18 | 22 | 5 | 17 | 2 | 15 |
| $x=21(y-8)$ | 0    | -21  | -21 | 294 | 273 | -126 | 210 | 294 | -63 | 189 | -126 | 147 |

| $x\mod26$   | 0    | 5    | 5   | 8   | 13  | 4    | 2   | 8   | 15  | 7   | 4    | 17  |

| 明文        | A    | F    | F   | I   | N   | E    | C   | I   | P   | H   | E    | R   |



It can be seen that it is characterized by only 26 English letters.


### 破


First of all, we can see that the affine password is different for any two different letters, and the ciphertext obtained by it is different, so it also has the most common features. When the ciphertext length is long enough, we can use the frequency analysis method to solve it.


Second, we can consider how to attack the password. It can be seen that when $a=1$, the affine encryption is Caesar encryption. In general, when we use affine ciphers, the character set uses the alphabet, generally only 26 letters, and not more than 26 and 26 symbiotics.


$$

(26) = (2) non (13) = 12
$$



Counting the offset of b, there is a total possible key space size.


$$

12 \times 26 = 312

$$



In general, for this kind of password, we must at least attack the known part of the plaintext. A simple analysis is performed below.


This kind of password is controlled by two parameters. If we know any one of them, then we can easily enumerate another parameter quickly to get the answer.


However, suppose we already know the set of letters used, here we assume 26 letters, we have another way of decryption, we only need to know the two encrypted letters $y_1, y_2$ to decrypt. Then we can still know


$$

y_1=(ax_1+b)\pmod{26} \\

y_2=(ax_2+b)\pmod{26}

$$



Two types of subtraction, available


$$

y_1-y_2=a(x_1-x_2)\pmod{26}

$$



Here $y_1,y_2$ is known. If we know the two different characters $x_1$ and $x_2$ for the cipher text, then we can easily get $a$ and then get $b$.


### Examples


Here we take TWCTF 2016&#39;s super_express as an example. Simply look at the source code


```python

import sys

key = '****CENSORED***************'

flag = 'TWCTF{*******CENSORED********}'



if len(key) % 2 == 1:

    print("Key Length Error")

    sys.exit(1)



n = len (key) / 2
encrypted = ''

for c in flag:

c = word (c)
    for a, b in zip(key[0:n], key[n:2*n]):

c = (ord (a) * c + ord (b))% 251
    encrypted += '%02x' % c



print encrypted

```



It can be found that although each letter in the flag is encrypted n times, if we analyze it carefully, we can find


$$

\begin{align*}

c_1&=a_1c+b_1 \\

c_2 &amp; = a_2c_1 + b_2 \\
   &=a_1a_2c+a_2b_1+b_2 \\

&amp; = kc + d
\end{align*}  

$$



According to the second line of derivation, we can get the actual form of $c_n $, which can be seen as $c_n=xc+y $ , and we can know that the key is always unchanged, so that In fact, this is the affine password.


In addition, the title also gives the plaintext and part of the partial ciphertext corresponding plaintext, then we can easily use the known plaintext attack method to attack, using the code as follows


```python

import gmpy



key = '****CENSORED****************'

flag = 'TWCTF{*******CENSORED********}'



f = open('encrypted', 'r')

data = f.read().strip('\n')

encrypted = [int(data[i:i + 2], 16) for i in range(0, len(data), 2)]

plaindelta = words (flag [1]) - words (flag [0])
cipherdalte = encrypted[1] - encrypted[0]

a = gmpy.invert (plaindelta, 251) * cipheral% 251
b = (encrypted[0] - a * ord(flag[0])) % 251

a_inv = gmpy.invert(a, 251)

result = ""

for c in encrypted:

    result += chr((c - b) * a_inv % 251)

print result

```



Results are as follows


```shell

➜  TWCTF2016-super_express git:(master) ✗ python exploit.py
TWCTF{Faster_Than_Shinkansen!}

```
