[EN](./des.md) | [ZH](./des-zh.md)
---

typora-root-url: ../../

---



# DES


## basic introduction


Data Encryption Standard (DES), a data encryption standard, is a typical block encryption. The basic information is as follows:


- Enter 64 bits.
- Output 64 bits.
- The key is 64 bits, using 56 bits of the 64-bit key, and the remaining 8 bits are either discarded or used as parity bits.
- Feistel iterative structure
- The plaintext is ciphered after 16 iterations.
- The ciphertext is plaintext after a similar 16 iterations.


## Basic Process


Give a simple [DES Flowchart] (http://homepage.usask.ca/~dtr467/400/).


![](./figure/des.gif)



### Encryption


We can consider each round of encryption process


$L_{i+1}=R_i$



$R_{i+1}=L_i\oplus F(R_i,K_i)$



Then before the last Permutation, the corresponding ciphertext is $(R_{n+1}, L_{n+1})$.


### Decryption


So how does decryption decrypt it? First, we can reverse the ciphertext first, then we can get the final round of output. We will consider each round at this time.


$R_i=L_{i+1}$



$L_i=R_{i+1}\oplus F(L_{i+1},K_i)$



Therefore, $(L_0,R_0)$ is the plaintext after the first replacement when encrypting. We only need to perform the inverse permutation to get the plaintext.


It can be seen that DES encryption and decryption uses the same set of logic, except that the order in which the keys are used is inconsistent.


## Core components


The core components in DES mainly include (only the encryption process is given here)


- initial replacement
- F function
- E extension function
- S box, design criteria not given.
- P replacement
- Last replacement


Where the F function is as follows


![](./figure/f-function.png)



If you are more interested in DES, you can study it more closely. Welcome to PR.


## derivative


Based on DES, the following two encryption methods are derived.


- Double DES
- Three DES


### Dual DES


Dual DES uses two keys and is 112 bits long. Encryption method is as follows


$ C = E_ {k2} (E_ {k1} (P)) $


But dual DES can&#39;t resist the middle encounter attack, we can construct the following two sets


$ I = {E_ {k1} (P)} $


$J=D_{k2}(C)$



That is, respectively enumerate K1 and K2 to encrypt P and decrypt C respectively.


After we encrypt P, we can sort the encryption results. The complexity is $2^nlog(2^n)=O(n2^n)$


When we decrypt C, we can go to the corresponding table for each decryption.


The total complexity is still $O(n2^n)$.


### Triple DES


Triple DES encryption and decryption methods are as follows


$C=E_{k3}(D_{k2}(E_{k1}(P)))$



$P=D_{k1}(E_{k2}(D_{k3}(C)))$



There are two ways to choose a key.


- 3 different keys, k1, k2, k3 are independent of each other, a total of 168 bits.
- 2 different keys, k1 and k2 are independent, k3 = k1, 112 bits.


## Attack method


- Differential attack
- Linear attack


## 2018 N1CTF N1ES



The basic code is as follows


```python

# -*- coding: utf-8 -*-

def round_add(a, b):

    f = lambda x, y: x + y - 2 * (x & y)

true = &#39;&#39;
    for i in range(len(a)):

res + = chr (f (words (a [i]), words (b [i])))
    return res



def permutate(table, block):

	return list(map(lambda x: block[x], table))



def string_to_bits(data):

    data = [ord(c) for c in data]

l = len (data) * 8
    result = [0] * l
post = 0
    for ch in data:

        for i in range(0,8):

            result[(pos<<3)+i] = (ch>>i) & 1

post + = 1
    return result



s_box = [54, 132, 138, 83, 16, 73, 187, 84, 146, 30, 95, 21, 148, 63, 65, 189, 188, 151, 72, 161, 116, 63, 161, 91, 37, 24, 126, 107, 87, 30, 117, 185, 98, 90, 0, 42, 140, 70, 86, 0, 42, 150, 54, 22, 144, 153, 36, 90, 149, 54, 156, 8, 59, 40, 110, 56,1, 84, 103, 22, 65, 17, 190, 41, 99, 151, 119, 124, 68, 17, 166, 125, 95, 65, 105, 133, 49, 19, 138, 29, 110, 7, 81, 134, 70, 87, 180, 78, 175, 108, 26, 121, 74, 29, 68, 162, 142, 177, 143, 86, 129, 101, 117, 41, 57, 34, 177, 103, 61, 135, 191, 74, 69, 147, 90, 49, 135, 124, 106, 19, 8

9, 38, 21, 41, 17, 155, 83, 38, 159, 179, 19, 157, 68, 105, 151, 166, 171, 122, 179, 114, 52, 183, 89, 107, 113, 65, 161, 141, 18, 121, 95, 4, 95, 101, 81, 156,

 17, 190, 38, 84, 9, 171, 180, 59, 45, 15, 34, 89, 75, 164, 190, 140, 6, 41, 188, 77, 165, 105, 5, 107, 31, 183, 107, 141, 66, 63, 10, 9, 125, 50, 2, 153, 156, 162, 186, 76, 158, 153, 117, 9, 77, 156, 11, 145, 12, 169, 52, 57, 161, 7, 158, 110, 191, 43, 82, 186, 49, 102, 166, 31, 41, 5, 189, 27]



def generate(o):

k = permutate (s_box, o)
    b = []

    for i in range(0, len(k), 7):

        b.append(k[i:i+7] + [1])

    c = []

    for i in range(32):

post = 0
        x = 0

        for j in b[i]:

            x += (j<<pos)

post + = 1
        c.append((0x10001**x) % (0x7f))

    return c







class N1ES:

    def __init__(self, key):

        if (len(key) != 24 or isinstance(key, bytes) == False ):

            raise Exception("key must be 24 bytes long")

        self.key = key

        self.gen_subkey()



    def gen_subkey(self):

        o = string_to_bits(self.key)

k = []
        for i in range(8):

o = generate (o)
        	k.extend(o)

        	o = string_to_bits([chr(c) for c in o[0:24]])

        self.Kn = []

        for i in range(32):

            self.Kn.append(map(chr, k[i * 8: i * 8 + 8]))

        return



    def encrypt(self, plaintext):

        if (len(plaintext) % 16 != 0 or isinstance(plaintext, bytes) == False):

            raise Exception("plaintext must be a multiple of 16 in length")

true = &#39;&#39;
        for i in range(len(plaintext) / 16):

            block = plaintext[i * 16:(i + 1) * 16]

            L = block[:8]

            R = block[8:]

            for round_cnt in range(32):

                L, R = R, (round_add(L, self.Kn[round_cnt]))

            L, R = R, L

            res += L + R

        return res

```



Obviously, we can think of it as a way of Feistel encryption, the decryption function is as follows


```python

    def decrypt(self,ciphertext):

true = &#39;&#39;
        for i in range(len(ciphertext) / 16):

            block = ciphertext[i * 16:(i + 1) * 16]

            L = block[:8]

            R = block[8:]

            for round_cnt in range(32):

                L, R =R, (round_add(L, self.Kn[31-round_cnt]))

            L,R=R,L

            res += L + R

        return res

```



The final result is


```shell

➜  baby_N1ES cat challenge.py

from N1ES import N1ES

import base64

key = "wxy191iss00000000000cute"

n1es = N1ES(key)

flag = "N1CTF{*****************************************}"

cipher = n1es.encrypt(flag)

#print base64.b64encode(cipher)  # HRlgC2ReHW1/WRk2DikfNBo1dl1XZBJrRR9qECMNOjNHDktBJSxcI1hZIz07YjVx

cipher = 'HRlgC2ReHW1/WRk2DikfNBo1dl1XZBJrRR9qECMNOjNHDktBJSxcI1hZIz07YjVx'

cipher = base64.b64decode(cipher)

print n1es.decrypt(cipher)

➜  baby_N1ES python challenge.py

N1CTF {F3istel_n3tw0rk_c4n_b3_ea5i1y_s0lv3d _ / - /}
```



## 2019 CISCN part_des


The title only gave one file:


```

Round n part_encode-> 0x92d915250119e12b

Key map -> 0xe0be661032d5f0b676f82095e4d67623628fe6d376363183aed373a60167af537b46abc2af53d97485591f5bd94b944a3f49d94897ea1f699d1cdc291f2d9d4a5c705f2cad89e938dbacaca15e10d8aeaed90236f0be2e954a8cf0bea6112e84

```



Considering the title name and data characteristics, `Round n part_encode` is the intermediate result of executing n rounds of des, and `Key map` should be the subkey of des. To restore the plaintext, only the reverse process of n rounds of des encryption can be performed. Pay attention to the following three points when decrypting.


- Subkey selection, for only n rounds of encryption results, the decryption should use the keys n, n-1..., 1 in sequence.
- des After the last round of operations, the unfinished des does not exchange the left and right parts and the inverse initial permutation, so we should perform these two steps on the ciphertext first.
- n choice, in this question, we don&#39;t know n, but it doesn&#39;t matter, we can try all possible values (0-15) flag should be ascii string.


??? note &quot;Solution code&quot;
    ``` python



kkk = 16
    def bit_rot_left(lst, pos):

    	return lst[pos:] + lst[:pos]



    class DES:

    	IP = [

    	        58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,

    	        62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,

    	        57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,

    	        61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7

    	    ]

    	IP_re = [

    	        40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
    	        38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,

    	        36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,

    	        34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25

    	    ]

    	Pbox = [

    	        16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,

    	        2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25

    	    ]

E = [
    	        32,1,2,3,4,5,4,5,6,7,8,9,

    	        8,9,10,11,12,13,12,13,14,15,16,17,

    	        16,17,18,19,20,21,20,21,22,23,24,25,

    	        24,25,26,27,28,29,28,29,30,31,32,1

    	    ]

    	PC1 = [

    	            57,49,41,33,25,17,9,1,58,50,42,34,26,18,

    	            10,2,59,51,43,35,27,19,11,3,60,52,44,36,

    	            63,55,47,39,31,23,15,7,62,54,46,38,30,22,

    	            14,6,61,53,45,37,29,21,13,5,28,20,12,4

    	    ]

    	PC2 = [

    	        14,17,11,24,1,5,3,28,15,6,21,10,

    	        23,19,12,4,26,8,16,7,27,20,13,2,

    	        41,52,31,37,47,55,30,40,51,45,33,48,

    	        44,49,39,56,34,53,46,42,50,36,29,32

    	    ]

Sbox = [
    	        [

    	            [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],

    	            [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],

    	            [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],

    	            [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],

    	        ],

    	        [

    	            [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],

    	            [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],

    	            [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],

    	            [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],

    	        ],

    	        [

    	            [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],

    	            [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],

    	            [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],

    	            [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],

    	        ],

    	        [

    	            [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],

    	            [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],

    	            [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],

    	            [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],

    	        ],

    	        [

    	            [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],

    	            [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],

    	            [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],

    	            [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],

    	        ],

    	        [

    	            [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],

    	            [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],

    	            [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],

    	            [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],

    	        ],

    	        [

    	            [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],

    	            [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],

    	            [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],

    	            [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],

    	        ],

    	        [

    	            [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],

    	            [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],

    	            [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],

    	            [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],

    	        ]

    	    ]

    	rout = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

    	def __init__(self):

    		self.subkey = [[[1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1], [1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1], [1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1], [1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1], [1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1], [1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0], [1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1], [0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0], [0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0], [0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1], [0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0], [0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0], [1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0], [1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0], [1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0], [1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0]], [[1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0], [1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0], [1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0], [1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0], [0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0], [0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0], [0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1], [0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0], [0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0], [1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1], [1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0], [1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1], [1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1], [1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1], [1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1], [1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1]]]



    	def permute(self, lst, tb):

    		return [lst[i-1] for i in tb]



    	def f(self,riti,subkeyi):

    		tmp = [i^j for i,j in zip(subkeyi,self.permute(riti,DES.E))]

    		return  self.permute(sum([[int(l) for l in str(bin(DES.Sbox[i][int(str(tmp[6*i])+str(tmp[6*i+5]),2)][int("".join(str(j) for j in tmp[6*i+1:6*i+5]),2)])[2:].zfill(4))] for i in range(8)],[]),DES.Pbox)



    	def des_main(self,m,mark):

    		sbkey = self.subkey[0]

    		#if mark == 'e' else self.subkey[1]

    		# tmp =  self.permute([int(i) for i in list((m).ljust(64,"0"))],self.IP)

    		tmp =  [int(i) for i in list((m).ljust(64,"0"))]

global kkk
print (kkk)
    		for i in range(kkk):

    			tmp = tmp[32:] + [j^k for j,k in zip(tmp[:32],self.f(tmp[32:],sbkey[i if mark != 'd' else kkk-1-i]))]

    		return "".join([str(i) for i in self.permute(tmp[32:]+tmp[:32],self.IP_re)])



    	def des_encipher(self,m):

    		m = "".join([bin(ord(i))[2:].zfill(8) for i in m])

des_en = self.des_main (m, &#39;e&#39;)
    		return "".join([chr(int(des_en[i*8:i*8+8],2)) for i in range(8)])



    	def des_decipher(self,c):

    		c = "".join([bin(ord(i))[2:].zfill(8) for i in c])

des_de = self.des_main (c, &#39;d&#39;)
    		return "".join([chr(int(des_de[i*8:i*8+8],2)) for i in range(8)])



    def test():

    	import base64

global kkk
    	while kkk >=0:

desobj = DES ()
    		# cipher = desobj.des_encipher("12345678")

    		cipher = '\x01\x19\xe1+\x92\xd9\x15%'

    		message1 = desobj.des_decipher(cipher)

    		print(message1)

kkk = 1
    if __name__=='__main__':

        test()



    ```



Decryption result (partial):


```

14
t-ÏEÏx§

13

y0ur9Ood
12

μp ^ Ûé = ¹
11

) Á`rûÕû
```



It can be seen that n is 13, and flag is `flag{y0ur9Ood}`




## Reference


Tsinghua University graduate data security courseware
- https://en.wikipedia.org/wiki/Data_Encryption_Standard
