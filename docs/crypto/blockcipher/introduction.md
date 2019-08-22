[EN](./introduction.md) | [ZH](./introduction-zh.md)
#块加密


## Overview


The so-called block encryption is to encrypt a piece of plaintext each time. Common encryption algorithms are available.


- IDEA encryption
- DES encryption
- AES encryption


Block encryption is also symmetric encryption.


In fact, we can also understand block encryption as a special alternative password, but each time it is replaced by a large block. It is precisely because of a large block, the plaintext space is huge, and for different keys, we can&#39;t make a table to correspond to the corresponding ciphertext, so we must have ** complex ** encryption and decryption algorithm to encrypt and decrypt the ciphertext .


At the same time, plain text can often be very long or short, so two blocks are often needed for block encryption.


- padding, ie padding to the specified packet length
- Packet encryption mode, which is the way in which plaintext packets are encrypted.


## Basic strategy


In the design of block ciphers, Shannon proposed two strategies: confusion and diffusion.


### Confusion


Confusion, Confusion, makes the statistical relationship between the ciphertext and the key as complex as possible, so that the attacker can not guess the key even if it acquires some statistical characteristics of the ciphertext. Generally, complex nonlinear transformations can be used to get a good confusion. The common methods are as follows:


- S box
- Multiplication


### Diffusion


Diffusion, Diffusion, makes every bit in the plaintext affect many bits in the ciphertext. Common methods are


- Linear transformation
- replacement
- shift, rotate


## Common encryption and decryption structure


The main block block encryption currently used is the structure.


- Iterative structure, because the iterative structure is easy to design and implement, while facilitating security assessment.


### Iterative structure


#### Overview


The iterative structure is basically as follows, generally consisting of three parts


- Key replacement
- Round encryption function
- Round decryption function


![image-20180714222206782](./figure/iterated_cipher.png)



####轮函数


At present, the main functions of the round function are mainly the following design methods.


- Feistel Network, invented by Horst Feistel, one of the DES designers.
- DES
- Substitution-Permutation Network(SPN)

    - AES

- Other programs


#### Key Expansion


At present, there are many methods for key expansion. There is no perfect key expansion method. The basic principle is that each bit of the key affects multiple rounds of round keys as much as possible.