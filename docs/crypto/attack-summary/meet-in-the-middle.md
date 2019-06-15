[EN](./meet-in-the-middle.md) | [ZH](./meet-in-the-middle-zh.md)
#中遇遇攻击- MITM


## Overview


The middle encounter attack is an attack method that exchanges space for time. It was proposed by Diffie and Hellman in 1977. From a personal point of view, people refer more to an idea, not only for cryptographic attacks, but also for other aspects, which can reduce the complexity of the algorithm.


The basic principle is as follows


Suppose E and D are encryption functions and decryption functions, respectively, k1 and k2 are the keys used for two encryptions respectively, then we have


$ C = E k_2 (E k_1 (P)) $


$P=D_{k_2}(D_{k_1}(C))$



Then we can launch


$E_{k_1}(P)=D_{k_2}(C)$



Then, when the user knows a pair of plaintext and ciphertext


1. An attacker can enumerate all k1s, store all the encrypted results of P, and sort them according to the size of the ciphertext.
2. The attacker further enumerates all k2, decrypts ciphertext C to get C1, and searches for C1 in the result of the first step of encryption. If we search, we can think that we have found the correct k1. And k2.
3. If you feel that the results obtained in the second step are not insured, we can also find some clear cipher pairs to verify.


Assuming that the key lengths for both k1 and k2 are n, then our violent enumeration would require $O(n^2)$, now we only need $O(n log_2n)$.


This is similar to the middle encounter attack of 2DES.


## topic


- 2018 National Crackmec, see the Wiki AES section
- 2018 Plaid CTF Transducipher, see the principle of the bit attack section.
- 2018 National CrackMe, see the discrete logarithmic part of the Wiki integer field
- 2018 WCTF RSA, see wiki RSA Complex section


## references


- https://zh.wikipedia.org/wiki/%E4%B8%AD%E9%80%94%E7%9B%B8%E9%81%87%E6%94%BB%E6%93%8A


