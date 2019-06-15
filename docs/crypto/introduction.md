[EN](./introduction.md) | [ZH](./introduction-zh.md)
Cryptography can generally be divided into classical cryptography and modern cryptography.


Among them, classical cryptography, as a practical art, its coding and deciphering usually depends on the creativity and skill of designers and adversaries, and does not clearly define the original cryptography. Classical cryptography mainly includes the following aspects:


- Monoalphabetic Cipher
- Polyalphabetic Cipher
- Strange encryption


Modern cryptography originated from a large number of related theories in the middle and late 20th century. In 1949, Shan Shan published a classic paper entitled &quot;Communication Theory of Security Systems&quot;, marking the beginning of modern cryptography. Modern cryptography mainly includes the following aspects:


- Symmetric Cryptography, represented by DES, AES, and RC4.
- Asymmetric Cryptography, represented by RSA, ElGamal, elliptic curve encryption.
- Hash function, represented by MD5, SHA-1, SHA-512, etc.
- Digital Signature, represented by RSA signature, ElGamal signature, and DSA signature.


Among them, the symmetric encryption system is mainly divided into two ways:


- Block Cipher, also known as block cipher.
- Stream Cipher, also known as stream cipher.


In general, the fundamental goal of password designers is to protect information and information systems.


- Confidentiality (Confidentiality)
- Integrity
- Availability
- Authentication
- Non-repudiation


Among them, the first three are called the three elements of CIA for information security.


For password crackers, it is generally necessary to find a way to identify the cryptographic algorithm, and then brute force, or use the cryptosystem vulnerability to crack. Of course, it is also possible to bypass the corresponding detection by constructing a false hash value or a digital signature.


In general, we will assume that the attacker knows the cryptosystem to be cracked, and the attack types are usually divided into the following four types:


| Attack Type | Description|
| ------------ | ------------------------------------------ |

| ciphertext attack | only has ciphertext |
| Known plaintext attack | Have ciphertext and corresponding plaintext |
| Select plaintext attack | Have encryption permission, can encrypt the plaintext and get the corresponding ciphertext|
| Select ciphertext attack | Have decryption permission, can decrypt the ciphertext and get the corresponding plaintext |


!!! note 

Note: I have previously written about the common scenarios of these attacks. As I continue to learn, I gradually realize that these types of attacks focus on describing the capabilities of attackers and may be applicable to a wide variety of scenarios. Therefore, the amendment was made.


Recommend some information here


- [Khan Academy Open Class] (http://open.163.com/special/Khan/moderncryptography.html)
- [In-depth cryptography - Principles and Applications of Common Encryption Technologies] (https://github.com/yuankeyang/python/blob/master/%E3%80%8A%E6%B7%B1%E5%85%A5% E6%B5%85%E5%87%BA%E5%AF%86%E7%A0%81%E5%AD%A6%E2%80%94%E2%80%94%E5%B8%B8%E7% 94%A8%E5%8A%A0%E5%AF%86%E6%8A%80%E6%9C%AF%E5%8E%9F%E7%90%86%E4%B8%8E%E5%BA% 94%E7%94%A8%E3%80%8B.pdf)
- https://cryptopals.com/, a bunch of cryptography exercises.


!!! note

It is recommended to consider whether to buy a book in the case of reading the open class and simply looking at the e-book, because the book is usually left unused.


## Reference


- [Wikipedia-Cryptography] (https://en.wikipedia.org/wiki/%E5%AF%86%E7%A0%81%E5%AD%A6)


!!! info

Most of the definitions and examples in this section refer to Wikipedia.