[EN](./csprng.md) | [ZH](./csprng-zh.md)
#密码安全 pseudo-random number generator


## Introduction


The cryptographically secure pseudo-random number generator (CSPRNG), also known as the cryptographic pseudo-random number generator (CPRNG), is a special pseudo-random number generation. Device. It needs to meet some of the necessary features to be suitable for cryptographic applications.


Many aspects of cryptography require random numbers


- Key generation
- Generate initialization vector, IV, CBC, CFB, OFB mode for grouping passwords
- nounce, used to prevent replay attacks and CTR mode of block ciphers, etc.
-   [one-time pads](https://en.wikipedia.org/wiki/One-time_pad)

- Salt in some signature schemes, such as [ECDSA] (https://en.wikipedia.org/wiki/ECDSA), [RSASSA-PSS] (https://en.wikipedia.org/w/index.php ?title=RSASSA-PSS&amp;action=edit&amp;redlink=1)


## demand


There is no doubt that the requirements for cryptographically secure pseudo-random number generators are certainly higher than for general pseudo-random number generators. In general, CSPRNG requirements can be divided into two categories.


- Pass the statistical randomness test. CSPRNG must pass [next-bit test] (https://en.wikipedia.org/wiki/Next-bit_test), that is, knowing the first k bits of a sequence, it is impossible for an attacker to A probability greater than 50% predicts the next bit. One point mentioned here is that Yao Zhizhi proved in 1982 that if a generator can pass [next-bit test] (https://en.wikipedia.org/wiki/Next-bit_test), then it can also pass all other Polynomial time statistics test.
- Must be able to resist strong enough attacks, such as when the initial state of the generator or the state of the runtime is known to the attacker, the attacker is still unable to obtain the generated random number before the leak state.


## Categories


As far as the current situation is concerned, the design of CSPRNG can be divided into the following three categories.


- Based on cryptographic algorithms such as ciphertext or hash values.
- Based on math problems
- Some special purpose designs


## references


-   https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator