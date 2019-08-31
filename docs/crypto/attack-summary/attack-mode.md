[EN](./attack-mode.md) | [ZH](./attack-mode-zh.md)
# Introduction


## Attack mode


When we attack a cryptography system, we get more or less information about the system. Depending on the amount of information we receive, the methods we can use may vary. In today&#39;s cryptanalysis, we generally assume that the attacker knows the cryptographic algorithm. This assumption is reasonable because there are many secret algorithms in history that are finally known, such as RC4. There are many ways to be known, such as spying, reverse engineering, etc.


Here we divide the attack mode into the following categories based on how much information the attacker obtains from the cryptography system.


- ** ciphertext attack only**: The attacker can only get some encrypted ciphertext.
- ** Known plaintext attack**: The attacker has some plaintext corresponding to the ciphertext.
- **Select plaintext attack**: The attacker can choose some plaintext when starting the attack and get the encrypted ciphertext. If an attacker can select a new plaintext based on the acquired information and obtain the corresponding ciphertext in the middle of the attack, it is called an adaptive selective plaintext attack.
- **Select ciphertext attack**: The attacker can select some ciphertexts and get the decrypted plaintext before starting the attack. If an attacker can select some new ciphertexts based on the information that has been acquired and obtain the corresponding plaintext, the attacker is called adaptive ciphertext attack.
- **Related key attack**: An attacker can obtain encrypted or decrypted ciphertext or plaintext of two or more related keys. But the attacker does not know these keys.


## Common attack methods


According to different attack modes, there may be different attack methods. Currently, common attack methods mainly include


- violent attacks
- Intercommunication attack
- Linear analysis
- Differential analysis
- Impossible differential analysis
- Integration analysis
- Algebraic analysis
- Related key attack
- Side channel attack


## references


- https://zh.wikipedia.org/wiki/%E5%AF%86%E7%A0%81%E5%88%86%E6%9E%90
