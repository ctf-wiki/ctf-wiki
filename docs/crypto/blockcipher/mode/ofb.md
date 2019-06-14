[EN](./ofb.md) | [ZH](./ofb-zh.md)
# OFB


OFB is called output feedback mode, and its feedback content is packet-encrypted content instead of ciphertext.


## Encryption


![](./figure/ofb_encryption.png)



## decryption


![](./figure/ofb_decryption.png)



## Advantages and disadvantages


### Advantages


1. Does not have error propagation characteristics.


### Disadvantages


1. IV does not require confidentiality, but a different IV must be chosen for each message.
2. Does not have self-synchronization capability.


## Applicable scene


Applicable to some scenarios where the plaintext redundancy is relatively large, such as image encryption and voice encryption.

