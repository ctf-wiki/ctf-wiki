[EN](./sha1.md) | [ZH](./sha1-zh.md)
# SHA1



## Basic description


The input and output of SHA1 are as follows


- Input: Any long message divided into **512 bits** long packets. First, bit 1 is added to the right side of the message, and then a number of bits 0 are added until the bit length of the message satisfies the modulo remainder of 512, which is 448, which is congruent with 448 modulo 512.
- Output: 160-bit message digest.


For a detailed introduction, please search for yourself.


In general, we can determine whether the SHA1 function is through the initialization of the function. In general, if a function has the following five initialized variables, you can guess that the function is a SHA1 function, because this is the initialization IV of the SHA1 function.


```

0x67452301

0xEFCDAB89

0x98BADCFE

0x10325476

0xC3D2E1F0

```



The first four are similar to the MD5, and the latter are new.


## Crack


For now, SHA1 is no longer safe, because Google has previously published two pdfs with the same sha1 value, please refer to [shattered] (https://shattered.io/).


There is also a more interesting website here: https://alf.nu/SHA1.


## 2017 SECCON SHA1 is dead



The title is described below


1. file1 != file2

2. SHA1(file1) == SHA1(file2)

3. SHA256(file1) <> SHA256(file2)

4. 2017KiB < sizeof(file1) < 2018KiB

5. 2017KiB < sizeof(file2) < 2018KiB



1KiB = 1024 bytes


That is, we need to find two files that satisfy the above constraints.


Here is the idea of Google&#39;s previously published documents, and, very importantly, as long as the given first 320 bytes, the hash added after adding the same byte is still the same, here we test the following


```shell

➜  2017_seccon_sha1_is_dead git:(master) dd bs=1 count=320 <shattered-1.pdf| sha1sum

Recorded the reading of 320+0
Recorded the write of 320+0
320 bytes copied, 0.00796817 s, 40.2 kB/s

f92d74e3874587aaf443d1db961d4e26dde13e9c -
➜  2017_seccon_sha1_is_dead git:(master) dd bs=1 count=320 <shattered-2.pdf| sha1sum

Recorded the reading of 320+0
Recorded the write of 320+0
320 bytes copied, 0.00397215 s, 80.6 kB/s

f92d74e3874587aaf443d1db961d4e26dde13e9c -
```



Then we can write the program directly, as follows


```python

from hashlib import sha1

from hashlib import sha256



pdf1 = open('./shattered-1.pdf').read(320)

pdf2 = open('./shattered-2.pdf').read(320)

pdf1 = pdf1.ljust (2017 * 1024 + 1 - 320, &quot;00&quot;) #padding pdf to 2017Kib + 1
pdf2 = pdf2.light (2017 * 1024 + 1 - 320, &quot;00&quot;)
open("upload1", "w").write(pdf1)

open("upload2", "w").write(pdf2)



print sha1(pdf1).hexdigest()

print sha1(pdf2).hexdigest()

print sha256(pdf1).hexdigest()

print sha256(pdf2).hexdigest()

```



## references


- https://www.slideshare.net/herumi/googlesha1






