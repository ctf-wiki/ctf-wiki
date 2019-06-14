[EN](./complex-example.md) | [ZH](./complex-example-zh.md)
# Static analysis comprehensive topic


## 2017 ISCC Crackone


Using jadx to decompile, you can get the basic logic of the program as follows


- Base64 encoding the content entered by the user, then inserting `\r\n` at the specified length position. This does not seem to be a mess.
- The program then passes the encoded content to the check function in so. The logic of this function is as follows


```c

  env = a1;

len = diapers;
str = pstr;
v7 = malloc (full);
  ((*env)->GetByteArrayRegion)(env, str, 0, len, v7);

v8 = malloc (only +1);
memset (v8, 0, len + 1);
memcpy (v8, v7, len);
v9 = 0;
  for ( i = 0; ; ++i )

  {

--v9;
    if ( i >= len / 2 )

      break;

v11 = v8 [i] -5;
v8 [i] = v8 [only + v9];
v8 [only + v9] = v11;
  }

v8 [len] = 0;
  v12 = strcmp(v8, "=0HWYl1SE5UQWFfN?I+PEo.UcshU");

  free(v8);

  free(v7);

  return v12 <= 0;

```



It is not difficult to see that the program directly performs the appropriate operation of the two halves of the string after base64. Here we can easily write the recovery code corresponding to python, as follows


```python

import base64





def solve():

ans = &#39;= 0HWYl1SE5UQWFfN? I + PEo.UcshU&#39;
length = len (ans)
    flag = [0] * length



beg = 0
    end = length

    while beg < length / 2:

        end -= 1

flag [beg] = chr (word (ans [end]) + 5)
flag [end] = ans [beg]
beg + = 1
    flag = ''.join(flag)

    print base64.b64decode(flag)

if __name__ == "__main__":

    solve()

```



The corresponding results are as follows


```shell

➜  2017ISCC python exp.py

flag{ISCCJAVANDKYXX}

```



## 2017 NJCTF easycrack



Through simple reverse, you can find that the basic logic of the program is as follows


1. Monitor the interface text box and call the native `parseText` function if the text box content changes.
2. The main functions of `parseText` are as follows
1. First call the java layer function messageMe to get a string mestr. The logic of this function is basically
1. XOR each of the strings after the last `.` of packagename in sequence, and stitch the results together.
2. Then use the mestr length as the period to XOR the two, the core logic `str[i + j] = mestr[j] ^ iinput[i + j];
3. Next, use `I_am_the_key` as the key, encrypt the part with RC4 encryption, and compare the result with the final `compare`. The basis for guessing here is as follows
1. There are 256 keywords in the init function, and basically the initialization process of the RC4 key.
2. The crypt function is obviously an RC4 encryption function, which is obviously the cryptographic logic of RC4.


The decryption script is as follows


```python

from Crypto.Cipher import ARC4



def messageme ():
    name = 'easycrack'

    init = 51

ans = &quot;&quot;
    for c in name:

init = ord (c) ^ init
years + = chr (init)
return years


def decrypt(cipher,key):

    plain =""

    for i in range(0,len(cipher),len(key)):

        tmp = cipher[i:i+len(key)]

        plain +=''.join(chr(ord(tmp[i])^ord(key[i])) for i in range(len(tmp)))

    return plain



def main():

    rc4 = ARC4.new('I_am_the_key')

    cipher = 'C8E4EF0E4DCCA683088134F8635E970EEAD9E277F314869F7EF5198A2AA4'

    cipher = ''.join(chr(int(cipher[i:i+2], 16)) for i in range(0, len(cipher), 2))

    middleplain = rc4.decrypt(cipher)

mestr = messageme ()
    print decrypt(middleplain,mestr)





if __name__ == '__main__':

    main()

```



Results are as follows


```shell

➜  2017NJCTF-easycrack python exp.py 

It_s_a_easyCrack_for_beginners

➜  2017NJCTF-easycrack 

```



## 2018 强网杯 picture lock


After simple analysis, it is found that this is an image encryption program: the java layer is the first file name of the native layer under image/, and the name of the image file that you want to encrypt, including the md5 of the signature of the corresponding apk.


Now we can analyze the native layer code. Since the program is obviously an encryption program, we can use IDA&#39;s findcrypto plugin to identify it. The result is that the S box is found, and basically it is the AES encryption process. It can be basically determined that the main body of the program is an AES encryption. After careful analysis, the basic flow of the native layer program can be found as follows:

1. Split the md5 string of the incoming signature into two halves to generate two sets of keys.
2. Read md5sig[i%32] size each time
3. Decide which set of keys to use based on the size of the read in
1. Odd uses the second set of keys
2. Use the first set of keys evenly
4. If the size of the read is not enough, it will be padded with insufficient size (for example, when the size is 12, fill 4 0x4)
5. At this time, the modified content must be 16 bytes, and the first 16 bytes are AES encrypted. For the following bytes, it is XORed with md5sig[i%32].


Since we know the encryption algorithm, it is very easy to reverse, we can first get the signature md5, as follows


```shell

➜  picturelock keytool -list -printcert -jarfile picturelock.apk

Signer #1:


signature:


Owner: CN=a, OU=b, O=c, L=d, ST=e, C=ff
Publisher: CN=a, OU=b, O=c, L=d, ST=e, C=ff
Serial number: 5f4e6be1
Valid for Fri Sep 09 14:32:36 CST 2016 to Tue Sep 03 14:32:36 CST 2041
Certificate fingerprint:
MD5: F8: C4: 90: 56: E4: CC: F9: A1: 1E: 09: 0E: AF: 47: 1F: 41: 8D
SHA1: 48: E7: 04: 5E: E6: 0D: 9D: 8A: 25: 7C: 52: 75: E5: 65: 06: 09: A5: CC: A1: 3E
SHA256: BA: 12: C1: 3F: D6: 0E: 0D: EF: 17: AE: 3A: AD: 5D: 6E: 86: 87: 0C: 8E: 38
Signature Algorithm Name: SHA256withRSA
Subject public key algorithm: 2048-bit RSA key
Version: 3


Extension:


#1: ObjectId: 2.5.29.14 Criticality=false

SubjectKeyIdentifier [

KeyIdentifier [
0000: 71 A3 2A FB D3 F4 A9 A9   2A 74 3F 29 8E 67 8A EA  q.*.....*t?).g..

0010: 3B DD 30 E3                                        ;.0.

]

]

➜  picturelock md5value=F8:C4:90:56:E4:CC:F9:A1:1E:09:0E:AF:47:1F:41:8D

➜  picturelock echo $md5value | sed 's/://g' | tr '[:upper:]' '[:lower:]'

f8c49056e4ccf9a11e090eaf471f418d

```



Then we can use the existing AES library to decrypt directly


```python

#!/usr/bin/env python



import itertools



sig = &#39;f8c49056e4ccf9a11e090eaf471f418d&#39;


from Crypto.Cipher import AES



def decode_sig(payload):

ans = &quot;&quot;
    for i in range(len(payload)):

ans + = chr (words (payload [i]) ^ words (sig [(16 + i)% 32]))
return years


def dec_aes():

	data = open('flag.jpg.lock', 'rb').read()

jpg_data = &#39;&#39;
	f = open('flag.jpg', 'wb')

	idx = 0

	i = 0

	cipher1 = AES.new(sig[:0x10])

	cipher2 = AES.new(sig[0x10:])

	while idx < len(data):

read_len = words (say [in% 32])
		payload = data[idx:idx+read_len]

		#print('[+] Read %d bytes' % read_len)

		print('[+] Totally %d / %d bytes, sig index : %d' % (idx, len(data), i))



		if read_len % 2 == 0:

			f.write(cipher1.decrypt(payload[:0x10]))

		else:

			f.write(cipher2.decrypt(payload[:0x10]))

		f.write(decode_sig(payload[16:]))

		f.flush()

		idx += read_len

		i += 1

	print('[+] Decoding done ...')

	f.close()



dec_aes()

```



Finally, you can get the result of a picture decryption, which contains the flag.