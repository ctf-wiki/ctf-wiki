[EN](./attack.md) | [ZH](./attack-zh.md)
# Hash Attack



Common hash function attack methods are mainly


- Violent attack: does not depend on any algorithm details, only related to the length of the hash value;
- Birthday Attack: The structure and any algebraic weak nature of the hash function are not used, depending only on the length of the message digest, which is the length of the hash value.
- Meet-In-The-Middle: It is a variant of a birthday attack. Instead of comparing hash values, it compares intermediate variables. This type of attack is mainly used to attack Hash schemes with a packet chain structure.
- Password analysis: Depends on the design shortcomings of specific algorithms.


## violent attack


**HashCat tool** can be said to be the best CPU and GPU-based cracking Hash software, the related links are as follows


[HashCat official website] (http://www.hashcat.net/hashcat/)


[HashCat Simple to use] (http://www.freebuf.com/sectool/112479.html)


## hash length extension attacks
### Introduction


The basic definition is as follows, from [Wikipedia] (https://en.wikipedia.org/wiki/%E9%95%BF%E5%BA%A6%E6%89%A9%E5%B1%95%E6% 94% BB% E5% 87% BB).


Hash Length Extension Attacks are pointers to certain cryptographic hash functions that allow additional information. This attack applies to all hash functions that take the H(key ∥ message) construct in the case where the length of the ** message and the key is known**. Algorithms based on the Merkle–Damgård constructs such as MD5 and SHA-1 show vulnerabilities to such attacks.


This type of hash function has the following characteristics


- The message padding method is similar. First, add a 1 after the message, then fill in a number of 0s until the total length is congruent with 448, and finally attach a 64-bit message length (before filling).
- Each link variable obtained will be used as the initial vector IV for the next execution of the hash function. In the last block, the corresponding link variable will be converted to a hash value.


The following conditions should be met during a general attack.


- We know the length of the key, if you don&#39;t know, you need to burst it out.
- We can control the message of the message.
- We already know the hash value of a message containing a key.


So we can get a pair (messge, x) to satisfy x = H (key ∥ message) although we are not sure about the contents of the key.


### Attack principle


Here we can assume that we know the hash value of hash(key+s), where s is known, then it will be filled when it is calculated. Then we can first get the key+s extended by key+s, ie


now=key|s|padding



Then if we attach a part of the information extra after the now, ie


key|s|padding|extra



When you go to calculate the hash value,


1. The extra is filled until the condition is met.
2. Calculate the link variable IV1 corresponding to now, and we already know the hash value of this part, and the algorithm that the link variable produces the hash value is reversible, so we can get the link variable.
3. The hash algorithm is performed on the extra part according to the obtained link variable IV1, and the hash value is returned.


So now that we know the hash value of the first part, and we also know the value of extra, then we can get the last hash value.


And before we said that we can control the value of the message. So in fact, s, padding, extra, we can all control. So we can naturally find the corresponding (message, x) to satisfy x = hash (key | mesage).


### Examples


It seems that most of them are inside the web, and I don&#39;t know much about the web. I will not give examples for the time being.


### Tools


- [hashpump](https://github.com/bwall/HashPump)



Please refer to the readme on github for how to use it.


## hash algorithm is incorrectly designed
Some custom hash algorithms may be reversible.


### Hashinator

The logic of the topic is very simple. Pick a `password` from a well-known password dictionary &quot;rockyou&quot; and use a variety of hash algorithms to randomly hash 32 rounds. We need to crack the original `password` from the final hash result.


#### Analysis
The hash algorithms used in the title are: `md5`, `sha1`, `blake`, `scrypt`.
The key code is as follows:
```python

    password = self.generate_password()     # from rock_you.txt

Salt = self.generate_salt(password) # related to the length of the password
Hash_rounds = self.generate_rounds() # Generate the order in which the hash algorithm is executed
    password_hash = self.calculate_hash(salt + password, hash_rounds)

```

1. The program first randomly extracts a `password` from `rockyou.txt` as the encrypted plaintext.
2. Then generate a `salt` of length `128 - len(password)` based on the length of the extracted `password`.
3. Extract from the four hash algorithms listed above to form 32 rounds of hash operations.
4. Calculate the last `password_hash` given to us based on the previously obtained `password`, `salt`.


Obviously, we can&#39;t complete the problem by the inverse hash algorithm.
We know all the possible plaintexts, first considering whether we can complete the exhaustion by constructing a rainbow table. But notice that in the `generate_salt()` function, the length combination of `salt` and `password` exceeds the length of 128 bytes and is annotated.
```

    msize = 128 # f-you hashcat :D

```

So, can only helplessly give up.


In that case, there is only one possibility, that is, the algorithm is reversible. Looking at the concrete implementation of the `calculate_hash()` function, you can find the following suspicious code:
```python

for i in range(len(hash_rounds)):

    interim_salt = xor(interim_salt, hash_rounds[-1-i](interim_hash))

    interim_hash = xor(interim_hash, hash_rounds[i](interim_salt))

final_hash = interim_salt + interim_hash

```

Reorganize the information we know:
1. There are 32 rounds stored in hash_rounds, which is the hash function handle to be used in each round.
2. final_hash is the last hash result for us.
3. The contents of hash_rounds will also be printed to us after generation.
4. We want to get the values of `interim_salt` and `interim_hash` in the first round.
5. `interim_salt` and `interim_hash` are both 64bytes in length.


A closer look at the calculations of `interim_salt` and `interim_hash` reveals that it is reversible.


$$

interim\_hash_1 = interim\_hash_2 \oplus hash\_rounds[i](interim\_salt_3)

$$



In this line of code, we know $interim\_hash_1$ and $interim\_salt_3$, so we can get the value of $interim\_hash_2$, and $interim\_hash_2$ is the last round of `interim_hash`.
By pushing back 32 times in this way, you can get the initial `password` and `salt`.


The specific decryption script is:
```python

import
import hashlib

import socket

import threading

import socketserver

import struct

import time

import threading
# import pyscrypt

from base64 import b64encode, b64decode

from pwn import *

def md5(bytestring):

    return hashlib.md5(bytestring).digest()

def sha(bytestring):

    return hashlib.sha1(bytestring).digest()

def blake(bytestring):

    return hashlib.blake2b(bytestring).digest()

def scrypt(bytestring):

    l = int(len(bytestring) / 2)

    salt = bytestring[:l]

    p = bytestring[l:]

    return hashlib.scrypt(p, salt=salt, n=2**16, r=8, p=1, maxmem=67111936)

    # return pyscrypt.hash(p, salt, 2**16, 8, 1, dkLen=64)

def xor(s1, s2):

    return b''.join([bytes([s1[i] ^ s2[i % len(s2)]]) for i in range(len(s1))])

def main():

# io = socket.socket (family = socket.AF_INET)
# io.connect ((&#39;47.88.216.38&#39;, 20013))
io = remote (&#39;47 .88.216.38 &#39;, 20013)
print (io.recv (1000))
    ans_array = bytearray()

    while True:

buf = io.recv (1)
        if buf:

            ans_array.extend(buf)

        if buf == b'!':

            break



    password_hash_base64 = ans_array[ans_array.find(b"b'") + 2: ans_array.find(b"'\n")]

    password_hash = b64decode(password_hash_base64)

    print('password:', password_hash)

    method_bytes = ans_array[

        ans_array.find(b'used:\n') + 6 : ans_array.find(b'\nYour')

    ]

    methods = method_bytes.split(b'\n')

    methods = [bytes(x.strip(b'- ')).decode() for x in methods]

    print(methods)

    in_salt = password_hash[:64]

    in_hash = password_hash[64:]

    for pos, neg in zip(methods, methods[::-1]):

        '''

            interim_salt = xor(interim_salt, hash_rounds[-1-i](interim_hash))

            interim_hash = xor(interim_hash, hash_rounds[i](interim_salt))

        '''

        in_hash = xor(in_hash, eval("{}(in_salt)".format(neg)))

        in_salt = xor(in_salt, eval("{}(in_hash)".format(pos)))

    print(in_hash, in_salt)

    print(in_hash[-20:])

io.interactive ()
main()



```



#### Original hash algorithm
```python



import
import hashlib

import socket

import threading

import socketserver

import struct

import time



# import pyscrypt



from base64 import b64encode



def md5(bytestring):

    return hashlib.md5(bytestring).digest()



def sha(bytestring):

    return hashlib.sha1(bytestring).digest()



def blake(bytestring):

    return hashlib.blake2b(bytestring).digest()



def scrypt(bytestring):

    l = int(len(bytestring) / 2)

    salt = bytestring[:l]

    p = bytestring[l:]

    return hashlib.scrypt(p, salt=salt, n=2**16, r=8, p=1, maxmem=67111936)

    # return pyscrypt.hash(p, salt, 2**16, 8, 1)



def xor(s1, s2):

    return b''.join([bytes([s1[i] ^ s2[i % len(s2)]]) for i in range(len(s1))])



class HashHandler (socketserver.BaseRequestHandler):


    welcome_message = """

Welcome, young wanna-be Cracker, to the Hashinator.



To prove your worthiness, you must display the power of your cracking skills.



The test is easy:

1. We send you a password from the rockyou list, hashed using multiple randomly chosen algorithms.

2. You crack the hash and send back the original password.



As you already know the dictionary and won't need any fancy password rules, {} seconds should be plenty, right?



Please wait while we generate your hash...

    """



    hashes = [md5, sha, blake, scrypt]

    timeout = 10

    total_rounds = 32



    def handle(self):

        self.request.sendall(self.welcome_message.format(self.timeout).encode())



        password = self.generate_password()     # from rock_you.txt

Salt = self.generate_salt(password) # related to the length of the password
Hash_rounds = self.generate_rounds() # Generate the order in which the hash algorithm is executed
        password_hash = self.calculate_hash(salt + password, hash_rounds)

        self.generate_delay()



        self.request.sendall("Challenge password hash: {}\n".format(b64encode(password_hash)).encode())

        self.request.sendall("Rounds used:\n".encode())

        test_rounds = []

        for r in hash_rounds:

            test_rounds.append(r)



        for r in hash_rounds:

            self.request.sendall("- {}\n".format(r.__name__).encode())

        self.request.sendall("Your time starts now!\n".encode())
        self.request.settimeout(self.timeout)

        try:

            response = self.request.recv(1024)

            if response.strip() == password:

                self.request.sendall("Congratulations! You are a true cracking master!\n".encode())

                self.request.sendall("Welcome to the club: {}\n".format(flag).encode())

                return

        except socket.timeout:

            pass

        self.request.sendall("Your cracking skills are bad, and you should feel bad!".encode())





    def generate_password(self):

        rand = struct.unpack("I", os.urandom(4))[0]

        lines = 14344391 # size of rockyou

        line = rand % lines

        password = ""

        f = open('rockyou.txt', 'rb')

        for i in range(line):

            password = f.readline()

        return password.strip()



    def generate_salt(self, p):

        msize = 128 # f-you hashcat :D

        salt_size = msize - len(p)

        return os.urandom(salt_size)



    def generate_rounds(self):

        rand = struct.unpack("Q", os.urandom(8))[0]

        rounds = []

        for i in range(self.total_rounds):

            rounds.append(self.hashes[rand % len(self.hashes)])

rand = rand &gt;&gt; 2
        return rounds



    def calculate_hash(self, payload, hash_rounds):

        interim_salt = payload[:64]

        interim_hash = payload[64:]

        for i in range(len(hash_rounds)):

            interim_salt = xor(interim_salt, hash_rounds[-1-i](interim_hash))

            interim_hash = xor(interim_hash, hash_rounds[i](interim_salt))

            '''

            interim_hash = xor(

                interim_hash,

                hash_rounds[i](

                    xor(interim_salt, hash_rounds[-1-i](interim_hash))

                )

            )

            '''

        final_hash = interim_salt + interim_hash

        return final_hash



    def generate_delay(self):

        rand = struct.unpack("I", os.urandom(4))[0]

        time.sleep(rand / 1000000000.0)







class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    allow_reuse_address = True



PORT = 1337

HOST = '0.0.0.0'

flag = ""



with open("flag.txt") as f:

    flag = f.read()



def main():

server = ThreadedTCPServer ((HOST, PORT), HashHandler)
    server_thread = threading.Thread(target=server.serve_forever)

    server_thread.start()

    server_thread.join()



if __name__ == "__main__":

    main()





```
