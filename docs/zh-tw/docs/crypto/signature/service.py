#!/usr/bin/python -u
import Crypto
from Crypto.Util.number import ceil_div
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as RSAsign
from Crypto.Hash import SHA
#from SECRET import flag
from random import shuffle
import sys
from binascii import b2a_hex

key = RSA.generate(1024)
a=["super", "important", "information", "for", "admin", "only", "some", "more","words", "just", "because" ]
shuffle(a)
message = ' '.join(a[:5])
# print message
# print "key.n",key.n
# print "key.e",key.e
h = SHA.new(message)
signer = RSAsign.new(key)
signature = signer.sign(h)
print "Welcome to admin's music portal.\nTo verify that you are the owner of this service\nsend the public key which will verify the following signature :\n"
print "Message   ->", message
print
print "Signature ->", signature.encode("hex")
sys.stdout.flush()

while True:
    try:
        n = long(raw_input("Enter n:"))
        e = long(raw_input("Enter e:"))
        sys.stdout.flush()
        if e >= 3 and n>=int(signature.encode("hex"),16) and n.bit_length()<=1025:
            break
    except ValueError:
        print "Invalid input"
    else:
        print "Invalid PublicKey"
sys.stdout.flush()
input_key = RSA.construct((n,e))
verifier = RSAsign.new(input_key)
if verifier.verify(h,signature):
    print flag
else:
    print "Music is only for admin's eyes."

sys.stdout.flush()

import libnum