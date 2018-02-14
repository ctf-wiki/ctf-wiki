#!/usr/bin/python
import gmpy
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


def ext_rsa_decrypt(p, q, e, msg):
    m = bytes_to_long(msg)
    while True:
        n = p * q
        try:
            phi = (p - 1) * (q - 1)
            d = gmpy.invert(e, phi)
            privatekey = RSA.construct((long(n), long(e), long(d), long(p),
                                        long(q)))
            key = PKCS1_v1_5.new(privatekey)
            de_error = ''
            enc = key.decrypt(msg.decode('base64'), de_error)
            return enc
        except Exception as error:
            print error
            p = gmpy.next_prime(p**2 + q**2)
            q = gmpy.next_prime(2 * p * q)
            e = gmpy.next_prime(e**2)


p = 311155972145869391293781528370734636009
q = 315274063651866931016337573625089033553
n = p * q
e = 12405943493775545863
# pubkey = RSA.construct((long(n), long(e)))
# f = open('pubkey.pem', 'w')
# f.write(pubkey.exportKey())
g = open('flag.enc', 'r')
msg = g.read()
flag = ext_rsa_decrypt(p, q, e, msg)
print flag
