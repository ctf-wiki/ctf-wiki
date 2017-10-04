#coding=utf8
from Crypto.PublicKey import DSA
from hashlib import sha1
import gmpy2
with open('./dsa_public.pem') as f:
    key = DSA.importKey(f)
    y = key.y
    g = key.g
    p = key.p
    q = key.q
f3 = open(r"packet3/message3", 'r')
f4 = open(r"packet4/message4", 'r')
data3 = f3.read()
data4 = f4.read()
sha = sha1()
sha.update(data3)
m3 = int(sha.hexdigest(), 16)
sha = sha1()
sha.update(data4)
m4 = int(sha.hexdigest(), 16)
print m3, m4
s3 = 0x30EB88E6A4BFB1B16728A974210AE4E41B42677D
s4 = 0x5E10DED084203CCBCEC3356A2CA02FF318FD4123
r = 0x5090DA81FEDE048D706D80E0AC47701E5A9EF1CC
ds = s4 - s3
dm = m4 - m3
k = gmpy2.mul(dm, gmpy2.invert(ds, q))
k = gmpy2.f_mod(k, q)
tmp = gmpy2.mul(k, s3) - m3
x = tmp * gmpy2.invert(r, q)
x = gmpy2.f_mod(x, q)
print int(x)
