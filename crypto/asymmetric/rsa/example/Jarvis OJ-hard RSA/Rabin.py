#!/usr/bin/python
# coding=utf-8
import gmpy2
import string
from Crypto.PublicKey import RSA

# 读取公钥参数
with open('pubkey.pem', 'r') as f:
    key = RSA.importKey(f)
    N = key.n
    e = key.e
with open('flag.enc', 'r') as f:
    cipher = f.read().encode('hex')
    cipher = string.atoi(cipher, base=16)
    # print cipher
print "please input p"
p = int(raw_input(), 10)
print 'please input q'
q = int(raw_input(), 10)
# 计算yp和yq
inv_p = gmpy2.invert(p, q)
inv_q = gmpy2.invert(q, p)

# 计算mp和mq
mp = pow(cipher, (p + 1) / 4, p)
mq = pow(cipher, (q + 1) / 4, q)

# 计算a,b,c,d
a = (inv_p * p * mq + inv_q * q * mp) % N
b = N - int(a)
c = (inv_p * p * mq - inv_q * q * mp) % N
d = N - int(c)

for i in (a, b, c, d):
    s = '%x' % i
    if len(s) % 2 != 0:
        s = '0' + s
    print s.decode('hex')
