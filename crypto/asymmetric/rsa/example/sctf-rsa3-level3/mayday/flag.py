from functools import reduce
import gmpy
from libnum import *
import json, binascii
def modinv(a, m):
    return int(gmpy.invert(gmpy.mpz(a), gmpy.mpz(m)))

def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * modinv(p, n_i) * p
    return int(sum % prod)

with open("my.json") as dfile:
    data = json.loads(dfile.read())

data = {k:[d.get(k) for d in data] for k in {k for d in data for k in d}}

t_to_e = chinese_remainder(data['n'], data['c'])
## modify e
t = int(gmpy.mpz(t_to_e).root(19)[0])

print hex(t)[2:-1].decode('hex')
