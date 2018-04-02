from functools import reduce
import gmpy
import json, binascii


def modinv(a, m):
    return int(gmpy.invert(gmpy.mpz(a), gmpy.mpz(m)))


def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a * b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * modinv(p, n_i) * p
    return int(sum % prod)


nset = []
cset = []
with open("data.txt") as f:
    now = f.read().strip('\n').split('\n')
    for item in now:
        item = item.split(',')
        nset.append(int(item[0]))
        cset.append(int(item[1]))

m = chinese_remainder(nset, cset)
m = int(gmpy.mpz(m).root(19)[0])
print binascii.unhexlify(hex(m)[2:-1])
