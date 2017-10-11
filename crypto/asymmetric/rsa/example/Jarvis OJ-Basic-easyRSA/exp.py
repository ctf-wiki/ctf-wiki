import gmpy2
p = 13574881
q = 23781539
n = p * q
e = 23
c = 0xdc2eeeb2782c
phin = (p - 1) * (q - 1)
d = gmpy2.invert(e, phin)
p = gmpy2.powmod(c, d, n)
tmp = hex(p)
print tmp, tmp[2:].decode('hex')
