import json
from sympy import randprime

e = 7
m = int(open('flag').read().strip().encode('hex'), 16)

for i in range(7):
    p = randprime(2 ** 256, 2 ** 257)
    q = randprime(2 ** 256, 2 ** 257)
    n = p * q
    assert m < n
    c = pow(m, e, n)
    print json.dumps({'n': n, 'e': e, 'c': c})
