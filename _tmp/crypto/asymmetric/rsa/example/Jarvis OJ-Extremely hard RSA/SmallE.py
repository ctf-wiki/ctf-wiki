#/usr/bin/python
# coding=utf-8
import gmpy2
from Crypto.PublicKey import RSA
from multiprocessing import Pool
pool = Pool(4)

with open('./pubkey.pem', 'r') as f:
    key = RSA.importKey(f)
    N = key.n
    e = key.e
with open('flag.enc', 'r') as f:
    cipher = f.read().encode('hex')
    cipher = int(cipher, 16)


def calc(j):
    print j
    a, b = gmpy2.iroot(cipher + j * N, 3)
    if b == 1:
        m = a
        print '{:x}'.format(int(m)).decode('hex')
        pool.terminate()
        exit()


def SmallE():
    inputs = range(0, 130000000)
    pool.map(calc, inputs)
    pool.close()
    pool.join()


if __name__ == '__main__':
    print 'start'
    SmallE()
