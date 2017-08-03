# -*- coding: utf-8 -*-
import sys
import os
from Crypto.Random import random
from Crypto.Util.number import *
import signal
signal.alarm(60)

flagfile = "flag"

PBITS = 201


with open(flagfile) as f:
    flag = f.read()
if len(flag) > (PBITS - 1) / 8:
    print "ERROR: too long flag"
    sys.exit(1)

def genkey(k):
    p = getPrime(k)
    g = random.randrange(2, p)
    x = random.randrange(1, p-1)
    h = pow(g, x, p)
    pk = (p, g, h)
    sk = (p, x)
    return (pk, sk)

def encrypt(pk, m, r = None):
    (p, g, h) = pk
    if r is None:
        r = random.randrange(1, p-1)
    c1 = pow(g, r, p)
    c2 = (m * pow(h, r, p)) % p
    return (c1, c2)

def main():
    (pk, sk) = genkey(PBITS)
    
    print "Encryption Oracle"
    sys.stdout.flush()
    for i in range(10):
        sys.stdout.write("m = ")
        sys.stdout.flush()
        try:
            m = long(sys.stdin.readline())
        except ValueError:
            break
        
        sys.stdout.write("r = ")
        sys.stdout.flush()
        try:
            r = long(sys.stdin.readline())
        except ValueError:
            r = None
        if r < 0:
            print "Invalid r"
            continue
        
        (c1, c2) = encrypt(pk, m, r)
        print "(%d, %d)" % (c1, c2)
        sys.stdout.flush()
    
    (c1, c2) = encrypt(pk, bytes_to_long(flag))
    print "My Secret Message:", "(%d, %d)" % (c1, c2)
    sys.stdout.flush()

main()
