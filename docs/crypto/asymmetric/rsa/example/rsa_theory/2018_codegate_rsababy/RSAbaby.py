#!/usr/bin/python
#-*- coding:utf-8 -*-

from gmpy2 import *
import sys
import time
import struct

def PrintIntro():
    print "██████╗ ███████╗ █████╗ ██████╗  █████╗ ██████╗ ██╗   ██╗"
    print "██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝"
    print "██████╔╝███████╗███████║██████╔╝███████║██████╔╝ ╚████╔╝ "
    print "██╔══██╗╚════██║██╔══██║██╔══██╗██╔══██║██╔══██╗  ╚██╔╝  "
    print "██║  ██║███████║██║  ██║██████╔╝██║  ██║██████╔╝   ██║   "
    print "╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═════╝    ╚═╝   "

def xgcd(b, n):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while n != 0:
        q, b, n = b // n, n, b % n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return  b, x0, y0

def mulinv(b, n):
    g, x, _ = xgcd(b, n)
    if g == 1:
        return x % n

def GenerateN(randomST):
    k1 = mpz_urandomb(randomST, 2048)
    k2 = mpz_urandomb(randomST, 2048)

    p = next_prime(k1)
    q = next_prime(k2)

    if is_prime(p, 50) and is_prime(q, 50):
        return [p, q]

def GenerateKeys(p, q):
    e = 65537
    n = p * q
    pi_n = (p-1)*(q-1)
    d = mulinv(e, pi_n)
    h = (d+p)^(d-p)
    g = d*(p-0xdeadbeef)

    return [e, n, h, g]

def EncryptMsg():
    Flag = "########################################"

    PrintIntro()

    f = open("/dev/urandom")
    seed = f.read(8)
    f.close()
    randomST = random_state(struct.unpack(">Q", seed)[0])

    print("[*] Generating Key ...\n")
    p, q = GenerateN(randomST)
    e, N, hint, gint = GenerateKeys(p, q)
    time.sleep(2)

    print("[*] Completed !!!\n")
    time.sleep(1)

    Flag = Flag.ljust(255, "\x2a")
    Flag = int(Flag.encode('hex'),16)

    EncryptedData = powmod(Flag, e, N)
    
    print("[*] Encrypted Data : %d\n" % EncryptedData)
    print("[*] N : %d\n" % N)
    print("[*] h : %d\n" % hint)
    print("[*] g : %d\n" % gint)

if __name__ == '__main__':
    EncryptMsg()
