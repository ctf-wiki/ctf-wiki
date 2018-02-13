#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
----------------------------------------------------------------------------
"THE BEER-WARE LICENSE" (Revision 42):
ganapati (@G4N4P4T1) wrote this file. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return.
----------------------------------------------------------------------------
"""

from Crypto.PublicKey import RSA
import gmpy
from libnum import *
import requests
import re
import argparse


class FactorizationError(Exception):
    pass


class PublicKey(object):
    def __init__(self, key):
        """Create RSA key from input content
           :param key: public key file content
           :type key: string
        """
        # pub = RSA.importKey(key)
        self.n = key[0]
        self.e = key[1]
        self.key = key

    def prime_factors(self):
        """Factorize n using factordb.com
        """
        try:
            url_1 = 'http://www.factordb.com/index.php?query=%i'
            url_2 = 'http://www.factordb.com/index.php?id=%s'
            r = requests.get(url_1 % self.n)
            regex = re.compile("index\.php\?id\=([0-9]+)", re.IGNORECASE)
            ids = regex.findall(r.text)
            p_id = ids[1]
            q_id = ids[2]
            regex = re.compile("value=\"([0-9]+)\"", re.IGNORECASE)
            r_1 = requests.get(url_2 % p_id)
            r_2 = requests.get(url_2 % q_id)
            self.p = int(regex.findall(r_1.text)[0])
            self.q = int(regex.findall(r_2.text)[0])
            if self.p == self.q == self.n:
                raise FactorizationError()
        except:
            raise FactorizationError()

    def __str__(self):
        """Print armored public key
        """
        return self.key


class PrivateKey(object):
    def __init__(self, p, q, e, n):
        """Create private key from base components
           :param p: extracted from n
           :type p: int
           :param q: extracted from n
           :type q: int
           :param e: exponent
           :type e: int
           :param n: n from public key
           :type n: int
        """
        t = (p-1)*(q-1)
        d = self.find_inverse(e, t)
        self.key = RSA.construct((n, e, d, p, q))

    def decrypt(self, cipher):
        """Uncipher data with private key
           :param cipher: input cipher
           :type cipher: string
        """
        return self.key.decrypt(cipher)

    def __str__(self):
        """Print armored private key
        """
        return self.key.exportKey()

    def eea(self, a, b):
        if b == 0:
            return (1, 0)
        (q, r) = (a//b, a % b)
        (s, t) = self.eea(b, r)
        return (t, s-(q * t))

    def find_inverse(self, x, y):
        inv = self.eea(x, y)[0]
        if inv < 1:
            inv += y
        return inv


if __name__ == "__main__":
    """Main method (entrypoint)
    F4An8LIn_rElT3r_rELa53d_Me33Age_aTtaCk_e_I2_s7aLL
    """

    words = open("../rsa3/w.txt", 'r')
    lists = words.readlines()
    for oneList in lists:
        oneRec = oneList.strip().split(',')

        cipher = oneRec[2]
        key = [int(oneRec[0]),19]

        pub_key = PublicKey(key)

        priv_key = None

        print "Try Hastad's attack"
        orig = int(cipher,16)

        c = orig
        while True:
            m = gmpy.root(c, 3)[0]
            if pow(m, 3, pub_key.n) == orig:
                unciphered = n2s(m)
                print m
                break
            c += pub_key.n
        print n2s(m-int(oneRec[1]))
