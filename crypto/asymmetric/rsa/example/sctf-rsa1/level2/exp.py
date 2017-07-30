from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
import gmpy2
from base64 import b64decode
d = 29897859398360008828023114464512538800655735360280670512160838259524245332403L
with open('./public.key') as f:
    key = RSA.importKey(f)
    n = key.n
    e = key.e


def getprivatekey(n, e, d):
    priviatekey = RSA.construct((long(n), long(e), long(d)))
    with open('private.pem', 'w') as f:
        f.write(priviatekey.exportKey())


def decrypt():
    with open('./level3.passwd.enc') as f:
        cipher = f.read()
    with open('./private.pem') as f:
        key = RSA.importKey(f)
    print key.decrypt(cipher)


getprivatekey(n, e, d)
decrypt()
