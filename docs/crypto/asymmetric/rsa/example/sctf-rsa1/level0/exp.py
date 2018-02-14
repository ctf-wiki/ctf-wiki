from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
import gmpy2
from base64 import b64decode

p = 250527704258269
q = 74891071972884336452892671945839935839027130680745292701175368094445819328761543101567760612778187287503041052186054409602799660254304070752542327616415127619185118484301676127655806327719998855075907042722072624352495417865982621374198943186383488123852345021090112675763096388320624127451586578874243946255833495297552979177208715296225146999614483257176865867572412311362252398105201644557511678179053171328641678681062496129308882700731534684329411768904920421185529144505494827908706070460177001921614692189821267467546120600239688527687872217881231173729468019623441005792563703237475678063375349
e = 65537
n = p * q


def getprivatekey(n, e, p, q):
    phin = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phin)
    priviatekey = RSA.construct((long(n), long(e), long(d)))
    with open('private.pem', 'w') as f:
        f.write(priviatekey.exportKey())


def decrypt():
    with open('./level1.passwd.enc') as f:
        cipher = f.read()
    cipher = b64decode(cipher)
    with open('./private.pem') as f:
        key = RSA.importKey(f)
    print key.decrypt(cipher)


def decrypt1():
    with open('./level1.passwd.enc') as f:
        cipher = f.read()
    cipher = b64decode(cipher)
    with open('./private.pem') as f:
        key = RSA.importKey(f)
        key = PKCS1_OAEP.new(key)
    print key.decrypt(cipher)


#getprivatekey(n, e, p, q)
decrypt1()
