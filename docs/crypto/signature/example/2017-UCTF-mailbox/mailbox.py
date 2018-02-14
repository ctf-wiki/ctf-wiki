import os
import SocketServer
import base64 as b64
import hashlib
from Crypto.Util import number
from Crypto import Random
from Crypto.PublicKey.pubkey import *

MSGLENGTH = 40000
HASHLENGTH = 16
FLAG = open("flag","r").read()
PORT_NUM = 40122

def sign(m, sk, pk, p, g):
    while True:
        k = getRandomRange(1, p-1)
        if number.GCD(k, p-1) == 1:
            break
    r = pow(g, k, p)
    s = (m - sk * r) % (p-1)
    while s < 0:
        s += (p-1)
    s = (s * inverse(k, p-1)) % (p-1)
    return r, s

def verify(m, r, s, pk, p, g):
    if r < 1: return False
    if (pow(pk, r, p) * pow(r, s, p)) % p == pow(g, m, p):
        return True
    return False

def generate_keys():
    randomFunc = Random.new().read
    while True:
        q = bignum(getPrime(512))
        # generate a safe prime
        p = 2 * q + 1
        if number.isPrime(p, 1e-6, randomFunc):
            break
    #print "Got p", p
    while True:
        g = number.getRandomRange(3, p, randomFunc)
        if pow(g, 2, p) == 1:
            continue
        if pow(g, q, p) == 1:
            continue
        if (p - 1) % g == 0:
            continue
        g_inv = number.inverse(g, p)
        if (p - 1) % g_inv == 0:
            continue
        break
    sk = number.getRandomRange(2, p - 1, randomFunc)
    pk = pow(g, sk, p)
    return pk, sk, g, p

def digitalize(m):
    return int(m.encode('hex'), 16)

class HandleCheckin(SocketServer.StreamRequestHandler):
    def handle(self):
        Random.atfork()
        req = self.request
        proof = b64.b64encode(os.urandom(12))

        req.sendall(
            "Please provide your proof of work, a sha1 sum ending in 16 bit's set to 0, it must be of length %d bytes, starting with %s\n" % (
            len(proof) + 5, proof))

        test = req.recv(21)
        ha = hashlib.sha1()
        ha.update(test)

        if (test[0:16] != proof or ord(ha.digest()[-1]) != 0 or ord(ha.digest()[-2]) != 0): # or ord(ha.digest()[-3]) != 0 or ord(ha.digest()[-4]) != 0):
            req.sendall("Check failed")
            req.close()
            return
        req.sendall('''=== Welcome to Overwatch Mailbox Login Portal ===
[Notice] As pointed out recently by Dr. Winston, username/password style authentication apparently becomes old-fashioned.
We've introduced new signature-based auth system. To login in, please input your username and your signature.
        
[Notice] We've received lots of complaints that overwatch agents kinda suck in signing signatures. To help you get familiar with the new system.
Dr. Winston is glad to provide you an example. Username starts with 'test' will get signed automatically.
        
You have 3 chances to log-in.\n\n''')
        req.sendall("Generating keys...\nDispatching keys to corresponding owners...\n")
        pk, sk, g, p = generate_keys()
        req.sendall("Current PK we are using: %s\n" % repr([p, g, pk]))
        print sk, pk, g, p

        for it in range(3):
            req.sendall("Username:")
            msg = self.rfile.readline().strip()
            if len(msg) > MSGLENGTH:
                req.sendall("what r u do'in?")
                req.close()
                return
            if msg[:4] == "test":
                r, s = sign(digitalize(msg), sk, pk, p, g)
                req.sendall("Your signature is" + repr((hex(r), hex(s))) + "\n")
            else:
                if msg == "Th3_bery_un1que1i_ChArmIng_G3nji" + test:
                    req.sendall("Signature:")
                    sig = self.rfile.readline().strip()
                    if len(sig) > MSGLENGTH:
                        req.sendall("what r u do'in?")
                        req.close()
                        return
                    sig_rs = sig.split(",")
                    if len(sig_rs) < 2:
                        req.sendall("yo what?")
                        req.close()
                        return
                    # print "Got sig", sig_rs
                    if verify(digitalize(msg), int(sig_rs[0]), int(sig_rs[1]), pk, p, g):
                        req.sendall("Login Success.\nDr. Ziegler has a message for you: " + FLAG)
                        print "shipped flag"
                        req.close()
                        return
                    else:
                        req.sendall("You are not the Genji I knew!\n")


class ThreadedServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", int(PORT_NUM)
    server = ThreadedServer((HOST, PORT), HandleCheckin)
    server.allow_reuse_address = True
    server.serve_forever()