import os, base64, time, sys, random, string
from Crypto.Cipher import AES
from Crypto.Hash import *

key = os.urandom(16)
iv = os.urandom(16)


def pad(msg):
    pad_length = 16 - len(msg) % 16
    return msg + chr(pad_length) * pad_length


def unpad(msg):
    return msg[:-ord(msg[-1])]


def encrypt(iv, msg):
    msg = pad(msg)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(msg)
    return encrypted


def decrypt(iv, msg):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(msg)
    decrypted = unpad(decrypted)
    return decrypted


def send_msg(msg):
    encrypted = encrypt(iv, msg)
    msg = iv + encrypted
    msg = base64.b64encode(msg)
    print msg


def recv_msg():
    msg = raw_input()
    try:
        msg = base64.b64decode(msg)
        assert len(msg) < 500
        decrypted = decrypt(msg[:16], msg[16:])
        return decrypted
    except:
        print 'Error'
        exit(0)


def check_token(token):
    print 'Give me the token!'
    msg = raw_input()
    msg = base64.b64decode(msg)
    return msg == token


def proof_of_work():
    proof = ''.join([
        random.choice(string.ascii_letters + string.digits) for _ in xrange(20)
    ])
    digest = SHA256.new(proof).hexdigest()
    print "SHA256(XXXX+%s) == %s" % (proof[4:], digest)
    x = raw_input('Give me XXXX:')
    if len(x) != 4 or SHA256.new(x + proof[4:]).hexdigest() != digest:
        exit(0)
    return


def main():
    proof_of_work()
    token = os.urandom(56)
    with open('flag.txt') as f:
        flag = f.read().strip()
    past = 0
    send_msg('Welcome!!')
    for i in xrange(340):
        try:
            #cur = time.time()
            #if cur - past < 1:
            #    time.sleep(1 - cur + past)
            #past = cur
            msg = recv_msg()
            if msg.startswith('exit-here'):
                exit(0)
            elif msg.startswith('get-md5'):
                send_msg(MD5.new(msg[7:]).digest())
            elif msg.startswith('get-time'):
                send_msg(str(time.time()))
            elif msg.startswith('get-sha1'):
                send_msg(SHA.new(msg[8:]).digest())
            elif msg.startswith('get-token'):
                send_msg('token: ' + token)
            elif msg.startswith('check-token'):
                if check_token(token):
                    print flag
                exit(0)
            else:
                send_msg('command not found')
        except:
            exit(0)


if __name__ == '__main__':
    main()
