import os, base64, time, random, string
from Crypto.Cipher import AES
from Crypto.Hash import *

key = os.urandom(16)

def pad(msg):
    pad_length = 16-len(msg)%16
    return msg+chr(pad_length)*pad_length

def unpad(msg):
    return msg[:-ord(msg[-1])]

def encrypt(iv,msg):
    msg = pad(msg)
    cipher = AES.new(key,AES.MODE_CBC,iv)
    encrypted = cipher.encrypt(msg)
    return encrypted

def decrypt(iv,msg):
    cipher = AES.new(key,AES.MODE_CBC,iv)
    decrypted = cipher.decrypt(msg)
    decrypted = unpad(decrypted)
    return decrypted

def send_msg(msg):
    iv = '2jpmLoSsOlQrqyqE'
    encrypted = encrypt(iv,msg)
    msg = iv+encrypted
    msg = base64.b64encode(msg)
    print msg
    return

def recv_msg():
    msg = raw_input()
    try:
        msg = base64.b64decode(msg)
        assert len(msg)<500
        decrypted = decrypt(msg[:16],msg[16:])
        return decrypted
    except:
        print 'Error'
        exit(0)

def proof_of_work():
    proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in xrange(20)])
    digest = SHA256.new(proof).hexdigest()
    print "SHA256(XXXX+%s) == %s" % (proof[4:],digest)
    x = raw_input('Give me XXXX:')
    if len(x)!=4 or SHA256.new(x+proof[4:]).hexdigest() != digest: 
        exit(0)
    print "Done!"
    return

if __name__ == '__main__':
    proof_of_work()
    with open('flag.txt') as f:
        flag = f.read().strip()
    assert flag.startswith('hitcon{') and flag.endswith('}')
    send_msg('Welcome!!')
    while True:
        try:
            msg = recv_msg().strip()
            if msg.startswith('exit-here'):
                exit(0)
            elif msg.startswith('get-flag'):
                send_msg(flag)
            elif msg.startswith('get-md5'):
                send_msg(MD5.new(msg[7:]).digest())
            elif msg.startswith('get-time'):
                send_msg(str(time.time()))
            elif msg.startswith('get-sha1'):
                send_msg(SHA.new(msg[8:]).digest())
            elif msg.startswith('get-sha256'):
                send_msg(SHA256.new(msg[10:]).digest())
            elif msg.startswith('get-hmac'):
                send_msg(HMAC.new(msg[8:]).digest())
            else:
                send_msg('command not found')
        except:
            exit(0)
