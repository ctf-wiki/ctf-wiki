from pwn import *
from hashlib import sha1
import string
import ast
import os
import binascii
import sys
print sys.version_info
context.log_level = 'debug'


def f(x):
    return sha1(prefix + x).digest()[-2:] == '\0\0'


def digitalize(m):
    return int(m.encode('hex'), 16)


sh = remote('106.75.66.195', 40001)
# bypass proof
sh.recvuntil('starting with ')
prefix = sh.recvuntil('\n', drop=True)
print string.ascii_letters
s = util.iters.mbruteforce(f, string.ascii_letters + string.digits, 5, 'fixed')
test = prefix + s
sh.sendline(test)

sh.recvuntil('Current PK we are using: ')
pubkey = ast.literal_eval(sh.recvuntil('\n', drop=True))
p = pubkey[0]
g = pubkey[1]
pk = pubkey[2]

# construct the message begins with 'test'
target = "Th3_bery_un1que1i_ChArmIng_G3nji" + test
part1 = (digitalize('test' + os.urandom(51)) << 512) // (p - 1) * (p - 1)
victim = part1 + digitalize(target)
while 1:
    tmp = hex(victim)[2:].decode('hex')
    if tmp.startswith('test') and '\n' not in tmp:
        break
    else:
        part1 = (digitalize('test' + os.urandom(51)) << 512) // (p - 1) * (
            p - 1)
        victim = part1 + digitalize(target)

assert (victim % (p - 1) == digitalize(target) % (p - 1))

# get victim signature
sh.sendline(hex(victim)[2:].decode('hex'))
sh.recvuntil('Your signature is')
sig = ast.literal_eval(sh.recvuntil('\n', drop=True))
sig = [int(sig[0], 0), int(sig[1], 0)]

# get flag
sh.sendline(target)
sh.sendline(str(sig[0]) + "," + str(sig[1]))
sh.interactive()
