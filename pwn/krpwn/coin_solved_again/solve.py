# coding:utf-8
#需要上传到本地才能在30s内完成脚本运行，这题没有细做，again的时候来联系一下io编程
from pwn import *
import re

def get_weight(start,end,r):
    #global r
    send_str = ""
    if start == end:
        r.sendline(str(start))
    else:
        for i in range(start,end + 1 ):
            send_str = send_str + str(i)+" "
        #print "[+]clent: ",send_str
        r.sendline(send_str)
    result = r.recvline()
    #print '[+]server: ',result
    return int(result)

def choose_coin(num,chance,r):
#    global r
    start = 0
    end = num -1
    weight = 0
    for i in range(0,chance  ):
    #    print '[*] round', i+1 ," / ", chance
        weight = get_weight(start,int(start+(end-start)/2),r)
        #if start = end:
        if weight%10 != 0:
            end = int(start+(end-start)/2)
        else:
            start = int(start+(end-start)/2 )+1
    #print '[+]client: ',end
    r.sendline(str(end))
    print '[+]server: ',r.recvline()




#global r
r = remote('localhost',9007)
print r.recv()
#print '='*18


#print num,'[+]',chance
for i in range(0,100):
    print '[*]','='*18," ",i," ","="*18 ,"[*]"
    recvword = r.recvline()
    print "[+]server: ",recvword
    p = re.compile(r'\d+')
    data = p.findall(recvword)
    num = int(data[0])
    chance = int(data[1])
    choose_coin(num,chance,r)
print r.recv()
