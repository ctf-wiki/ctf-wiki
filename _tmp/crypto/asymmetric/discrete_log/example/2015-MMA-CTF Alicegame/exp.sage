import socket
from Crypto.Util.number import *
from sage.all import *


def get_maxfactor(N):
    f = factor(N)
    print 'factor done'
    return f[-1][0]

maxnumber = 1 << 50
i = 0
while 1:
    print 'cycle: ',i
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 9999))
    sock.recv(17)
    # get g,h
    sock.recv(512)
    sock.sendall("1\n")
    sock.recv(512)
    sock.sendall("1\n")
    data = sock.recv(1024)
    print data
    if data.startswith('r'):
       sock.close()
       print 'continue'
       continue
    if '\n' in data:
        data =data[:data.index('\n')]
    else:
        # receive m=
        sock.recv(1024)
    (g,h) = eval(data)
    
    # get g,p
    sock.sendall("-1\n")
    sock.recv(512)
    sock.sendall("1\n")
    data = sock.recv(1024)
    print data
    if data.startswith('r'):
       sock.close()
       print 'continue'
       continue
    if '\n' in data:
        data = data[:data.index('\n')]
    else:
        # receive m=
        sock.recv(512)
    (g,tmp) = eval(data)
    p = tmp+h
    tmp = get_maxfactor(p-1)
    if tmp<maxnumber:
        print 'may be success'
        # skip the for cycle
        sock.sendall('quit\n');
        data = sock.recv(1024)
        print 'receive data: ',data
        data = data[data.index(":")+1:]
        (c1,c2)=eval(data)
        # generate the group
        g = Mod(g, p)
        h = Mod(h, p)
        c1 = Mod(c1, p)
        c2 = Mod(c2, p)
        x = discrete_log(h, g)
        print "x = ", x
        print "Flag: ", long_to_bytes(long(c2 / ( c1 ** x)))
    sock.sendall('quit\n')
    sock.recv(1024)
    sock.close()
    i += 1