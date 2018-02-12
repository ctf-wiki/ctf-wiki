# -*- coding: utf-8 -*-

def egcd(m, n):
    if n>0:
        y,x,d = egcd(n, m%n)
        return x, y-m/n*x, d
    else:
        return 1, 0, m


def modinv(a, m):
    (inv, q, gcd_val) = egcd(a, m)
    return inv % m


def chinese_remainder(Q, X):
    P = reduce(lambda x,y: x*y, Q)
    result = 0
    for i in xrange(len(X)):
        x, y, d = egcd(Q[i], P/Q[i])
        result += y*(P/Q[i])*X[i]
    return result % P


# Baby-step giant-step
def baby_step_giant_step(g, y, p, q):
    m = int(q**0.5 + 1)
    
    # Baby-step
    baby = {}
    b = 1
    for j in xrange(m):
        baby[b] = j
        b = (b * g) % p

    # Giant-step
    gm = pow(modinv(g, p), m, p)
    giant = y
    for i in xrange(m):
        if giant in baby:
            x = i*m + baby[giant]
            print "Found:", x
            return x
        else:
            giant = (giant * gm) % p
    print "not found"
    return -1


# Pohlig-Hellman algorithm
def pohlig_hellman(p, g, y, phi_p):
    Q = map(int, phi_p.split(" * "))
    print "[+] Q:", Q
    X = []
    for q in Q:
        x = baby_step_giant_step(pow(g,(p-1)/q,p), pow(y,(p-1)/q,p), p, q)
        X.append(x)
    print "[+] X:", X
    x = chinese_remainder(Q, X)
    return x



g = 1828219035112142373387222893932751631772945852477987101590090
y = 1012750243445446249248731524345776923711031192963358920130436
p = 3047318456124223787871095946374791137939076290647203431778747
c1 = 1851635883910479967256646617880733235123029676545812189105888
c2 = 2279140729739532482438192630521498934347693926502811537441460
phi_p = "2 * 3 * 7 * 281 * 585131 * 2283091 * 66558319 * 38812459031 * 8407411055293 * 8899182573469"

x = pohlig_hellman(p, g, y, phi_p)
print "[+] x:", x

m = c2 * modinv(pow(c1,x,p),p) % p
print "[+] m:", m
print "[+] FLAG: ", "0"+hex(m)[2:-1].decode('hex')

# [+] FLAG: 0MMA{wrOng_wr0ng_ElGamal}
