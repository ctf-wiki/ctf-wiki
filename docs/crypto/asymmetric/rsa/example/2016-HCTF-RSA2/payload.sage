from sage.all import *
import binascii
n = 0x724d41149e1bd9d2aa9b333d467f2dfa399049a5d0b4ee770c9d4883123be11a52ff1bd382ad37d0ff8d58c8224529ca21c86e8a97799a31ddebd246aeeaf0788099b9c9c718713561329a8e529dfeae993036921f036caa4bdba94843e0a2e1254c626abe54dc3129e2f6e6e73bbbd05e7c6c6e9f44fcd0a496f38218ab9d52bf1f266004180b6f5b9bee7988c4fe5ab85b664280c3cfe6b80ae67ed8ba37825758b24feb689ff247ee699ebcc4232b4495782596cd3f29a8ca9e0c2d86ea69372944d027a0f485cea42b74dfd74ec06f93b997a111c7e18017523baf0f57ae28126c8824bd962052623eb565cee0ceee97a35fd8815d2c5c97ab9653c4553f
p4 =0xa37302107c17fb4ef5c3443f4ef9e220ac659670077b9aa9ff7381d11073affe9183e88acae0ab61fb75a3c7815ffcb1b756b27c4d90b2e0ada753fa17cc108c1d0de82c747db81b9e6f49bde1362693
cipher = 0xf11e932fa420790ca3976468dc4df1e6b20519ebfdc427c09e06940e1ef0ca566d41714dc1545ddbdcae626eb51c7fa52608384a36a2a021960d71023b5d0f63e6b38b46ac945ddafea42f01d24cc33ce16825df7aa61395d13617ae619dca2df15b5963c77d6ededf2fe06fd36ae8c5ce0e3c21d72f2d7f20cd9a8696fbb628df29299a6b836c418cbfe91e2b5be74bdfdb4efdd1b33f57ebb72c5246d5dce635529f1f69634d565a631e950d4a34a02281cbed177b5a624932c2bc02f0c8fd9afd332ccf93af5048f02b8bd72213d6a52930b0faa0926973883136d8530b8acf732aede8bb71cb187691ebd93a0ea8aeec7f82d0b8b74bcf010c8a38a1fa8
e2 = 0xf93b
pbits = 1024
kbits = pbits - p4.nbits()
print p4.nbits()
p4 = p4 << kbits
PR.<x> = PolynomialRing(Zmod(n))
f = x + p4
roots = f.small_roots(X=2^kbits, beta=0.4)
if roots:
    p = p4+int(roots[0])
    print "p: ", hex(int(p))
    assert n % p == 0
    q = n/int(p)
    print "q: ", hex(int(q))
    print gcd(p,q)
    phin = (p-1)*(q-1)
    print gcd(e2,phin)
    d = inverse_mod(e2,phin)
    flag = pow(cipher,d,n)
    flag = hex(int(flag))[2:-1]
    print binascii.unhexlify(flag)