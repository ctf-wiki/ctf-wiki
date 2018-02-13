from Crypto.Util.number import size, long_to_bytes, bytes_to_long
from Crypto.Cipher import DES
k = 2048
key = "abcdefg1"

def pi_b(x, m):
	'''
	m:
	1: encrypt
	0: decrypt
	'''	
	enc = DES.new(key)
	if m:
		method = enc.encrypt
	else:
		method = enc.decrypt
	s = long_to_bytes(x)
	sp = [s[a:a+8] for a in xrange(0, len(s), 8)]
	r = ""
	for a in sp:
		r += method(a)
	return bytes_to_long(r)

if __name__=="__main__":
	n = 0x724d41149e1bd9d2aa9b333d467f2dfa399049a5d0b4ee770c9d4883123be11a52ff1bd382ad37d0ff8d58c8224529ca21c86e8a97799a31ddebd246aeeaf0788099b9c9c718713561329a8e529dfeae993036921f036caa4bdba94843e0a2e1254c626abe54dc3129e2f6e6e73bbbd05e7c6c6e9f44fcd0a496f38218ab9d52bf1f266004180b6f5b9bee7988c4fe5ab85b664280c3cfe6b80ae67ed8ba37825758b24feb689ff247ee699ebcc4232b4495782596cd3f29a8ca9e0c2d86ea69372944d027a0f485cea42b74dfd74ec06f93b997a111c7e18017523baf0f57ae28126c8824bd962052623eb565cee0ceee97a35fd8815d2c5c97ab9653c4553f
	u = hex(n)[2:-1][-480:-320]
	u = int(u,16)
	p4 = pi_b(u,0)
	print hex(p4)