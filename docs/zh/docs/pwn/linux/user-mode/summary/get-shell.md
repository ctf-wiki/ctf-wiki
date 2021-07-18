# shell 获取小结

## overview

我们获取到的 shell 一般有两种形式

- 直接可交互的 shell
- 将 shell 绑定到指定 ip 的指定端口

下面总结几种常见的获取 shell 的方式。

## shellcode

在利用 shellcode 获取 shell 时，基本要求就是我们能够将 shellcode 布置在**可写可执行的内存区域**中。因此，在没有可写可执行的内存区域的时候，我们需要利用`mprotect` 等函数设置相关内存的权限。

此外，有时候可能 shellcode 中的字符必须满足某些要求，比如可打印字符，字母，数字等等。

## system

我们这里一般是执行 system("/bin/sh")，system('sh') 等函数。

这里我们主要需要找到一些地址，可以参考获取地址的小节。

- system 的地址
- "/bin/sh"， “sh” 地址
    - binary 里面是否字符串
    - 考虑个人读取对应字符串
    - libc 中其实是有 /bin/sh 的

在 system 获取 shell 时，一个非常好的优点在于我们只需要布置一个参数就可以了，缺点就是我们在布置参数时，可能因为破坏了环境变量而无法执行。

## execve

执行 execve("/bin/sh",NULL,NULL)。

在利用 `execve` 获取 shell 时，前几条同 system 一致。但它具有一个优点就是几乎不受环境变量的影响。但是缺点在于我们需要布置三个参数。

此外，glibc 中我们还可以使用 one_gadget 来获取 shell。

## syscall

系统调用号 `__NR_execve` 在 IA-32 中为 11，x86-64 为 59。

它的优点在于几乎不受环境变量的影响。然而我们需要找到 `syscall` 之类的系统调用命令。