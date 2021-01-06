# ret2VDSO

## VDSO介绍

什么是VDSO(Virtual Dynamically-linked Shared Object)呢？听其名字，大概是虚拟动态链接共享对象，所以说它应该是虚拟的，与虚拟内存一致，在计算机中本身并不存在。具体来说，它是将内核态的调用映射到用户地址空间的库。那么它为什么会存在呢？这是因为有些系统调用经常被用户使用，这就会出现大量的用户态与内核态切换的开销。通过vdso，我们可以大量减少这样的开销，同时也可以使得我们的路径更好。这里路径更好指的是，我们不需要使用传统的int 0x80来进行系统调用，不同的处理器实现了不同的快速系统调用指令

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

```asm
push ebp
mov ebp,esp
```

此外，如果我们没有提供functtion prolog的话，我们还需要一个可以进行栈迁移的gadgets，以便于可以改变栈的位置。

## 原理

待补充。

## 题目

- **Defcon 2015 Qualifier fuckup**

## 参考

- http://man7.org/linux/man-pages/man7/vdso.7.html
- http://adam8157.info/blog/2011/10/linux-vdso/

