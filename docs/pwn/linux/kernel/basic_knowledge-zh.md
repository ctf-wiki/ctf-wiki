[EN](./basic_knowledge.md) | [ZH](./basic_knowledge-zh.md)
介绍一些 linux kernel pwn 会用到的基础知识，后续会逐渐补充。

主要参考了 [Linux Kernel Exploitation](https://github.com/ctf-wiki/ctf-wiki/blob/master/docs/pwn/linux/kernel/ref/13_lecture.pdf)。

## Kernel
kernel 也是一个程序，用来管理软件发出的数据 I/O 要求，将这些要求转义为指令，交给 CPU 和计算机中的其他组件处理，kernel 是现代操作系统最基本的部分。

![](https://upload.wikimedia.org/wikipedia/commons/8/8f/Kernel_Layout.svg)

kernel 最主要的功能有两点：

1. 控制并与硬件进行交互
2. 提供 application 能运行的环境

包括 I/O，权限控制，系统调用，进程管理，内存管理等多项功能都可以归结到上边两点中。

需要注意的是，**kernel 的 crash 通常会引起重启**。

## Ring Model
intel CPU 将 CPU 的特权级别分为 4 个级别：Ring 0, Ring 1, Ring 2, Ring 3。

Ring0 只给 OS 使用，Ring 3 所有程序都可以使用，内层 Ring 可以随便使用外层 Ring 的资源。

使用 Ring Model 是为了提升系统安全性，例如某个间谍软件作为一个在 Ring 3 运行的用户程序，在不通知用户的时候打开摄像头会被阻止，因为访问硬件需要使用being驱动程序保留的 Ring 1 的方法。

大多数的现代操作系统只使用了 Ring 0 和 Ring 3。

## Loadable Kernel Modules(LKMs)
可加载核心模块 (或直接称为内核模块) 就像运行在内核空间的可执行程序，包括:

- 驱动程序（Device drivers）
	- 设备驱动
	- 文件系统驱动
	- ...
- 内核扩展模块 (modules)

LKMs 的文件格式和用户态的可执行程序相同，Linux 下为 ELF，Windows 下为 exe/dll，mac 下为 MACH-O，因此我们可以用 IDA 等工具来分析内核模块。

模块可以被单独编译，但不能单独运行。它在运行时被链接到内核作为内核的一部分在内核空间运行，这与运行在用户控件的进程不同。

模块通常用来实现一种文件系统、一个驱动程序或者其他内核上层的功能。

> Linux 内核之所以提供模块机制，是因为它本身是一个单内核 (monolithic kernel)。单内核的优点是效率高，因为所有的内容都集合在一起，但缺点是可扩展性和可维护性相对较差，模块机制就是为了弥补这一缺陷。

### 相关指令
- **insmod**: 讲指定模块加载到内核中
- **rmmod**: 从内核中卸载指定模块
- **lsmod**: 列出已经加载的模块

> 大多数　kernel vulnerability 也出在 LKM 中。


## syscall
系统调用，指的是用户空间的程序向操作系统内核请求需要更高权限的服务，比如 IO 操作或者进程间通信。系统调用提供用户程序与操作系统间的接口，部分库函数（如 scanf，puts 等 IO 相关的函数实际上是对系统调用的封装 （read 和 write)）。

> 在 */usr/include/x86_64-linux-gnu/asm/unistd_64.h* 和 */usr/include/x86_64-linux-gnu/asm/unistd_32.h* 分别可以查看 64 位和 32 位的系统调用号。

> 同时推荐一个很好用的网站 [Linux Syscall Reference](https://syscalls.kernelgrok.com)，可以查阅 32 位系统调用对应的寄存器含义以及源码。欢迎师傅们推荐 64 位类似功能的网站。

## ioctl
直接查看 man 手册
```
NAME
       ioctl - control device

SYNOPSIS
       #include <sys/ioctl.h>

       int ioctl(int fd, unsigned long request, ...);

DESCRIPTION
       The ioctl() system call manipulates the underlying device parameters of special
       files.  In particular, many  operating  characteristics  of  character  special
       files  (e.g., terminals) may be controlled with ioctl() requests.  The argument
       fd must be an open file descriptor.

       The second argument is a device-dependent request code.  The third argument  is
       an  untyped  pointer  to  memory.  It's traditionally char *argp (from the days
       before void * was valid C), and will be so named for this discussion.

       An ioctl() request has encoded in it whether the argument is an in parameter or
       out  parameter, and the size of the argument argp in bytes.  Macros and defines
       used in specifying an ioctl() request are located in the file <sys/ioctl.h>.
```
可以看出 ioctl 也是一个系统调用，用于与设备通信。

`int ioctl(int fd, unsigned long request, ...)` 的第一个参数为打开设备 (open) 返回的 [文件描述符](http://m4x.fun/post/play-with-file-descriptor-1/)，第二个参数为用户程序对设备的控制命令，再后边的参数则是一些补充参数，与设备有关。

> 使用 ioctl 进行通信的原因：

> 操作系统提供了内核访问标准外部设备的系统调用，因为大多数硬件设备只能够在内核空间内直接寻址,但是当访问非标准硬件设备这些系统调用显得不合适,有时候用户模式可能需要直接访问设备。

> 比如，一个系统管理员可能要修改网卡的配置。现代操作系统提供了各种各样设备的支持，有一些设备可能没有被内核设计者考虑到，如此一来提供一个这样的系统调用来使用设备就变得不可能了。 

> 为了解决这个问题，内核被设计成可扩展的，可以加入一个称为设备驱动的模块，驱动的代码允许在内核空间运行而且可以对设备直接寻址。一个Ioctl接口是一个独立的系统调用，通过它用户空间可以跟设备驱动沟通。对设备驱动的请求是一个以设备和请求号码为参数的Ioctl调用，如此内核就允许用户空间访问设备驱动进而访问设备而不需要了解具体的设备细节，同时也不需要一大堆针对不同设备的系统调用。


## 状态切换

### user space to kernel space
当发生 `系统调用`，`产生异常`，`外设产生中断`等事件时，会发生用户态到内核态的切换，具体的过程为：

1. 通过 `swapgs` 切换 GS 段寄存器，将 GS 寄存器值和一个特定位置的值进行交换，目的是保存 GS 值，同时将该位置的值作为内核执行时的 GS 值使用。
2. 将当前栈顶（用户空间栈顶）记录在 CPU 独占变量区域里，将 CPU 独占区域里记录的内核栈顶放入 rsp/esp。
3. 通过 push 保存各寄存器值，具体的 [代码](http://elixir.free-electrons.com/linux/v4.12/source/arch/x86/entry/entry_64.S) 如下:

	```asm
	 ENTRY(entry_SYSCALL_64)
	 /* SWAPGS_UNSAFE_STACK是一个宏，x86直接定义为swapgs指令 */
	 SWAPGS_UNSAFE_STACK
	
	 /* 保存栈值，并设置内核栈 */
	 movq %rsp, PER_CPU_VAR(rsp_scratch)
	 movq PER_CPU_VAR(cpu_current_top_of_stack), %rsp
	
	
	/* 通过push保存寄存器值，形成一个pt_regs结构 */
	/* Construct struct pt_regs on stack */
	pushq  $__USER_DS      /* pt_regs->ss */
	pushq  PER_CPU_VAR(rsp_scratch)  /* pt_regs->sp */
	pushq  %r11             /* pt_regs->flags */
	pushq  $__USER_CS      /* pt_regs->cs */
	pushq  %rcx             /* pt_regs->ip */
	pushq  %rax             /* pt_regs->orig_ax */
	pushq  %rdi             /* pt_regs->di */
	pushq  %rsi             /* pt_regs->si */
	pushq  %rdx             /* pt_regs->dx */
	pushq  %rcx tuichu    /* pt_regs->cx */
	pushq  $-ENOSYS        /* pt_regs->ax */
	pushq  %r8              /* pt_regs->r8 */
	pushq  %r9              /* pt_regs->r9 */
	pushq  %r10             /* pt_regs->r10 */
	pushq  %r11             /* pt_regs->r11 */
	sub $(6*8), %rsp      /* pt_regs->bp, bx, r12-15 not saved */
	```
4. 通过汇编指令判断是否为 x32\_abi。
5. 通过系统调用号，跳到全局变量 `sys_call_table` 相应位置继续执行系统调用。

### kernel space to user space
退出时，流程如下：

1. 通过 `swapgs` 恢复 GS 值
2. 通过 `sysretq` 或者 `iretq` 恢复到用户控件继续执行。如果使用 `iretq` 还需要给出用户空间的一些信息（CS, eflags/rflags, esp/rsp 等）

## struct cred
之前提到 kernel 记录了进程的权限，更具体的，是用 cred 结构体记录的，每个进程中都有一个 cred 结构，这个结构保存了该进程的权限等信息（uid，gid 等），如果能修改某个进程的 cred，那么也就修改了这个进程的权限。

[源码](https://code.woboq.org/linux/linux/include/linux/cred.h.html#cred) 如下:
```asm
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key __rcu *session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	struct rcu_head	rcu;		/* RCU deletion hook */
} __randomize_layout;
```

## 内核态函数
相比用户态库函数，内核态的函数有了一些变化

- printf()		->		**printk()**，但需要注意的是 printk() 不一定会把内容显示到终端上，但一定在内核缓冲区里，可以通过 `dmesg` 查看效果
- memcpy()		->		**copy\_from\_user()/copy\_to\_user()**
	- copy\_from\_user() 实现了将用户空间的数据传送到内核空间
	- copy\_to\_user() 实现了将内核空间的数据传送到用户空间
- malloc()		->		**kmalloc()**，内核态的内存分配函数，和 malloc() 相似，但使用的是 `slab/slub 分配器`
- free()		->		**kfree()**，同 kmalloc()

另外要注意的是，`kernel 管理进程，因此 kernel 也记录了进程的权限`。kernel 中有两个可以方便的改变权限的函数：

- **int commit_creds(struct cred *new)**
- **struct cred\* prepare_kernel_cred(struct task_struct\* daemon)**

从函数名也可以看出，执行 `commit_creds(prepare_kernel_cred(0))` 即可获得 root 权限（root 的 uid，gid 均为 0）

执行 `commit_creds(prepare_kernel_cred(0))` 也是最常用的提权手段，两个函数的地址都可以在 `/proc/kallsyms` 中查看（较老的内核版本中是 `/proc/ksyms`。
```bash
post sudo grep commit_creds /proc/kallsyms 
[sudo] m4x 的密码：
ffffffffbb6af9e0 T commit_creds
ffffffffbc7cb3d0 r __ksymtab_commit_creds
ffffffffbc7f06fe r __kstrtab_commit_creds
post sudo grep prepare_kernel_cred /proc/kallsyms
ffffffffbb6afd90 T prepare_kernel_cred
ffffffffbc7d4f20 r __ksymtab_prepare_kernel_cred
ffffffffbc7f06b7 r __kstrtab_prepare_kernel_cred
```

> 一般情况下，/proc/kallsyms 的内容需要 root 权限才能查看

## Mitigation

> canary, dep, PIE, RELRO 等保护与用户态原理和作用相同

- smep: Supervisor Mode Execution Protection，当处理器处于 `ring0` 模式，执行 `用户空间` 的代码会触发页错误。（在 arm 中该保护称为 `PXN`)

- smap: Superivisor Mode Access Protection，类似于 smep，通常是在访问数据时。

- mmap_min_addr:

## CTF kernel pwn 相关
一般会给以下三个文件

1. boot.sh: 一个用于启动 kernel 的 shell 的脚本，多用 qemu，保护措施与 qemu 不同的启动参数有关
2. bzImage: kernel binary
3. rootfs.cpio: 文件系统映像

	比如：
	
	```bash
	CISCN2017_babydriver [master●] ls
	babydriver.tar
	CISCN2017_babydriver [master●] x babydriver.tar
	boot.sh
	bzImage
	rootfs.cpio
	CISCN2017_babydriver [master●] ls
	babydriver.tar  boot.sh  bzImage  rootfs.cpio
	CISCN2017_babydriver [master●] file bzImage
	bzImage: Linux kernel x86 boot executable bzImage, version 4.4.72 (atum@ubuntu) #1 SMP Thu Jun 15 19:52:50 PDT 2017, RO-rootFS, swap_dev 0x6, Normal VGA
	CISCN2017_babydriver [master●] file rootfs.cpio
	rootfs.cpio: gzip compressed data, last modified: Tue Jul  4 08:39:15 2017, max compression, from Unix, original size 2844672
	CISCN2017_babydriver [master●] file boot.sh
	boot.sh: Bourne-Again shell script, ASCII text executable
	CISCN2017_babydriver [master●] bat boot.sh 
	───────┬─────────────────────────────────────────────────────────────────────────────────
	       │ File: boot.sh
	───────┼─────────────────────────────────────────────────────────────────────────────────
	   1   │ #!/bin/bash
	   2   │ 
	   3   │ qemu-system-x86_64 -initrd rootfs.cpio -kernel bzImage -append 'console=ttyS0 ro
	       │ ot=/dev/ram oops=panic panic=1' -enable-kvm -monitor /dev/null -m 64M --nographi
	       │ c  -smp cores=1,threads=1 -cpu kvm64,+smep
	───────┴─────────────────────────────────────────────────────────────────────────────────
	```
	解释一下 qemu 启动的参数：
	
	- -initrd rootfs.cpio，使用 rootfs.cpio 作为内核启动的文件系统
	- -kernel bzImage，使用 bzImage 作为 kernel 映像
	- -cpu kvm64,+smep，设置 CPU 的安全选项，这里开启了 smep
	- -m 64M，设置虚拟 RAM 为 64M，默认为 128M
	其他的选项可以通过 --help 查看。

4. 本地写好 exploit 后，可以通过 base64 编码等方式把编译好的二进制文件保存到远程目录下，进而拿到 flag


## Reference:
https://zh.wikipedia.org/wiki/内核

https://zh.wikipedia.org/wiki/分级保护域

https://zh.wikipedia.org/wiki/Ioctl

http://www.freebuf.com/articles/system/54263.html

https://blog.csdn.net/zqixiao_09/article/details/50839042

https://yq.aliyun.com/articles/53679

