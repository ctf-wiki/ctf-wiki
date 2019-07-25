[EN](./basic_knowledge.md) | [ZH](./basic_knowledge-zh.md)
Introduce some basic knowledge that Linux kernel pwn will use, and will gradually add it later.


Mainly refer to [Linux Kernel Exploitation] (https://github.com/ctf-wiki/ctf-wiki/blob/master/docs/pwn/linux/kernel/ref/13_lecture.pdf).


## Kernel

The kernel is also a program that manages the data I/O requirements issued by the software, escaping these requirements into instructions, and handing them over to the CPU and other components in the computer. The kernel is the most basic part of modern operating systems.


![](https://upload.wikimedia.org/wikipedia/commons/8/8f/Kernel_Layout.svg)



The main function of the kernel is twofold:


1. Control and interact with the hardware
2. Provide an environment in which the application can run


Various functions including I/O, permission control, system call, process management, memory management, etc. can be attributed to the above two points.


It should be noted that the **kernel crash usually causes a reboot**.


## Ring Model

The intel CPU divides the privilege level of the CPU into four levels: Ring 0, Ring 1, Ring 2, Ring 3.


Ring0 is only used by the OS. All Ring 3 programs can be used. The inner ring can use the resources of the outer ring.


The Ring Model is used to improve system security. For example, a spyware as a user program running on Ring 3 will be blocked when the user is not notified, because the access hardware needs to use the Ring 1 reserved by the being driver. method.


Most modern operating systems use only Ring 0 and Ring 3.


## Loadable Kernel Modules(LKMs)

Loadable core modules (or directly called kernel modules) are like executable programs running in kernel space, including:


- Drivers
- device driver
- File system driver
	- ...

- kernel extension modules (modules)


The file format of LKMs is the same as that of user mode. ELF under Linux, exe/dll under Windows, and MACH-O under mac, so we can use IDA and other tools to analyze kernel modules.


Modules can be compiled separately, but not separately. It is linked to the kernel as part of the kernel at run time, running in kernel space, unlike processes running on user controls.


Modules are often used to implement a file system, a driver, or other kernel-level functionality.


&gt; The Linux kernel provides a modular mechanism because it is itself a monolithic kernel. The advantage of a single core is that it is efficient because all the content is brought together, but the disadvantage is that the scalability and maintainability are relatively poor, and the module mechanism is to make up for this defect.


### Related Instructions
- **insmod**: Load the specified module into the kernel
- **rmmod**: Unload the specified module from the kernel
- **lsmod**: List the modules that have been loaded


&gt; Most kernel vulnerability is also in LKM.




## syscall

A system call is a program in which user space requests a service that requires higher privileges from the operating system kernel, such as IO operations or interprocess communication. The system call provides an interface between the user program and the operating system. Some library functions (such as scanf, puts, etc. IO related functions are actually the encapsulation (read and write) of the system call).


&gt; View 64-bit and 32-bit system calls in */usr/include/x86_64-linux-gnu/asm/unistd_64.h* and */usr/include/x86_64-linux-gnu/asm/unistd_32.h* respectively number.


&gt; Also recommend a very useful website [Linux Syscall Reference] (https://syscalls.kernelgrok.com), you can refer to the register meaning and source code of the 32-bit system call. Teachers are welcome to recommend 64-bit similar features.


## ioctl

Directly view the man page
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

It can be seen that ioctl is also a system call for communicating with devices.


The first argument to `int ioctl(int fd, unsigned long request, ...)` is the [file descriptor] returned by the open device (open) (http://m4x.fun/post/play-with-file -descriptor-1/), the second parameter is the user program&#39;s control command for the device, and the latter parameter is some supplementary parameter, which is related to the device.


&gt; Reasons for communicating with ioctl:


&gt; The operating system provides kernel access to system calls to standard external devices, as most hardware devices can only be addressed directly within kernel space, but when accessing non-standard hardware devices these system calls are not appropriate, and sometimes user mode may need to be directly Access the device.


&gt; For example, a system administrator might want to modify the configuration of the NIC. Modern operating systems provide support for a wide variety of devices, and some devices may not be considered by the kernel designer, thus making it impossible to provide such a system call to use the device.


&gt; To solve this problem, the kernel is designed to be extensible, and a module called device driver can be added. The driver code allows it to run in kernel space and directly address the device. An Ioctl interface is a separate system call through which user space can communicate with device drivers. The device-driven request is an Ioctl call with the device and request number as parameters, so the kernel allows user space to access the device driver and access the device without knowing the specific device details, and does not require a lot of different devices. System call.




## Status Switch


### user space to kernel space

When a &#39;system call&#39;, `generate exception`, `peripheral generate interrupt`, etc. event occurs, the user mode to kernel mode switch occurs. The specific process is:


1. Switch the GS segment register with `swapgs` to exchange the GS register value with the value of a specific location. The purpose is to save the GS value and use the value of this location as the GS value when the kernel is executed.
2. Record the current top of the stack (the top of the user space stack) in the CPU exclusive variable area, and put the top of the kernel stack recorded in the CPU exclusive area into rsp/esp.
3. Save each register value by push. The specific [code] (http://elixir.free-electrons.com/linux/v4.12/source/arch/x86/entry/entry_64.S) is as follows:


`` `asm
	 ENTRY(entry_SYSCALL_64)

/* SWAPGS_UNSAFE_STACK is a macro, x86 is directly defined as the swapgs command */
	 SWAPGS_UNSAFE_STACK

	

/* Save the stack value and set the kernel stack */
	 movq %rsp, PER_CPU_VAR(rsp_scratch)

	 movq PER_CPU_VAR(cpu_current_top_of_stack), %rsp

	

	

/* Save the register value by push to form a pt_regs structure*/
	/* Construct struct pt_regs on stack */

	pushq  $__USER_DS      /* pt_regs->ss */

	pushq  PER_CPU_VAR(rsp_scratch)  /* pt_regs->sp */

	pushq  %r11             /* pt_regs->flags */

	pushq  $__USER_CS      /* pt_regs->cs */

	pushq  %rcx             /* pt_regs->ip */

	pushq  %rax             /* pt_regs->orig_ax */

pushq% rdi / * pt_regs-&gt; at * /
pushq% rsi / * pt_regs-&gt; and * /
	pushq  %rdx             /* pt_regs->dx */
Pushq %rcx tuichu /* pt_regs-&gt;cx */
	pushq  $-ENOSYS        /* pt_regs->ax */

	pushq  %r8              /* pt_regs->r8 */

pushq% r9 / * pt_regs-&gt; r9 * /
	pushq  %r10             /* pt_regs->r10 */

	pushq  %r11             /* pt_regs->r11 */

	sub $(6*8), %rsp      /* pt_regs->bp, bx, r12-15 not saved */

	```

4. Determine if it is x32\_abi by the assembly instruction.
5. Continue to execute the system call by jumping to the corresponding location of the global variable `sys_call_table` by the system call number.


### kernel space to user space

When exiting, the process is as follows:


1. Restore GS value by `swapgs`
2. Resume to the user control via `sysretq` or `iretq` to continue execution. If you use `iretq` you also need to give some information about the user space (CS, eflags/rflags, esp/rsp, etc.)


## structure I think
As mentioned before, the kernel records the permissions of the process. More specifically, it is recorded by the cred structure. Each process has a cred structure. This structure saves the permissions of the process (uid, gid, etc.). Can modify the cred of a process, then modify the permissions of this process.


[source code] (https://code.woboq.org/linux/linux/include/linux/cred.h.html#cred) as follows:
`` `asm
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

but_t fsuid; / * UID for VFS ops * /
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



## Kernel state function
Kernel state functions have some changes compared to user state library functions


- printf() -&gt; **printk()**, but note that printk() does not necessarily display the content on the terminal, but it must be in the kernel buffer. You can view the effect via `dmesg`
- memcpy()		->		**copy\_from\_user()/copy\_to\_user()**

- copy\_from\_user() implements transferring user space data to kernel space
- copy\_to\_user() implements transferring kernel space data to user space
- malloc() -&gt; **kmalloc()**, kernel-mode memory allocation function, similar to malloc(), but using the `slab/slub allocator`
- free()		->		**kfree()**，同 kmalloc()



Also note that the `kernel manages the process, so the kernel also records the permissions of the process`. There are two functions in the kernel that can easily change permissions:


- **int commit_creds(struct cred \*new)**

- **struct cred\* prepare_kernel_cred(struct task_struct\* daemon)**



As you can see from the function name, execute `commit_creds(prepare_kernel_cred(0))` to get root privileges (root&#39;s uid, gid is 0)


Executing `commit_creds(prepare_kernel_cred(0))` is also the most commonly used method of lifting. The addresses of both functions can be viewed in `/proc/kallsyms` (the older kernel version is `/proc/ksyms`.
```bash

post sudo grep commit_creds /proc/kallsyms 

[sudo] m4x password:
ffffffffbb6af9e0 T commit_creds

ffffffffbc7cb3d0 r __ksymtab_commit_creds

ffffffffbc7f06fe r __kstrtab_commit_creds

post sudo grep prepare_kernel_cred /proc/kallsyms

ffffffffbb6afd90 T prepare_kernel_cred

ffffffffbc7d4f20 r __ksymtab_prepare_kernel_cred

ffffffffbc7f06b7 r __kstrtab_prepare_kernel_cred

```



&gt; In general, the contents of /proc/kallsyms require root privileges to view


## Mitigation



&gt; canary, dep, PIE, RELRO and other protections are the same as user principles


- smep: Supervisor Mode Execution Protection, when the processor is in `ring0` mode, executing the `userspace` code will trigger a page fault. (This protection is called `PXN` in arm)


- smap: Superivisor Mode Access Protection, similar to smep, usually when accessing data.


- mmap_min_addr:



## CTF kernel pwn Related
Generally given the following three documents


1. boot.sh: a script for starting the shell of the kernel, mostly using qemu, the protection measures are related to the different startup parameters of qemu
2. bzImage: kernel binary

3. rootfs.cpio: file system image


such as:
	

	```bash

CISCN2017_babydriver [master]] ls
babydriver.tar
CISCN2017_babydriver [master ●] x baby driver.tar
	boot.sh

	bzImage

	rootfs.cpio

CISCN2017_babydriver [master]] ls
	babydriver.tar  boot.sh  bzImage  rootfs.cpio

	CISCN2017_babydriver [master●] file bzImage

	bzImage: Linux kernel x86 boot executable bzImage, version 4.4.72 (atum@ubuntu) #1 SMP Thu Jun 15 19:52:50 PDT 2017, RO-rootFS, swap_dev 0x6, Normal VGA

	CISCN2017_babydriver [master●] file rootfs.cpio

	rootfs.cpio: gzip compressed data, last modified: Tue Jul  4 08:39:15 2017, max compression, from Unix, original size 2844672
	CISCN2017_babydriver [master●] file boot.sh

	boot.sh: Bourne-Again shell script, ASCII text executable

CISCN2017_babydriver [master ●] bat boot.sh
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

Explain the parameters that qemu starts:
	

- -initrd rootfs.cpio, using rootfs.cpio as the kernel-initiated file system
- -kernel bzImage, using bzImage as the kernel image
- -cpu kvm64, +smep, set the security options for the CPU, here smep is enabled
- -m 64M, set the virtual RAM to 64M, the default is 128M
Other options can be viewed with --help.


4. After writing the exploit locally, you can save the compiled binary file to the remote directory by base64 encoding, etc., and then get the flag.




## Reference:

Https://en.wikipedia.org/wiki/kernel


https://en.wikipedia.org/wiki/Classified protection domain


https://zh.wikipedia.org/wiki/Ioctl



http://www.freebuf.com/articles/system/54263.html



https://blog.csdn.net/zqixiao_09/article/details/50839042



https://yq.aliyun.com/articles/53679


