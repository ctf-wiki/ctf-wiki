# Qemu 模拟环境

这一章节主要介绍如何使用 QEMU 来搭建调试分析环境。为了使用 qemu 启动和调试内核，我们需要内核、qemu、文件系统。

## 准备

### 内核

这个在之前已经编译完成了。

### QEMU

关于 QEMU 的介绍与安装请参考 `ctf-tools`。

### 文件系统

这里我们使用 busybox 来构建一个简单的文件系统。

#### 下载编译 busybox

##### 下载 busybox

```bash
❯ wget https://busybox.net/downloads/busybox-1.32.1.tar.bz2
❯ tar -jxf busybox-1.32.1.tar.bz2
```

##### 配置

```bash
❯ make menuconfig
```

在 Setttings 选中 Build static binary (no shared libs)，将 busybox 编译为静态链接的文件；在 Linux System Utilities 中取消选中 Support mounting NFS file systems on Linux < 2.6.23 (NEW)；在 Networking Utilities 中取消选中 inetd。

##### 编译

```bash
make -j3
```

#### 配置文件系统

使用 busybox 创建 `_install` 目录，使用命令：

```bash
make install
```

在编译完成后，我们在 `_install` 目录下创建以下文件夹

```bash
❯ mkdir -p  proc sys dev etc/init.d
```

并创建 `init` 作为 linux 的启动脚本，内容为

```bash
#!/bin/sh
echo "INIT SCRIPT"
mkdir /tmp
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug
mount -t tmpfs none /tmp
echo -e "Boot took $(cut -d' ' -f1 /proc/uptime) seconds"
setsid /bin/cttyhack setuidgid 1000 /bin/sh
```

将脚本加上可执行权限，以便于执行。

```bash
❯ chmod +x init
```

之后在 `_install` 目录下打包整个文件系统

```bash
❯ find . | cpio -o --format=newc > ../rootfs.img
5367 blocks
```

当然，我们还可以使用如下的命令重新解包文件系统

```shell
cpio -idmv < rootfs.img
```

## 启动内核

这里以前面编译好的 Linux 内核、文件系统镜像为例来介绍如何启动内核。我们可以直接使用下面的脚本来启动 Linux 内核

```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel ./bzImage \
    -initrd  ./rootfs.img \
    -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 kaslr" \
    -smp cores=2,threads=1 \
    -cpu kvm64
```

启动后的效果如下

```bash
Boot took 2.05 seconds
/ $ [    2.265131] tsc: Refined TSC clocksource calibration: 2399.950 MHz
[    2.265561] clocksource: tsc: mask: 0xffffffffffffffff max_cycles: 0x2298086d749, max_idle_ns: 440795294037 ns
[    2.266131] clocksource: Switched to clocksource tsc

/ $
/ $ ls
bin      etc      linuxrc  root     sys      usr
dev      init     proc     sbin     tmp
```

在没有设置 monitor 时，我们可以使用`ctrl-a+c` 来进入 monitor，可以看到 monitor 提供了很多命令。

```bash
/ $ QEMU 5.2.0 monitor - type 'help' for more information
(qemu) help
acl_add aclname match allow|deny [index] -- add a match rule to the access control list
acl_policy aclname allow|deny -- set default access control list policy
acl_remove aclname match -- remove a match rule from the access control list
acl_reset aclname -- reset the access control list
acl_show aclname -- list rules in the access control list
...
```

在用 qemu 启动内核时，常用的选项如下

- -m， 指定RAM大小，默认 384M
- -kernel，指定内核镜像文件 bzImage 路径
- -initrd，设置内核启动的内存文件系统
- `-smp [cpus=]n[,cores=cores][,threads=threads][,dies=dies][,sockets=sockets][,maxcpus=maxcpus]`，指定使用到的核数。
- -cpu，指定指定要模拟的处理器架构，可以同时开启一些保护，如
    - +smap，开启 smap 保护
    - +smep，开启 smep 保护
- -nographic，表示不需要图形界面
- -monitor，对 qemu 提供的控制台进行重定向，如果没有设置的话，可以直接进入控制台。
- -append，附加选项
    -  `nokaslr` 关闭随机偏移
    -  console=ttyS0，和 `nographic` 一起使用，启动的界面就变成了当前终端。

## 加载驱动

当然，我们还可以加载之前编译的驱动。将生成的 ko 文件拷贝到 busybox 的 `_install` 目录下，然后对启动脚本进行修改，添加 `insmod /ko_test.ko` ，具体如下

```bash
#!/bin/sh
echo "INIT SCRIPT"
mkdir /tmp
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug
mount -t tmpfs none /tmp
insmod /ko_test.ko
echo -e "Boot took $(cut -d' ' -f1 /proc/uptime) seconds"
setsid /bin/cttyhack setuidgid 1000 /bin/sh
poweroff -f
```

qemu 启动内核后，我们可以使用 dmesg 查看输出，可以看到确实加载了对应的 ko。

```
[    2.019440] ko_test: loading out-of-tree module taints kernel.
[    2.020847] ko_test: module verification failed: signature and/or required key missing - tainting kernel
[    2.025423] This is a test ko!
```

## 调试分析

这里我们简单介绍一下如何调试内核。

### 调试建议

为了方便调试，我们可以使用 root 用户启动 shell，即修改 init 脚本中对应的代码

```shell
- setsid /bin/cttyhack setuidgid 1000 /bin/sh
+ setsid /bin/cttyhack setuidgid 0 /bin/sh
```

此外，我们还可以在启动时，指定内核关闭随机化

```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel ./bzImage \
    -initrd  ./rootfs.img \
    -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 nokaslr" \
    -smp cores=2,threads=1 \
    -cpu kvm64
```

### 基本操作

获取内核特定符号地址

```bash
grep prepare_kernel_cred  /proc/kallsyms
grep commit_creds  /proc/kallsyms
```

查看装载的驱动

```bash
lsmod
```

获取驱动加载的基地址

```bash
# method 1
grep target_module_name /proc/modules 
# method 2
cat /sys/module/target_module_name/sections/.text 
```

/sys/module/ 目录下存放着加载的各个模块的信息。

### 启动调试

qemu 其实提供了调试内核的接口，我们可以在启动参数中添加 `-gdb dev` 来启动调试服务。最常见的操作为在一个端口监听一个 tcp 连接。 QEMU 同时提供了一个简写的方式 `-s`，表示 `-gdb tcp::1234`，即在 1234 端口开启一个 gdbserver。

当我们以调试模式启动内核后，我们就可以在另外一个终端内使用如下命令来连接到对应的 gdbserver，开始调试。

```bash
gdb -q -ex "target remote localhost:1234"
```

在启动内核后，我们可以使用 `add-symbol-file` 来添加符号信息，比如

```
add-symbol-file vmlinux addr_of_vmlinux 
add-symbol-file ./your_module.ko addr_of_ko
```

当然，我们也可以添加源码目录信息。这些就和用户态调试没什么区别了。

## 参考

- https://www.ibm.com/developerworks/cn/linux/l-busybox/index.html
- https://qemu.readthedocs.io/en/latest/system/qemu-manpage.html
- http://blog.nsfocus.net/gdb-kgdb-debug-application/
