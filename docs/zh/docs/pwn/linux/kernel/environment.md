# 环境搭建

## 安装依赖

环境是Ubuntu20.04

```shell
$ sudo apt-get update
$ sudo apt-get install git fakeroot build-essential ncurses-dev xz-utils qemu flex libncurses5-dev fakeroot build-essential ncurses-dev xz-utils libssl-dev bc bison libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev
```

## 获取内核镜像（bzImage）

大概有如下三种方式：

- 下载内核源码后编译
- 直接下载现成的的内核镜像，不过这样我们就不能自己魔改内核了2333
- 直接使用自己系统的镜像

### 方法一：自行编译内核源码

#### 获取内核源码

前往[Linux Kernel Archive](https://www.kernel.org/)下载对应版本的内核源码

笔者这里选用5.11这个版本的内核镜像

```shell
$ wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.11.tar.xz
```

#### 配置编译选项

解压我们下载来的内核源码

```shell
$ tar -xvf linux-5.11.tar.xz
```

完成后进入文件夹内，执行如下命令开始配置编译选项

```shell
$ make menuconfig
```

保证勾选如下配置（默认都是勾选了的）：

- Kernel hacking ---> Kernel debugging
- Kernel hacking ---> Compile-time checks and compiler options ---> Compile the kernel with debug info
- Kernel hacking ---> Generic Kernel Debugging Instruments --> KGDB: kernel debugger
- kernel hacking ---> Compile the kernel with frame pointers 

一般来说不需要有什么改动，直接保存退出即可

#### 开始编译

运行如下命令开始编译，生成内核镜像

```shell
$ make bzImage
```

> 可以使用make bzImage -j4加速编译
>
> 笔者机器比较烂，大概要等一顿饭的时间...
>
> 以及编译内核会比较需要空间，一定要保证磁盘剩余空间充足

完成之后会出现如下信息：

```shell
Kernel: arch/x86/boot/bzImage is ready  (#1)
```

##### vmlinux：原始内核文件

在当前目录下提取到```vmlinux```，为编译出来的原始内核文件

```shell
$ file vmlinux
vmlinux: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=f1fc85f87a5e6f3b5714dad93a8ac55fa7450e06, with debug_info, not stripped
```

##### bzImage：压缩内核镜像

在当前目录下的```arch/x86/boot/```目录下提取到```bzImage```，为压缩后的内核文件，适用于大内核

```shell
$ file arch/x86/boot/bzImage
arch/x86/boot/bzImage: Linux kernel x86 boot executable bzImage, version 5.11.0 (root@iZf3ye3at4zthpZ) #1 SMP Sun Feb 21 21:44:35 CST 2021, RO-rootFS, swap_dev 0xB, Normal VGA
```

> ###### zImage && bzImage
>
> zImage--是vmlinux经过gzip压缩后的文件。
> bzImage--bz表示“big zImage”，不是用bzip2压缩的，而是要偏移到一个位置，使用gzip压缩的。两者的不同之处在于，zImage解压缩内核到低端内存(第一个 640K)，bzImage解压缩内核到高端内存(1M以上)。如果内核比较小，那么采用zImage或bzImage都行，如果比较大应该用bzImage。 
> 

### 方法二：下载现有内核镜像

我们也可以自己下载现有的内核镜像，而不需要自行编译一整套Linux内核

使用如下命令列出可下载内核镜像

```shell
$ sudo apt search linux-image- 
```

选一个自己喜欢的下载就行，笔者所用的阿里云源似乎没有最新的5.11的镜像，这里用5.8的做个示范：

```shell
$ sudo apt download linux-image-5.8.0-43-generic
```

下载下来是一个deb文件，解压

```shell
$ dpkg -X ./linux-image-5.8.0-43-generic_5.8.0-43.49~20.04.1_amd64.deb extract
./
./boot/
./boot/vmlinuz-5.8.0-43-generic
./usr/
./usr/share/
./usr/share/doc/
./usr/share/doc/linux-image-5.8.0-43-generic/
./usr/share/doc/linux-image-5.8.0-43-generic/changelog.Debian.gz
./usr/share/doc/linux-image-5.8.0-43-generic/copyright
```

其中的```./boot/vmlinuz-5.8.0-43-generic```便是```bzImage```内核镜像文件

### 方法三：使用系统内核镜像

一般位于```/boot/```目录下，也可以直接拿出来用

## 二、获取busybox

 BusyBox 是一个集成了三百多个最常用Linux命令和工具的软件，包含了例如ls、cat和echo等一些简单的工具

后续构建磁盘镜像我们需要用到busybox

### 编译busybox

#### I.获取busybox源码

在[busybox.net](https://busybox.net/downloads/)下载自己想要的版本，笔者这里选用```busybox-1.33.0.tar.bz2```这个版本

```shell
$ wget https://busybox.net/downloads/busybox-1.33.0.tar.bz2
```

> 外网下载的速度可能会比较慢，可以在前面下载Linux源码的时候一起下载，也可以选择去国内的镜像站下载

解压

```shell
$ tar -jxvf busybox-1.33.0.tar.bz2
```

#### II.编译busybox源码

进入配置界面

```shell
$ make menuconfig
```

勾选Settings ---> Build static binary file (no shared lib)

>  若是不勾选则需要单独配置lib，比较麻烦

接下来就是编译了，速度会比编译内核快很多

```shell
$ make install
```

编译完成后会生成一个```_install```目录，接下来我们将会用它来构建我们的磁盘镜像

## 三、构建磁盘镜像

### 建立文件系统

#### I.初始化文件系统

一些简单的初始化操作...

```shell
$ cd _install
$ mkdir -pv {bin,sbin,etc,proc,sys,home,lib64,lib/x86_64-linux-gnu,usr/{bin,sbin}}
$ touch etc/inittab
$ mkdir etc/init.d
$ touch etc/init.d/rcS
$ chmod +x ./etc/init.d/rcS
```

#### II.配置初始化脚本

首先配置```etc/inttab```，写入如下内容：

```shell
::sysinit:/etc/init.d/rcS
::askfirst:/bin/ash
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/swapoff -a
::shutdown:/bin/umount -a -r
::restart:/sbin/init
```

在上面的文件中指定了系统初始化脚本，因此接下来配置```etc/init.d/rcS```，写入如下内容：

```shell
#!/bin/sh
mount -t proc none /proc
mount -t sys none /sys
/bin/mount -n -t sysfs none /sys
/bin/mount -t ramfs none /dev
/sbin/mdev -s
```

主要是配置各种目录的挂载

也可以在根目录下创建 ```init``` 文件，写入如下内容：

```shell
#!/bin/sh
 
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev

exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys
poweroff -d 0  -f
```

别忘了添加可执行权限：

```shell
$ chmod +x ./init
```

#### 配置用户组

```shell
$ echo "root:x:0:0:root:/root:/bin/sh" > etc/passwd
$ echo "ctf:x:1000:1000:ctf:/home/ctf:/bin/sh" >> etc/passwd
$ echo "root:x:0:" > etc/group
$ echo "ctf:x:1000:" >> etc/group
$ echo "none /dev/pts devpts gid=5,mode=620 0 0" > etc/fstab
```

在这里建立了两个用户组```root```和```ctf```，以及两个用户```root```和```ctf```


### 打包文件系统为镜像文件

使用如下命令打包文件系统

```shell
$ find . | cpio -o --format=newc > ../../rootfs.cpio
```

也可以这么写

```shell
$ find . | cpio -o -H newc > ../core.cpio
```

> 这里的位置是笔者随便选的，也可以将之放到自己喜欢的位置

### 向文件系统中添加文件

若是我们后续需要向文件系统中补充一些其他的文件，可以选择在原先的 ```_install``` 文件夹中添加（不过这样的话若是配置多个文件系统则会变得很混乱），也可以解压文件系统镜像后添加文件再重新进行打包

#### 解压磁盘镜像

```shell
$ cpio -idv < ./rootfs.cpio
```

该命令会将磁盘镜像中的所有文件解压到当前目录下

#### 重打包磁盘镜像

和打包磁盘镜像的命令一样

```shell
$ find . | cpio -o --format=newc > ../new_rootfs.cpio
```

## 使用qemu运行内核

接下来我们将使用 `qemu` 运行我们的 Linux kernel

### 配置启动脚本

首先将先前的 ```bzImage``` 和 ```rootfs.cpio``` 放到同一个目录下

接下来编写启动脚本

```shell
$ touch boot.sh
```

写入如下内容：

```shell
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -kernel ./bzImage \
    -initrd  ./rootfs.cpio \
    -monitor /dev/null \
    -append "root=/dev/ram rdinit=/sbin/init console=ttyS0 oops=panic panic=1 loglevel=3 quiet nokaslr" \
    -cpu kvm64,+smep \
    -smp cores=2,threads=1 \
    -netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
    -nographic \
    -s
```

部分参数说明如下：

- ```-m```：虚拟机内存大小
- ```-kernel```：内存镜像路径
- ```-initrd```：磁盘镜像路径
- ```-append```：附加参数选项
  - ```nokalsr```：关闭内核地址随机化，方便我们进行调试
  - ```rdinit```：指定初始启动进程，```/sbin/init``` 进程会默认以 ```/etc/init.d/rcS``` 作为启动脚本
  - ```loglevel=3 ``` & ```quiet```：不输出log
  - ```console=ttyS0```：指定终端为```/dev/ttyS0```，这样一启动就能进入终端界面
- ```-monitor```：将监视器重定向到主机设备```/dev/null```，这里重定向至null主要是防止CTF中被人给偷了qemu拿flag
- ```-cpu```：设置CPU安全选项，在这里开启了smep保护
- ```-s```：相当于```-gdb tcp::1234```的简写（也可以直接这么写），后续我们可以通过gdb连接本地端口进行调试

运行 ```boot.sh``` 即可成功启动

## 使用gdb调试Linux内核

### remote连接

我们启动时已经将内核映射到了本地的1234端口，只需要gdb连接上就行

```shell
$ gdb
pwndbg> set architecture i386:x86-64
pwndbg> target remote localhost:1234
```


### 寻找gadget

用ROPgadget或者ropper都行，笔者比较喜欢使用ROPgadget

```shell
$ ROPgadget --binary ./vmlinux > gadget.txt
```

一般出来大概有个几十MB

在CTF中有的kernel pwn题目仅给出压缩后镜像```bzImage```，此时我们可以使用 [这个脚本](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux) 进行解压

##  CTF中kernel类题目的部署

和常规的CTF题目的布置方法是相类似的，最常见的办法便是使用```ctf_xinted``` + ```docker```布置，我们只需要配置用ctf\_xinetd启动boot.sh即可

## REFERENCE

[arttnba3 - Linux Kernel Pwn学习笔记 I](https://arttnba3.cn/2021/02/21/NOTE-0X02-LINUX-KERNEL-PWN-PART-I/)

[eqqie - Linux下kernel调试环境搭建](https://eqqie.cn/index.php/laji_note/1475/)

[TaQini - Linux Kernel Pwn 入门笔记](http://taqini.space/2020/11/21/linux-kernel-pwn-learning/)

[Mask - Linux Kernel Pwn I: Basic Knowledge](https://mask6asok.top/2020/02/06/Linux_Kernel_Pwn_1.html)
