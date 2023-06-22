# QEMU 下载与编译

本文介绍如何从源码编译 QEMU。

## 获取 QEMU 源码

我们可以前往 [qemu 的官网](https://download.qemu.org)下载对应版本的源码：

```shell
$ wget https://download.qemu.org/qemu-7.0.0.tar.xz
$ tar -xf qemu-7.0.0.tar.xz
```

也可以直接从 [GitHub](https://github.com/qemu/qemu) 上获取：

```shell
$ git clone git@github.com:qemu/qemu.git
```

## 编译 QEMU

首先安装一些必备的依赖：

```shell
$ sudo apt -y install ninja-build build-essential zlib1g-dev pkg-config libglib2.0-dev binutils-dev libpixman-1-dev libfdt-dev
```

接下来创建 build 目录并配置对应的编译选项：

```shell
$ mkdir build && cd build
build$ ../qemu-7.0.0/configure --enable-kvm --target-list=x86_64-softmmu --enable-debug
```

这里我们手动指定了这几个编译选项：

- `--enable-kvm`：开启 kvm 支持。
- `--target-list=<架构名>`：指定要编译的 CPU 架构，这里我们指定为 `x86_64-softmmu` 即表示我们要编译 x86 架构的 64位 CPU。
- `--enable-debug`：能够对 Qemu 进行调试。

接下来直接 `make` 即可：

```shell
build$ make -j$(nproc)
```

完成编译之后在当前目录下可以看到一个新的可执行文件 `qemu-system_x86-64`，这个就是 Qemu 的本体了。

如果想要从命令行启动我们自行编译的 QEMU，则可以键入 `make install` 命令，其会自动安装到 `/bin` 目录下：

```shell
build$ sudo make install
```

## 调试 QEMU

QEMU 允许我们通过 `-s` 或是 `-gdb tcp::1234` 这样的附加参数来调试虚拟机（比如说调试 Linux kernel），但有的时候我们想要**直接调试 QEMU 本体**（比如说调试一些自己写的模拟设备），这个时候就需要我们将 Host 上的 QEMU 进程作为待调试对象。

由于 QEMU 本质上也是运行在宿主机上的一个进程，因此我们只需要直接找到其对应的 pid 便能直接使用 `gdb attach` 进行调试。

## REFERENCE

[【VIRT.0x00】Qemu - I：Qemu 简易食用指南](https://arttnba3.cn/2022/07/15/VIRTUALIZATION-0X00-QEMU-PART-I/)

[QEMU 源码编译](https://hlyani.github.io/notes/openstack/qemu_make.html)