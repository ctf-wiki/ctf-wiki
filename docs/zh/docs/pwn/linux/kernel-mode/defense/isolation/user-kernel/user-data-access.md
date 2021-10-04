# 用户数据不可访问

如果内核态可以访问用户态的数据，也会出现问题。比如在劫持控制流后，攻击者可以通过栈迁移将栈迁移到用户态，然后进行 ROP，进一步达到提权的目的。在 Linux 内核中，这个防御措施的实现是与指令集架构相关的。

## x86 - SMAP - Supervisor Mode Access Protection

### 介绍

x86 下对应的保护机制的名字为 SMAP。CR4 寄存器中的第 21 位用来标记是否开启 SMEP 保护。

![20180220141919-fc10512e-1605-1](figure/cr4.png)

### 发展历史

TODO。

### 实现

TODO。

### 开启与关闭

#### 开启

默认情况下，SMAP 保护是开启的。

如果是使用 qemu 启动的内核，我们可以在 `-append` 选项中添加 `+smap` 来开启 SMAP。

#### 关闭

在 `/etc/default/grub` 的如下两行中添加 nosmap

```
GRUB_CMDLINE_LINUX_DEFAULT="quiet"  
GRUB_CMDLINE_LINUX="initrd=/install/initrd.gz"
```

然后运行 `update-grub` ，重启系统就可以关闭 smap。

如果是使用 qemu 启动的内核，我们可以在 `-append` 选项中添加 `nosmap` 来关闭 SMAP。

### 状态查看

通过如下命令可以检查 SMAP 是否开启，如果发现了 smap 字符串就说明开启了 smap 保护，否则没有开启。

```bash
grep smap /proc/cpuinfo
```

### Attack SMEP

这里给出几种方式。

#### 设置 CR4 寄存器

把 CR4 寄存器中的第 21 位置为 0 后，我们就可以访问用户态的数据。一般而言，我们会使用 0x6f0 来设置 CR4，这样 SMAP 和 SMEP 都会被关闭。

内核中修改 cr4 的代码最终会调用到 `native_write_cr4`，当我们能够劫持控制流后，我们就可以执行内核中对应的 gadget 来修改 CR4。从另外一个维度来看，内核中存在固定的修改 cr4 的代码，比如在 `refresh_pce` 函数、` set_tsc_mode` 等函数里都有。

#### copy_from/to_user

在劫持控制流后，攻击者可以调用 `copy_from_user` 和 `copy_to_user` 来访问用户态的内存。这两个函数会临时清空禁止访问用户态内存的标志。

## ARM - PAN

TODO。
