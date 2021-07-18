# 用户代码不可执行

起初，在内核态执行代码时，可以直接执行用户态的代码。那如果攻击者控制了内核中的执行流，就可以执行处于用户态的代码。由于用户态的代码是攻击者可控的，所以更容易实施攻击。为了防范这种攻击，研究者提出当位于内核态时，不能执行用户态的代码。在 Linux 内核中，这个防御措施的实现是与指令集架构相关的。

## x86 - SMEP - Supervisor Mode Execution Protection

x86 下对应的保护机制的名字为 SMEP。CR4 寄存器中的第 20 位用来标记是否开启 SMEP 保护。

![20180220141919-fc10512e-1605-1](figure/cr4.png)

### 发展历史

TODO。

### 实现

TODO。

### 开启与关闭

#### 开启

默认情况下，SMEP 保护是开启的。

如果是使用 qemu 启动的内核，我们可以在 `-append` 选项中添加 `+smep` 来开启 SMEP。

#### 关闭

在 `/etc/default/grub` 的如下两行中添加 nosmep

```
GRUB_CMDLINE_LINUX_DEFAULT="quiet"  
GRUB_CMDLINE_LINUX="initrd=/install/initrd.gz"
```

然后运行 `update-grub` 并且重启系统就可以关闭 smep。

如果是使用 qemu 启动的内核，我们可以在 `-append` 选项中添加 `nosmep` 来关闭 SMEP。

### 状态查看

通过如下命令可以检查 SMEP 是否开启，如果发现了 smep 字符串就说明开启了 smep 保护，否则没有开启。

```bash
grep smep /proc/cpuinfo
```

### Attack SMEP

把 CR4 寄存器中的第 20 位置为 0 后，我们就可以执行用户态的代码。一般而言，我们会使用 0x6f0 来设置 CR4，这样 SMAP 和 SMEP 都会被关闭。

内核中修改 cr4 的代码最终会调用到 `native_write_cr4`，当我们能够劫持控制流后，我们可以执行内核中的 gadget 来修改 CR4。从另外一个维度来看，内核中存在固定的修改 cr4 的代码，比如在 `refresh_pce` 函数、` set_tsc_mode` 等函数里都有。

## ARM - PXN

TODO。

## 参考

- https://duasynt.com/slides/smep_bypass.pdf
- https://github.com/torvalds/linux/commit/15385dfe7e0fa6866b204dd0d14aec2cc48fc0a7