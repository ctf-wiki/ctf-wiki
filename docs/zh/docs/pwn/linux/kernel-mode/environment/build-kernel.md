# 内核下载与编译

首先，我们需要下载并编译内核。

## 下载内核

我们可以从 `https://www.kernel.org` 下载想要的内核。根据 https://www.kernel.org/category/releases.html，我们可以知道内核主要有以下几种类别：

- Prepatch

- Mainline

- Stable
- Longterm

这里我们选择长期支持版。

下面为了方便介绍，我们使用 `5.4` 版本，内核开发者会一直支持这个版本到 2025 年 12 月份。进一步地，我们选择 5.4 的最新版本 5.4.98（2021 年 2 月记录）。为了加速，我们可以选择就近的源来下载内核，这里使用清华源：https://mirrors.tuna.tsinghua.edu.cn/kernel/。

```bash
❯ curl -O -L https://mirrors.tuna.tsinghua.edu.cn/kernel/v5.x/linux-5.4.98.tar.xz
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  104M  100  104M    0     0  35.5M      0  0:00:02  0:00:02 --:--:-- 35.5M
❯ unxz linux-5.4.98.tar.xz
```

## 验证内核签名

为了防止内核被恶意修改，在发布内核时，发布者会对内核进行签名。这里我们也对内核的签名进行校验。

```bash
❯ curl -O -L https://mirrors.tuna.tsinghua.edu.cn/kernel/v5.x/linux-5.4.98.tar.sign
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   989  100   989    0     0   5525      0 --:--:-- --:--:-- --:--:--  5525
❯ gpg --verify linux-5.4.98.tar.sign
gpg: assuming signed data in 'linux-5.4.98.tar'
gpg: Signature made 2021年02月13日 星期六 20时54分47秒 CST
gpg:                using RSA key 647F28654894E3BD457199BE38DBBDC86092693E
gpg: Can't check signature: No public key
```

可以看到，我们遇到了 `Can't check signature: No public key` 的问题。这主要是因为我们没有相应的公钥来验证签名。此时我们可以下载相应内核版本发布者的公钥。

```bash
❯ gpg --locate-keys torvalds@kernel.org gregkh@kernel.org
gpg: WARNING: unacceptable HTTP redirect from server was cleaned up
gpg: key 38DBBDC86092693E: public key "Greg Kroah-Hartman <gregkh@kernel.org>" imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg: WARNING: unacceptable HTTP redirect from server was cleaned up
gpg: key 79BE3E4300411886: public key "Linus Torvalds <torvalds@kernel.org>" imported
gpg: Total number processed: 1
gpg:               imported: 1
pub   rsa4096 2011-09-23 [SC]
      647F28654894E3BD457199BE38DBBDC86092693E
uid           [ unknown] Greg Kroah-Hartman <gregkh@kernel.org>
sub   rsa4096 2011-09-23 [E]

pub   rsa2048 2011-09-20 [SC]
      ABAF11C65A2970B130ABE3C479BE3E4300411886
uid           [ unknown] Linus Torvalds <torvalds@kernel.org>
sub   rsa2048 2011-09-20 [E]
```

为了方便，我们也导入了 torvalds 的公钥。下面我们就可以验证内核的签名了

```bash
❯ gpg --verify linux-5.4.98.tar.sign
gpg: assuming signed data in 'linux-5.4.98.tar'
gpg: Signature made 2021年02月13日 星期六 20时54分47秒 CST
gpg:                using RSA key 647F28654894E3BD457199BE38DBBDC86092693E
gpg: Good signature from "Greg Kroah-Hartman <gregkh@kernel.org>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: 647F 2865 4894 E3BD 4571  99BE 38DB BDC8 6092 693E
```

这里报了一个 WARNING。为了消除这个问题，我们可以选择使用 TOFU 信任对应的密钥。

```bash
❯ gpg --tofu-policy good 647F28654894E3BD457199BE38DBBDC86092693E
gpg: Setting TOFU trust policy for new binding <key: 647F28654894E3BD457199BE38DBBDC86092693E, user id: Greg Kroah-Hartman <gregkh@kernel.org>> to good.
❯ gpg --trust-model tofu --verify linux-5.4.98.tar.sign
gpg: assuming signed data in 'linux-5.4.98.tar'
gpg: Signature made 2021年02月13日 星期六 20时54分47秒 CST
gpg:                using RSA key 647F28654894E3BD457199BE38DBBDC86092693E
gpg: Good signature from "Greg Kroah-Hartman <gregkh@kernel.org>" [full]
gpg: gregkh@kernel.org: Verified 1 signatures in the past 0 seconds.  Encrypted
     0 messages.
```

在验证成功后，我们就可以解压缩压缩包得到内核源码。

```shell
tar -xf linux-5.4.98.tar
```

## 编译选项配置

在正式编译之前，我们可以配置内核的编译选项。

make menuconfig

!!! tip
		可以通过看看这个 menu 顶部的介绍，了解这个 menu 如何使用。

### 调试相关选项

这里我们主要关注调试方面的选项，依次进入到 Kernel hacking -> Compile-time checks and compiler options，然后勾选如下选项`Compile the kernel with debug info`，以便于调试。不过似乎现在是默认开启的。

如果要使用 kgdb 调试内核，则需要选中 `KGDB: kernel debugger`，并选中 KGDB 下的所有选项。

## 编译内核

编译内核镜像，可以根据机器的核数来选择具体使用多少核来编译内核。

```bash
make -j3 bzImage
```

最后，出现如下信息时

```
Setup is 18012 bytes (padded to 18432 bytes).
System is 9189 kB
CRC df09b895
Kernel: arch/x86/boot/bzImage is ready  (#1)
```

意味着编译成功。在编译成功后，我们一般主要关注于如下的文件

- bzImage：`arch/x86/boot/bzImage`

- vmlinux：源码所在的根目录下。

此外，这里给出常见内核文件的介绍。

- **bzImage**：目前主流的 kernel 镜像格式，即 big zImage（即 bz 不是指 bzip2），适用于较大的（大于 512 KB） Kernel。这个镜像会被加载到内存的高地址，高于 1MB。bzImage 是用 gzip 压缩的，文件的开头部分有 gzip 解压缩的代码，所以我们不能用 gunzip 来解压缩。
- **zImage**：比较老的 kernel 镜像格式，适用于较小的（不大于512KB） Kernel。启动时，这个镜像会被加载到内存的低地址，即内存的前 640 KB。zImage 也不能用 gunzip 来解压缩。
- **vmlinuz**：vmlinuz 不仅包含了压缩后的 vmlinux，还包含了 gzip 解压缩的代码。实际上就是 zImage 或者 bzImage 文件。该文件是 bootable 的。 bootable 是指它能够把内核加载到内存中。对于 Linux 系统而言，该文件位于 /boot 目录下。该目录包含了启动系统时所需要的文件。
- **vmlinux**：静态链接的 Linux kernel，以可执行文件的形式存在，尚未经过压缩。该文件往往是在生成 vmlinuz 的过程中产生的。该文件适合于调试。但是该文件不是 bootable 的。
- **vmlinux.bin**：也是静态链接的 Linux kernel，只是以一个可启动的 (bootable) 二进制文件存在。所有的符号信息和重定位信息都被删除了。生成命令为：`objcopy -O binary vmlinux vmlinux.bin`。
- **uImage**：uImage 是 U-boot 专用的镜像文件，它是在 zImage 之前加上了一个长度为 0x40 的 tag 而构成的。这个 tag 说明了这个镜像文件的类型、加载位置、生成时间、大小等信息。

## 参考

- https://en.wikipedia.org/wiki/Linux_kernel_version_history
- https://www.kernel.org/category/releases.html
- https://www.kernel.org/signature.html
- http://www.linfo.org/vmlinuz.html
- https://www.nullbyte.cat/post/linux-kernel-exploit-development-environment/#environment-setup

- https://unix.stackexchange.com/questions/5518/what-is-the-difference-between-the-following-kernel-makefile-terms-vmlinux-vml
