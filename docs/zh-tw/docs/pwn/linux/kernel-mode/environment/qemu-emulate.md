# Qemu 模擬環境

這一章節主要介紹如何使用 QEMU 來搭建調試分析環境。爲了使用 qemu 啓動和調試內核，我們需要內核、qemu、文件系統。

## 準備

### 內核

這個在之前已經編譯完成了。

### QEMU

關於 QEMU 的介紹與安裝請參考 `ctf-tools`。

### 文件系統

這裏我們使用 busybox 來構建一個簡單的文件系統。

#### 下載編譯 busybox

##### 下載 busybox

```bash
❯ wget https://busybox.net/downloads/busybox-1.32.1.tar.bz2
❯ tar -jxf busybox-1.32.1.tar.bz2
```

##### 配置

```bash
❯ make menuconfig
```

在 Setttings 選中 Build static binary (no shared libs)，將 busybox 編譯爲靜態鏈接的文件；在 Linux System Utilities 中取消選中 Support mounting NFS file systems on Linux < 2.6.23 (NEW)；在 Networking Utilities 中取消選中 inetd。

##### 編譯

```bash
make -j3
```

#### 配置文件系統

使用 busybox 創建 `_install` 目錄，使用命令：

```bash
make install
```

在編譯完成後，我們在 `_install` 目錄下創建以下文件夾

```bash
❯ mkdir -p  proc sys dev etc/init.d
```

並創建 `init` 作爲 linux 的啓動腳本，內容爲

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

將腳本加上可執行權限，以便於執行。

```bash
❯ chmod +x init
```

之後在 `_install` 目錄下打包整個文件系統

```bash
❯ find . | cpio -o --format=newc > ../rootfs.img
5367 blocks
```

當然，我們還可以使用如下的命令重新解包文件系統

```shell
cpio -idmv < rootfs.img
```

## 啓動內核

這裏以前面編譯好的 Linux 內核、文件系統鏡像爲例來介紹如何啓動內核。我們可以直接使用下面的腳本來啓動 Linux 內核

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

啓動後的效果如下

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

在沒有設置 monitor 時，我們可以使用`ctrl-a+c` 來進入 monitor，可以看到 monitor 提供了很多命令。

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

在用 qemu 啓動內核時，常用的選項如下

- -m， 指定RAM大小，默認 384M
- -kernel，指定內核鏡像文件 bzImage 路徑
- -initrd，設置內核啓動的內存文件系統
- `-smp [cpus=]n[,cores=cores][,threads=threads][,dies=dies][,sockets=sockets][,maxcpus=maxcpus]`，指定使用到的核數。
- -cpu，指定指定要模擬的處理器架構，可以同時開啓一些保護，如
    - +smap，開啓 smap 保護
    - +smep，開啓 smep 保護
- -nographic，表示不需要圖形界面
- -monitor，對 qemu 提供的控制檯進行重定向，如果沒有設置的話，可以直接進入控制檯。
- -append，附加選項
    -  `nokaslr` 關閉隨機偏移
    -  console=ttyS0，和 `nographic` 一起使用，啓動的界面就變成了當前終端。

## 加載驅動

當然，我們還可以加載之前編譯的驅動。將生成的 ko 文件拷貝到 busybox 的 `_install` 目錄下，然後對啓動腳本進行修改，添加 `insmod /ko_test.ko` ，具體如下

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

qemu 啓動內核後，我們可以使用 dmesg 查看輸出，可以看到確實加載了對應的 ko。

```
[    2.019440] ko_test: loading out-of-tree module taints kernel.
[    2.020847] ko_test: module verification failed: signature and/or required key missing - tainting kernel
[    2.025423] This is a test ko!
```

## 調試分析

這裏我們簡單介紹一下如何調試內核。

### 調試建議

爲了方便調試，我們可以使用 root 用戶啓動 shell，即修改 init 腳本中對應的代碼

```shell
- setsid /bin/cttyhack setuidgid 1000 /bin/sh
+ setsid /bin/cttyhack setuidgid 0 /bin/sh
```

此外，我們還可以在啓動時，指定內核關閉隨機化

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

獲取內核特定符號地址

```bash
grep prepare_kernel_cred  /proc/kallsyms
grep commit_creds  /proc/kallsyms
```

查看裝載的驅動

```bash
lsmod
```

獲取驅動加載的基地址

```bash
# method 1
grep target_module_name /proc/modules 
# method 2
cat /sys/module/target_module_name/sections/.text 
```

/sys/module/ 目錄下存放着加載的各個模塊的信息。

### 啓動調試

qemu 其實提供了調試內核的接口，我們可以在啓動參數中添加 `-gdb dev` 來啓動調試服務。最常見的操作爲在一個端口監聽一個 tcp 連接。 QEMU 同時提供了一個簡寫的方式 `-s`，表示 `-gdb tcp::1234`，即在 1234 端口開啓一個 gdbserver。

當我們以調試模式啓動內核後，我們就可以在另外一個終端內使用如下命令來連接到對應的 gdbserver，開始調試。

```bash
gdb -q -ex "target remote localhost:1234"
```

在啓動內核後，我們可以使用 `add-symbol-file` 來添加符號信息，比如

```
add-symbol-file vmlinux addr_of_vmlinux 
add-symbol-file ./your_module.ko addr_of_ko
```

當然，我們也可以添加源碼目錄信息。這些就和用戶態調試沒什麼區別了。

## 參考

- https://www.ibm.com/developerworks/cn/linux/l-busybox/index.html
- https://qemu.readthedocs.io/en/latest/system/qemu-manpage.html
- http://blog.nsfocus.net/gdb-kgdb-debug-application/
