# QEMU 下載與編譯

本文介紹如何從源碼編譯 QEMU。

## 獲取 QEMU 源碼

我們可以前往 [qemu 的官網](https://download.qemu.org)下載對應版本的源碼：

```shell
$ wget https://download.qemu.org/qemu-7.0.0.tar.xz
$ tar -xf qemu-7.0.0.tar.xz
```

也可以直接從 [GitHub](https://github.com/qemu/qemu) 上獲取：

```shell
$ git clone git@github.com:qemu/qemu.git
```

## 編譯 QEMU

首先安裝一些必備的依賴：

```shell
$ sudo apt -y install ninja-build build-essential zlib1g-dev pkg-config libglib2.0-dev binutils-dev libpixman-1-dev libfdt-dev
```

接下來創建 build 目錄並配置對應的編譯選項：

```shell
$ mkdir build && cd build
build$ ../qemu-7.0.0/configure --enable-kvm --target-list=x86_64-softmmu --enable-debug
```

這裏我們手動指定了這幾個編譯選項：

- `--enable-kvm`：開啓 kvm 支持。
- `--target-list=<架構名>`：指定要編譯的 CPU 架構，這裏我們指定爲 `x86_64-softmmu` 即表示我們要編譯 x86 架構的 64位 CPU。
- `--enable-debug`：能夠對 Qemu 進行調試。

接下來直接 `make` 即可：

```shell
build$ make -j$(nproc)
```

完成編譯之後在當前目錄下可以看到一個新的可執行文件 `qemu-system_x86-64`，這個就是 Qemu 的本體了。

如果想要從命令行啓動我們自行編譯的 QEMU，則可以鍵入 `make install` 命令，其會自動安裝到 `/bin` 目錄下：

```shell
build$ sudo make install
```

## 調試 QEMU

QEMU 允許我們通過 `-s` 或是 `-gdb tcp::1234` 這樣的附加參數來調試虛擬機（比如說調試 Linux kernel），但有的時候我們想要**直接調試 QEMU 本體**（比如說調試一些自己寫的模擬設備），這個時候就需要我們將 Host 上的 QEMU 進程作爲待調試對象。

由於 QEMU 本質上也是運行在宿主機上的一個進程，因此我們只需要直接找到其對應的 pid 便能直接使用 `gdb attach` 進行調試。

## REFERENCE

[【VIRT.0x00】Qemu - I：Qemu 簡易食用指南](https://arttnba3.cn/2022/07/15/VIRTUALIZATION-0X00-QEMU-PART-I/)

[QEMU 源碼編譯](https://hlyani.github.io/notes/openstack/qemu_make.html)