# 內核下載與編譯

首先，我們需要下載並編譯內核。

## 下載內核

我們可以從 `https://www.kernel.org` 下載想要的內核。根據 https://www.kernel.org/category/releases.html，我們可以知道內核主要有以下幾種類別：

- Prepatch

- Mainline

- Stable
- Longterm

這裏我們選擇長期支持版。

下面爲了方便介紹，我們使用 `5.4` 版本，內核開發者會一直支持這個版本到 2025 年 12 月份。進一步地，我們選擇 5.4 的最新版本 5.4.98（2021 年 2 月記錄）。爲了加速，我們可以選擇就近的源來下載內核，這裏使用清華源：https://mirrors.tuna.tsinghua.edu.cn/kernel/。

```bash
❯ curl -O -L https://mirrors.tuna.tsinghua.edu.cn/kernel/v5.x/linux-5.4.98.tar.xz
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  104M  100  104M    0     0  35.5M      0  0:00:02  0:00:02 --:--:-- 35.5M
❯ unxz linux-5.4.98.tar.xz
```

## 驗證內核簽名

爲了防止內核被惡意修改，在發佈內核時，發佈者會對內核進行簽名。這裏我們也對內核的簽名進行校驗。

```bash
❯ curl -O -L https://mirrors.tuna.tsinghua.edu.cn/kernel/v5.x/linux-5.4.98.tar.sign
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   989  100   989    0     0   5525      0 --:--:-- --:--:-- --:--:--  5525
❯ gpg --verify linux-5.4.98.tar.sign
gpg: assuming signed data in 'linux-5.4.98.tar'
gpg: Signature made 2021年02月13日 星期六 20時54分47秒 CST
gpg:                using RSA key 647F28654894E3BD457199BE38DBBDC86092693E
gpg: Can't check signature: No public key
```

可以看到，我們遇到了 `Can't check signature: No public key` 的問題。這主要是因爲我們沒有相應的公鑰來驗證簽名。此時我們可以下載相應內核版本發佈者的公鑰。

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

爲了方便，我們也導入了 torvalds 的公鑰。下面我們就可以驗證內核的簽名了

```bash
❯ gpg --verify linux-5.4.98.tar.sign
gpg: assuming signed data in 'linux-5.4.98.tar'
gpg: Signature made 2021年02月13日 星期六 20時54分47秒 CST
gpg:                using RSA key 647F28654894E3BD457199BE38DBBDC86092693E
gpg: Good signature from "Greg Kroah-Hartman <gregkh@kernel.org>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: 647F 2865 4894 E3BD 4571  99BE 38DB BDC8 6092 693E
```

這裏報了一個 WARNING。爲了消除這個問題，我們可以選擇使用 TOFU 信任對應的密鑰。

```bash
❯ gpg --tofu-policy good 647F28654894E3BD457199BE38DBBDC86092693E
gpg: Setting TOFU trust policy for new binding <key: 647F28654894E3BD457199BE38DBBDC86092693E, user id: Greg Kroah-Hartman <gregkh@kernel.org>> to good.
❯ gpg --trust-model tofu --verify linux-5.4.98.tar.sign
gpg: assuming signed data in 'linux-5.4.98.tar'
gpg: Signature made 2021年02月13日 星期六 20時54分47秒 CST
gpg:                using RSA key 647F28654894E3BD457199BE38DBBDC86092693E
gpg: Good signature from "Greg Kroah-Hartman <gregkh@kernel.org>" [full]
gpg: gregkh@kernel.org: Verified 1 signatures in the past 0 seconds.  Encrypted
     0 messages.
```

在驗證成功後，我們就可以解壓縮壓縮包得到內核源碼。

```shell
tar -xf linux-5.4.98.tar
```

## 編譯選項配置

在正式編譯之前，我們可以配置內核的編譯選項。

make menuconfig

!!! tip
		可以通過看看這個 menu 頂部的介紹，瞭解這個 menu 如何使用。

### 調試相關選項

這裏我們主要關注調試方面的選項，依次進入到 Kernel hacking -> Compile-time checks and compiler options，然後勾選如下選項`Compile the kernel with debug info`，以便於調試。不過似乎現在是默認開啓的。

如果要使用 kgdb 調試內核，則需要選中 `KGDB: kernel debugger`，並選中 KGDB 下的所有選項。

## 編譯內核

編譯內核鏡像，可以根據機器的核數來選擇具體使用多少核來編譯內核。

```bash
make -j3 bzImage
```

最後，出現如下信息時

```
Setup is 18012 bytes (padded to 18432 bytes).
System is 9189 kB
CRC df09b895
Kernel: arch/x86/boot/bzImage is ready  (#1)
```

意味着編譯成功。在編譯成功後，我們一般主要關注於如下的文件

- bzImage：`arch/x86/boot/bzImage`

- vmlinux：源碼所在的根目錄下。

此外，這裏給出常見內核文件的介紹。

- **bzImage**：目前主流的 kernel 鏡像格式，即 big zImage（即 bz 不是指 bzip2），適用於較大的（大於 512 KB） Kernel。這個鏡像會被加載到內存的高地址，高於 1MB。bzImage 是用 gzip 壓縮的，文件的開頭部分有 gzip 解壓縮的代碼，所以我們不能用 gunzip 來解壓縮。
- **zImage**：比較老的 kernel 鏡像格式，適用於較小的（不大於512KB） Kernel。啓動時，這個鏡像會被加載到內存的低地址，即內存的前 640 KB。zImage 也不能用 gunzip 來解壓縮。
- **vmlinuz**：vmlinuz 不僅包含了壓縮後的 vmlinux，還包含了 gzip 解壓縮的代碼。實際上就是 zImage 或者 bzImage 文件。該文件是 bootable 的。 bootable 是指它能夠把內核加載到內存中。對於 Linux 系統而言，該文件位於 /boot 目錄下。該目錄包含了啓動系統時所需要的文件。
- **vmlinux**：靜態鏈接的 Linux kernel，以可執行文件的形式存在，尚未經過壓縮。該文件往往是在生成 vmlinuz 的過程中產生的。該文件適合於調試。但是該文件不是 bootable 的。
- **vmlinux.bin**：也是靜態鏈接的 Linux kernel，只是以一個可啓動的 (bootable) 二進制文件存在。所有的符號信息和重定位信息都被刪除了。生成命令爲：`objcopy -O binary vmlinux vmlinux.bin`。
- **uImage**：uImage 是 U-boot 專用的鏡像文件，它是在 zImage 之前加上了一個長度爲 0x40 的 tag 而構成的。這個 tag 說明瞭這個鏡像文件的類型、加載位置、生成時間、大小等信息。

## 參考

- https://en.wikipedia.org/wiki/Linux_kernel_version_history
- https://www.kernel.org/category/releases.html
- https://www.kernel.org/signature.html
- http://www.linfo.org/vmlinuz.html
- https://www.nullbyte.cat/post/linux-kernel-exploit-development-environment/#environment-setup

- https://unix.stackexchange.com/questions/5518/what-is-the-difference-between-the-following-kernel-makefile-terms-vmlinux-vml
