# 用戶數據不可訪問

如果內核態可以訪問用戶態的數據，也會出現問題。比如在劫持控制流後，攻擊者可以通過棧遷移將棧遷移到用戶態，然後進行 ROP，進一步達到提權的目的。在 Linux 內核中，這個防禦措施的實現是與指令集架構相關的。

## x86 - SMAP - Supervisor Mode Access Protection

### 介紹

x86 下對應的保護機制的名字爲 SMAP。CR4 寄存器中的第 21 位用來標記是否開啓 SMEP 保護。

![20180220141919-fc10512e-1605-1](figure/cr4.png)

### 發展歷史

TODO。

### 實現

TODO。

### 開啓與關閉

#### 開啓

默認情況下，SMAP 保護是開啓的。

如果是使用 qemu 啓動的內核，我們可以在 `-append` 選項中添加 `+smap` 來開啓 SMAP。

#### 關閉

在 `/etc/default/grub` 的如下兩行中添加 nosmap

```
GRUB_CMDLINE_LINUX_DEFAULT="quiet"  
GRUB_CMDLINE_LINUX="initrd=/install/initrd.gz"
```

然後運行 `update-grub` ，重啓系統就可以關閉 smap。

如果是使用 qemu 啓動的內核，我們可以在 `-append` 選項中添加 `nosmap` 來關閉 SMAP。

### 狀態查看

通過如下命令可以檢查 SMAP 是否開啓，如果發現了 smap 字符串就說明開啓了 smap 保護，否則沒有開啓。

```bash
grep smap /proc/cpuinfo
```

### Attack SMEP

這裏給出幾種方式。

#### 設置 CR4 寄存器

把 CR4 寄存器中的第 21 位置爲 0 後，我們就可以訪問用戶態的數據。一般而言，我們會使用 0x6f0 來設置 CR4，這樣 SMAP 和 SMEP 都會被關閉。

內核中修改 cr4 的代碼最終會調用到 `native_write_cr4`，當我們能夠劫持控制流後，我們就可以執行內核中對應的 gadget 來修改 CR4。從另外一個維度來看，內核中存在固定的修改 cr4 的代碼，比如在 `refresh_pce` 函數、` set_tsc_mode` 等函數裏都有。

#### copy_from/to_user

在劫持控制流後，攻擊者可以調用 `copy_from_user` 和 `copy_to_user` 來訪問用戶態的內存。這兩個函數會臨時清空禁止訪問用戶態內存的標誌。

## ARM - PAN

TODO。
