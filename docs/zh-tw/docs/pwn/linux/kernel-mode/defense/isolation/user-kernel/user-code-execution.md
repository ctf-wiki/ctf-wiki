# 用戶代碼不可執行

起初，在內核態執行代碼時，可以直接執行用戶態的代碼。那如果攻擊者控制了內核中的執行流，就可以執行處於用戶態的代碼。由於用戶態的代碼是攻擊者可控的，所以更容易實施攻擊。爲了防範這種攻擊，研究者提出當位於內核態時，不能執行用戶態的代碼。在 Linux 內核中，這個防禦措施的實現是與指令集架構相關的。

## x86 - SMEP - Supervisor Mode Execution Protection

x86 下對應的保護機制的名字爲 SMEP。CR4 寄存器中的第 20 位用來標記是否開啓 SMEP 保護。

![20180220141919-fc10512e-1605-1](figure/cr4.png)

### 發展歷史

TODO。

### 實現

TODO。

### 開啓與關閉

#### 開啓

默認情況下，SMEP 保護是開啓的。

如果是使用 qemu 啓動的內核，我們可以在 `-append` 選項中添加 `+smep` 來開啓 SMEP。

#### 關閉

在 `/etc/default/grub` 的如下兩行中添加 nosmep

```
GRUB_CMDLINE_LINUX_DEFAULT="quiet"  
GRUB_CMDLINE_LINUX="initrd=/install/initrd.gz"
```

然後運行 `update-grub` 並且重啓系統就可以關閉 smep。

如果是使用 qemu 啓動的內核，我們可以在 `-append` 選項中添加 `nosmep` 來關閉 SMEP。

### 狀態查看

通過如下命令可以檢查 SMEP 是否開啓，如果發現了 smep 字符串就說明開啓了 smep 保護，否則沒有開啓。

```bash
grep smep /proc/cpuinfo
```

### Attack SMEP

把 CR4 寄存器中的第 20 位置爲 0 後，我們就可以執行用戶態的代碼。一般而言，我們會使用 0x6f0 來設置 CR4，這樣 SMAP 和 SMEP 都會被關閉。

內核中修改 cr4 的代碼最終會調用到 `native_write_cr4`，當我們能夠劫持控制流後，我們可以執行內核中的 gadget 來修改 CR4。從另外一個維度來看，內核中存在固定的修改 cr4 的代碼，比如在 `refresh_pce` 函數、` set_tsc_mode` 等函數裏都有。

## ARM - PXN

TODO。

## 參考

- https://duasynt.com/slides/smep_bypass.pdf
- https://github.com/torvalds/linux/commit/15385dfe7e0fa6866b204dd0d14aec2cc48fc0a7