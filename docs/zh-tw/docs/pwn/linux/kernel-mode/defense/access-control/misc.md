# Misc

## __ro_after_init

### 介紹

Linux 內核中有很多數據都只會在 `__init` 階段被初始化，而且之後不會被改變。使用 `__ro_after_init` 標記的內存，在 init 階段結束後，不能夠被再次修改。

### 攻擊

我們可以使用 `set_memory_rw(unsigned long addr, int numpages)` 來修改對應頁的權限。

## mmap_min_addr

mmap_min_addr 是用來對抗 NULL Pointer Dereference 的，指定用戶進程通過 mmap 可以使用的最低的虛擬內存地址。

## 參考

- https://lwn.net/Articles/676145/
- https://lwn.net/Articles/666550/
- https://lore.kernel.org/patchwork/patch/621386/