# Misc

## __ro_after_init

### 介绍

Linux 内核中有很多数据都只会在 `__init` 阶段被初始化，而且之后不会被改变。使用 `__ro_after_init` 标记的内存，在 init 阶段结束后，不能够被再次修改。

### 攻击

我们可以使用 `set_memory_rw(unsigned long addr, int numpages)` 来修改对应页的权限。

## mmap_min_addr

mmap_min_addr 是用来对抗 NULL Pointer Dereference 的，指定用户进程通过 mmap 可以使用的最低的虚拟内存地址。

## 参考

- https://lwn.net/Articles/676145/
- https://lwn.net/Articles/666550/
- https://lore.kernel.org/patchwork/patch/621386/