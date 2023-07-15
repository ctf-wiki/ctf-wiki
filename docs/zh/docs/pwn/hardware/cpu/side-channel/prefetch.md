# prefetch side-channel attack

Prefetch 侧信道攻击（Prefetch Side-channel Attacks）是由 [Daniel Gruss](https://gruss.cc/) 于论文 _[Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR](https://gruss.cc/files/prefetch.pdf)_ 中提出来的一种辅助攻击手法，该攻击方法利用了 Intel CPU 中 `prefetch` 系指令的硬件设计上的弱点，通过对比在不同虚拟地址上执行 `prefetch` 指令的时间差以泄露内存相关信息，并绕过 KASLR 等保护。

CPU 的高速运行极度依赖于 _推测执行_ （speculative execution，即在条件分支判断之前推测后续分支并执行相应指令），数据预取（data prefetching）基于此思想将数据推测性地载入缓存，这可以通过硬件（瞬态执行）或软件（指令，不过有可能会被 CPU 忽略）完成。Intel CPU 有着五个用于预取的指令：`prefetch0` 、`prefetch1`、`prefetch2` 、`prefetchchnta` 、`prefetchw`，用以主动告诉 CPU 某些内存可能将被访问，ARMv8-A CPUs 也支持了类似的预取指令 `PRFM` 。

## 攻击原语构建

Prefetch 侧信道攻击利用了 `prefetch` 指令的以下两个特性：

- **Property 1** ： prefetch 指令的执行时间依赖于 CPU 内部多种缓存的状态
- **Property 2**：prefetch 指令不需要任何权限检查

### Translation-level oracle

> 待施工。

###  Address-translation oracle

由于 prefetch 指令不需要任何权限检查，攻击者可以在任何虚拟地址上执行 `prefetch` 指令，**包括未映射地址与内核地址**，由此我们可以通过如下步骤验证两个虚拟地址 $p$ 与 $\overline{p}$ 是否映射到同一物理地址：

1. 清除地址 $p$

2. 预取（不可访问的）地址 $\overline{p}$

3. 重新载入地址 $p$

若两个虚拟地址映射到同一个物理地址，则第二步中对地址 $\overline{p}$ 执行的 prefetch 指令将使得第三步有较高的概率造成缓存命中（cache hit），这种情况下第三步的执行时间将远小于缓存未命中（cache miss）的情况。

类似地，基于 prefetch 指令的执行时间（property 1），我们可以知道**目标地址 p 是否存在于缓存中**：

1. 清除地址 $p$。

2. 执行函数或系统调用。

3. 预取地址 $p$。

若第二步中访问的地址 $\overline{p}$ 与地址 $p$ 映射到了同一物理页面，则第三步的执行时间将远小于缓存未命中的情况，由此我们便能得知两个虚拟地址 $p$ 与 $\overline{p}$ 是否映射到同一物理地址，不过这种情况下攻击者无法得知 $\overline{p}$ ，但能得知 $p$ 被函数或系统调用所使用。

## Translation-level Recovery Attack

> 待施工。

## Address-Translation Attack

现代操作系统内核中通常都有着对物理内存空间的完整线性映射，因此攻击者可以使用 `Address-translation oracle` 爆破用户地址空间中地址 $p$ 对应的内核地址空间中该区域对应的地址 $\overline{p}$ ，并利用 property 1 向前爆破以获取到内核地址空间中对物理地址空间的线性映射的虚拟地址空间的基址（以 Linux 为例，该区域起始地址为 `page_offset_base`）。由于在物理地址线性映射区起始地址前的虚拟地址并不存在到对应物理页面的映射，prefetch 指令的执行时间差异是可以被观察到的。

## KASLR bypass

我们使用 `Address-translation oracle` 的一种变种来绕过 KASLR。不同于搜索映射到同一物理页面的虚拟地址，我们通过如下方式确认一个虚拟地址 $p$ 是否被系统调用所使用：

1. 清除所有的缓存（通过访问一个足够大的 buffer 来完成）。

2. 执行系统调用，此时相应的页面会被载入到缓存中。

3. 测量一组 prefetch 指令的执行时间，从而得知虚拟地址 $p$ 是否被系统调用所使用。

通过这个方式，我们可以得知对应系统调用的虚拟地址，从而绕过 KASLR。

### KASLR bypass with KPTI enabled

当 KPTI 开启时，用户态程序所使用的页表几乎没有对内核内存的映射，但仍然**存在对系统调用入口函数的映射，这为 prefetch 侧信道攻击留下了一个缺口**，由于系统调用入口函数同样存在于内核代码段中，因此我们可以通过利用 prefetch 侧信道攻击获取到映射了系统调用入口函数的虚拟地址从而绕过 KASLR。

> 参见 [EntryBleed: Breaking KASLR under KPTI with Prefetch (CVE-2022-4543)](https://www.willsroot.io/2022/12/entrybleed.html)。

## 例题：TCTF2021 Final - kbrop

> 待施工。

## REFERENCE

[Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR](https://gruss.cc/files/prefetch.pdf)

[EntryBleed: Breaking KASLR under KPTI with Prefetch (CVE-2022-4543)](https://www.willsroot.io/2022/12/entrybleed.html)