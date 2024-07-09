# prefetch side-channel attack

Prefetch 側信道攻擊（Prefetch Side-channel Attacks）是由 [Daniel Gruss](https://gruss.cc/) 於論文 _[Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR](https://gruss.cc/files/prefetch.pdf)_ 中提出來的一種輔助攻擊手法，該攻擊方法利用了 Intel CPU 中 `prefetch` 係指令的硬件設計上的弱點，通過對比在不同虛擬地址上執行 `prefetch` 指令的時間差以泄露內存相關信息，並繞過 KASLR 等保護。

CPU 的高速運行極度依賴於 _推測執行_ （speculative execution，即在條件分支判斷之前推測後續分支並執行相應指令），數據預取（data prefetching）基於此思想將數據推測性地載入緩存，這可以通過硬件（瞬態執行）或軟件（指令，不過有可能會被 CPU 忽略）完成。Intel CPU 有着五個用於預取的指令：`prefetch0` 、`prefetch1`、`prefetch2` 、`prefetchchnta` 、`prefetchw`，用以主動告訴 CPU 某些內存可能將被訪問，ARMv8-A CPUs 也支持了類似的預取指令 `PRFM` 。

## 攻擊原語構建

Prefetch 側信道攻擊利用了 `prefetch` 指令的以下兩個特性：

- **Property 1** ： prefetch 指令的執行時間依賴於 CPU 內部多種緩存的狀態
- **Property 2**：prefetch 指令不需要任何權限檢查

### Translation-level oracle

> 待施工。

###  Address-translation oracle

由於 prefetch 指令不需要任何權限檢查，攻擊者可以在任何虛擬地址上執行 `prefetch` 指令，**包括未映射地址與內核地址**，由此我們可以通過如下步驟驗證兩個虛擬地址 $p$ 與 $\overline{p}$ 是否映射到同一物理地址：

1. 清除地址 $p$

2. 預取（不可訪問的）地址 $\overline{p}$

3. 重新載入地址 $p$

若兩個虛擬地址映射到同一個物理地址，則第二步中對地址 $\overline{p}$ 執行的 prefetch 指令將使得第三步有較高的概率造成緩存命中（cache hit），這種情況下第三步的執行時間將遠小於緩存未命中（cache miss）的情況。

類似地，基於 prefetch 指令的執行時間（property 1），我們可以知道**目標地址 p 是否存在於緩存中**：

1. 清除地址 $p$。

2. 執行函數或系統調用。

3. 預取地址 $p$。

若第二步中訪問的地址 $\overline{p}$ 與地址 $p$ 映射到了同一物理頁面，則第三步的執行時間將遠小於緩存未命中的情況，由此我們便能得知兩個虛擬地址 $p$ 與 $\overline{p}$ 是否映射到同一物理地址，不過這種情況下攻擊者無法得知 $\overline{p}$ ，但能得知 $p$ 被函數或系統調用所使用。

## Translation-level Recovery Attack

> 待施工。

## Address-Translation Attack

現代操作系統內核中通常都有着對物理內存空間的完整線性映射，因此攻擊者可以使用 `Address-translation oracle` 爆破用戶地址空間中地址 $p$ 對應的內核地址空間中該區域對應的地址 $\overline{p}$ ，並利用 property 1 向前爆破以獲取到內核地址空間中對物理地址空間的線性映射的虛擬地址空間的基址（以 Linux 爲例，該區域起始地址爲 `page_offset_base`）。由於在物理地址線性映射區起始地址前的虛擬地址並不存在到對應物理頁面的映射，prefetch 指令的執行時間差異是可以被觀察到的。

## KASLR bypass

我們使用 `Address-translation oracle` 的一種變種來繞過 KASLR。不同於搜索映射到同一物理頁面的虛擬地址，我們通過如下方式確認一個虛擬地址 $p$ 是否被系統調用所使用：

1. 清除所有的緩存（通過訪問一個足夠大的 buffer 來完成）。

2. 執行系統調用，此時相應的頁面會被載入到緩存中。

3. 測量一組 prefetch 指令的執行時間，從而得知虛擬地址 $p$ 是否被系統調用所使用。

通過這個方式，我們可以得知對應系統調用的虛擬地址，從而繞過 KASLR。

### KASLR bypass with KPTI enabled

當 KPTI 開啓時，用戶態程序所使用的頁表幾乎沒有對內核內存的映射，但仍然**存在對系統調用入口函數的映射，這爲 prefetch 側信道攻擊留下了一個缺口**，由於系統調用入口函數同樣存在於內核代碼段中，因此我們可以通過利用 prefetch 側信道攻擊獲取到映射了系統調用入口函數的虛擬地址從而繞過 KASLR。

> 參見 [EntryBleed: Breaking KASLR under KPTI with Prefetch (CVE-2022-4543)](https://www.willsroot.io/2022/12/entrybleed.html)。

## 例題：TCTF2021 Final - kbrop

> 待施工。

## REFERENCE

[Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR](https://gruss.cc/files/prefetch.pdf)

[EntryBleed: Breaking KASLR under KPTI with Prefetch (CVE-2022-4543)](https://www.willsroot.io/2022/12/entrybleed.html)