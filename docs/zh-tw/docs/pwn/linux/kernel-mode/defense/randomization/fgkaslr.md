# FGKASLR

## 簡介

鑑於 KASLR 的不足，有研究者實現了 FGKASLR。FGKASLR 在 KASLR 基地址隨機化的基礎上，在加載時刻，以函數粒度重新排布內核代碼。

## 實現

FGKASLR 的實現相對比較簡單，主要在兩個部分進行了修改。目前，FGKASLR 只支持 x86_64 架構。

### 編譯階段

FGKASLR 利用 gcc 的編譯選項 `-ffunction-sections` 把內核中不同的函數放到不同的 section 中。 在編譯的過程中，任何使用 C 語言編寫的函數以及不在特殊輸入節的函數都會單獨作爲一個節；使用匯編編寫的代碼會位於一個統一的節中。

編譯後的 vmlinux 保留了所有的節區頭（Section Headers），以便於知道每個函數的地址範圍。同時，FGKASLR 還有一個重定位地址的擴展表。通過這兩組信息，內核在解壓縮後就可以亂序排列函數。

最後的 binary 的第一個段包含了一個合併節（由若干個函數合併而成）、以及若干其它單獨構成一個節的函數。

### 加載階段

在解壓內核後，會首先檢查保留的符號信息，然後尋找需要隨機化的 `.text.*` 節區。其中，第一個合併的節區(`.text`)會被跳過，不會被隨機化。後面節區的地址會被隨機化，但仍然會與 `.text` 節區相鄰。同時，FGKASLR 修改了已有的用於更新重定位地址的代碼，不僅考慮了相對於加載地址的偏移，還考慮了函數節區要被移動到的位置。

爲了隱藏新的內存佈局，/proc/kallsyms 中符號使用隨機的順序來排列。在 v4 版本之前，該文件中的符號按照字母序排列。

通過分析代碼，我們可以知道，在 `layout_randomized_image` 函數中計算了最終會隨機化的節區，存儲在 sections 裏。

```c
	/*
	 * now we need to walk through the section headers and collect the
	 * sizes of the .text sections to be randomized.
	 */
	for (i = 0; i < shnum; i++) {
		s = &sechdrs[i];
		sname = secstrings + s->sh_name;

		if (s->sh_type == SHT_SYMTAB) {
			/* only one symtab per image */
			if (symtab)
				error("Unexpected duplicate symtab");

			symtab = malloc(s->sh_size);
			if (!symtab)
				error("Failed to allocate space for symtab");

			memcpy(symtab, output + s->sh_offset, s->sh_size);
			num_syms = s->sh_size / sizeof(*symtab);
			continue;
		}

		if (s->sh_type == SHT_STRTAB && i != ehdr->e_shstrndx) {
			if (strtab)
				error("Unexpected duplicate strtab");

			strtab = malloc(s->sh_size);
			if (!strtab)
				error("Failed to allocate space for strtab");

			memcpy(strtab, output + s->sh_offset, s->sh_size);
		}

		if (!strcmp(sname, ".text")) {
			if (text)
				error("Unexpected duplicate .text section");

			text = s;
			continue;
		}

		if (!strcmp(sname, ".data..percpu")) {
			/* get start addr for later */
			percpu = s;
			continue;
		}

		if (!(s->sh_flags & SHF_ALLOC) ||
		    !(s->sh_flags & SHF_EXECINSTR) ||
		    !(strstarts(sname, ".text")))
			continue;

		sections[num_sections] = s;

		num_sections++;
	}
	sections[num_sections] = NULL;
	sections_size = num_sections;
```

可以看到，只有同時滿足以下條件的節區纔會參與隨機化

- 節區名以 .text 開頭
- section flags 中包含`SHF_ALLOC`
- section flags 中包含`SHF_EXECINSTR` 

因此，通過以下命令，我們可以知道

- __ksymtab 不會參與隨機化
- .data 不會參與隨機化

```
> readelf --section-headers -W vmlinux| grep -vE " .text|AX"
...
  [36106] .rodata           PROGBITS        ffffffff81c00000 e1e000 382241 00  WA  0   0 4096
  [36107] .pci_fixup        PROGBITS        ffffffff81f82250 11a0250 002ed0 00   A  0   0 16
  [36108] .tracedata        PROGBITS        ffffffff81f85120 11a3120 000078 00   A  0   0  1
  [36109] __ksymtab         PROGBITS        ffffffff81f85198 11a3198 00b424 00   A  0   0  4
  [36110] __ksymtab_gpl     PROGBITS        ffffffff81f905bc 11ae5bc 00dab8 00   A  0   0  4
  [36111] __ksymtab_strings PROGBITS        ffffffff81f9e074 11bc074 027a82 01 AMS  0   0  1
  [36112] __init_rodata     PROGBITS        ffffffff81fc5b00 11e3b00 000230 00   A  0   0 32
  [36113] __param           PROGBITS        ffffffff81fc5d30 11e3d30 002990 00   A  0   0  8
  [36114] __modver          PROGBITS        ffffffff81fc86c0 11e66c0 000078 00   A  0   0  8
  [36115] __ex_table        PROGBITS        ffffffff81fc8740 11e6738 001c50 00   A  0   0  4
  [36116] .notes            NOTE            ffffffff81fca390 11e8388 0001ec 00   A  0   0  4
  [36117] .data             PROGBITS        ffffffff82000000 11ea000 215d80 00  WA  0   0 8192
  [36118] __bug_table       PROGBITS        ffffffff82215d80 13ffd80 01134c 00  WA  0   0  1
  [36119] .vvar             PROGBITS        ffffffff82228000 14110d0 001000 00  WA  0   0 16
  [36120] .data..percpu     PROGBITS        0000000000000000 1413000 02e000 00  WA  0   0 4096
  [36122] .rela.init.text   RELA            0000000000000000 149eec0 000180 18   I 36137 36121  8
  [36124] .init.data        PROGBITS        ffffffff822b6000 14a0000 18d1a0 00  WA  0   0 8192
  [36125] .x86_cpu_dev.init PROGBITS        ffffffff824431a0 162d1a0 000028 00   A  0   0  8
  [36126] .parainstructions PROGBITS        ffffffff824431c8 162d1c8 01e04c 00   A  0   0  8
  [36127] .altinstructions  PROGBITS        ffffffff82461218 164b214 003a9a 00   A  0   0  1
  [36129] .iommu_table      PROGBITS        ffffffff82465bb0 164fbb0 0000a0 00   A  0   0  8
  [36130] .apicdrivers      PROGBITS        ffffffff82465c50 164fc50 000038 00  WA  0   0  8
  [36132] .smp_locks        PROGBITS        ffffffff82468000 1651610 007000 00   A  0   0  4
  [36133] .data_nosave      PROGBITS        ffffffff8246f000 1658610 001000 00  WA  0   0  4
  [36134] .bss              NOBITS          ffffffff82470000 165a000 590000 00  WA  0   0 4096
  [36135] .brk              NOBITS          ffffffff82a00000 1659610 02c000 00  WA  0   0  1
  [36136] .init.scratch     PROGBITS        ffffffff82c00000 1659620 400000 00  WA  0   0 32
  [36137] .symtab           SYMTAB          0000000000000000 1a59620 30abd8 18     36138 111196  8
  [36138] .strtab           STRTAB          0000000000000000 1d641f8 219a29 00      0   0  1
  [36139] .shstrtab         STRTAB          0000000000000000 1f7dc21 0ed17b 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)
```

## 性能開銷

FGKASLR 對於性能的影響主要來自於兩個階段：啓動，運行。

### 啓動階段

在啓動階段，FGKASLR

- 需要解析內核的 ELF 文件來獲取需要隨機化的節區。
- 會調用隨機數生成器來確定每個節區需要存儲的地址，並進行佈局。
- 會將原有解壓的內核拷貝到另外一個地方，以便於避免內存破壞。
- 會增加內核需要重定位的次數。
- 需要檢查每一個需要重定位的地址是否位於隨機化的節區，如果是的話，需要調整一個新的偏移。
- 會重新排列那些需要按照地址排序的數據表。

在一個現代化的系統上，啓動一個測試的 VM，大概花費了 1s。

### 運行階段

運行階段的開銷其實主要取決於具體的負載。不過由於原先相鄰的函數可能被隨機化被放在不同的地址，所以相對而言，整體性能應該會有所降低。

## 內存開銷

在啓動階段，FGKASLR 需要較多的堆內存。因此，FGKASLR 可能不適用於具有較小內存的系統上。這些內存會在內核解壓後被釋放。

## 程序大小影響

FGKASLR 會引入額外的節區頭部信息，因此會增加 vmlinux 文件的大小。在標準的配置下，vmlinux 的大小會增加 3%。壓縮後的鏡像大小大概會增加 15%。

## 開啓與關閉

### 開啓

如果想要開啓內核的 FGKASLR，你需要開啓 `CONFIG_FG_KASLR=y` 選項。

FGKASLR 也支持模塊的隨機化，儘管 FGKASLR 只支持 x86_64 架構下的內核，但是該特性可以支持其它架構下的模塊。我們可以使用 `CONFIG_MODULE_FG_KASLR=y` 來開啓這個特性。

### 關閉

通過在命令行使用 `nokaslr` 關閉 KASLR 也同時會關閉 FGKASLR。當然，我們可以單獨使用 `nofgkaslr` 來關閉 FGKASLR。

## 缺點

根據 FGKASLR 的特點，我們可以發現它具有以下缺陷

- 函數粒度隨機化，如果函數內的某個地址知道了，函數內部的相對地址也就知道了。
- `.text` 節區不參與函數隨機化。因此，一旦知道其中的某個地址，就可以獲取該節區所有的地址。有意思的是系統調用的入口代碼都在該節區內，主要是因爲這些代碼都是彙編代碼。此外，該節區具有以下一些不錯的 gadget
    - swapgs_restore_regs_and_return_to_usermode，該部分的代碼可以幫助我們繞過 KPTI 防護
    - memcpy 內存拷貝
    - sync_regs，可以把 RAX 放到 RDI 中
- `__ksymtab` 相對於內核鏡像的偏移是固定的。因此，如果我們可以泄露數據，那就可以泄露出其它的符號地址，如prepare_kernel_cred、commit_creds。具體方式如下
    - 基於內核鏡像地址獲取 __ksymtab 地址
    - 基於 __ksymtab 獲取對應符號記錄項的地址
    - 根據符號記錄項中具體的內容來獲取對應符號的地址
- data 節區相對於內核鏡像的偏移也是固定的。因此在獲取了內核鏡像的基地址後，就可以計算出數據區數據的地址。這個節區有一些可以重點關注的數據
    - modprobe_path

### __ksymtab 格式

__ksymtab 中每個記錄項的名字的格式爲 ` __ksymtab_func_name`，以 `prepare_kernel_cred` 爲例，對應的記錄項的名字爲` __ksymtab_prepare_kernel_cred`，因此，我們可以直接通過該名字在 IDA 裏找到對應的位置，如下

```assembly
__ksymtab:FFFFFFFF81F8D4FC __ksymtab_prepare_kernel_cred dd 0FF5392F4h
__ksymtab:FFFFFFFF81F8D500                 dd 134B2h
__ksymtab:FFFFFFFF81F8D504                 dd 1783Eh
```

`__ksymtab` 每一項的結構爲

```c
struct kernel_symbol {
	int value_offset;
	int name_offset;
	int namespace_offset;
};
```

第一個表項記錄了重定位表項相對於當前地址的偏移。那麼，`prepare_kernel_cred` 的地址應該爲 `0xFFFFFFFF81F8D4FC-(2**32-0xFF5392F4)=0xffffffff814c67f0`。實際上也確實如此。

```assembly
.text.prepare_kernel_cred:FFFFFFFF814C67F0                 public prepare_kernel_cred
.text.prepare_kernel_cred:FFFFFFFF814C67F0 prepare_kernel_cred proc near           ; CODE XREF: sub_FFFFFFFF814A5ED5+52↑p
```

## 參考

- https://lwn.net/Articles/832434/
- https://github.com/kaccardi/linux/compare/fg-kaslr
- https://elixir.bootlin.com/linux/latest/source/include/linux/export.h#L60
- https://www.youtube.com/watch?v=VcqhJKfOcx4
- https://www.phoronix.com/scan.php?page=article&item=kaslr-fgkaslr-benchmark&num=1
