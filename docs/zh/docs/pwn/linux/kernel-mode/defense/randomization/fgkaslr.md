# FGKASLR

## 简介

鉴于 KASLR 的不足，有研究者实现了 FGKASLR。FGKASLR 在 KASLR 基地址随机化的基础上，在加载时刻，以函数粒度重新排布内核代码。

## 实现

FGKASLR 的实现相对比较简单，主要在两个部分进行了修改。目前，FGKASLR 只支持 x86_64 架构。

### 编译阶段

FGKASLR 利用 gcc 的编译选项 `-ffunction-sections` 把内核中不同的函数放到不同的 section 中。 在编译的过程中，任何使用 C 语言编写的函数以及不在特殊输入节的函数都会单独作为一个节；使用汇编编写的代码会位于一个统一的节中。

编译后的 vmlinux 保留了所有的节区头（Section Headers），以便于知道每个函数的地址范围。同时，FGKASLR 还有一个重定位地址的扩展表。通过这两组信息，内核在解压缩后就可以乱序排列函数。

最后的 binary 的第一个段包含了一个合并节（由若干个函数合并而成）、以及若干其它单独构成一个节的函数。

### 加载阶段

在解压内核后，会首先检查保留的符号信息，然后寻找需要随机化的 `.text.*` 节区。其中，第一个合并的节区(`.text`)会被跳过，不会被随机化。后面节区的地址会被随机化，但仍然会与 `.text` 节区相邻。同时，FGKASLR 修改了已有的用于更新重定位地址的代码，不仅考虑了相对于加载地址的偏移，还考虑了函数节区要被移动到的位置。

为了隐藏新的内存布局，/proc/kallsyms 中符号使用随机的顺序来排列。在 v4 版本之前，该文件中的符号按照字母序排列。

通过分析代码，我们可以知道，在 `layout_randomized_image` 函数中计算了最终会随机化的节区，存储在 sections 里。

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

可以看到，只有同时满足以下条件的节区才会参与随机化

- 节区名以 .text 开头
- section flags 中包含`SHF_ALLOC`
- section flags 中包含`SHF_EXECINSTR` 

因此，通过以下命令，我们可以知道

- __ksymtab 不会参与随机化
- .data 不会参与随机化

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

## 性能开销

FGKASLR 对于性能的影响主要来自于两个阶段：启动，运行。

### 启动阶段

在启动阶段，FGKASLR

- 需要解析内核的 ELF 文件来获取需要随机化的节区。
- 会调用随机数生成器来确定每个节区需要存储的地址，并进行布局。
- 会将原有解压的内核拷贝到另外一个地方，以便于避免内存破坏。
- 会增加内核需要重定位的次数。
- 需要检查每一个需要重定位的地址是否位于随机化的节区，如果是的话，需要调整一个新的偏移。
- 会重新排列那些需要按照地址排序的数据表。

在一个现代化的系统上，启动一个测试的 VM，大概花费了 1s。

### 运行阶段

运行阶段的开销其实主要取决于具体的负载。不过由于原先相邻的函数可能被随机化被放在不同的地址，所以相对而言，整体性能应该会有所降低。

## 内存开销

在启动阶段，FGKASLR 需要较多的堆内存。因此，FGKASLR 可能不适用于具有较小内存的系统上。这些内存会在内核解压后被释放。

## 程序大小影响

FGKASLR 会引入额外的节区头部信息，因此会增加 vmlinux 文件的大小。在标准的配置下，vmlinux 的大小会增加 3%。压缩后的镜像大小大概会增加 15%。

## 开启与关闭

### 开启

如果想要开启内核的 FGKASLR，你需要开启 `CONFIG_FG_KASLR=y` 选项。

FGKASLR 也支持模块的随机化，尽管 FGKASLR 只支持 x86_64 架构下的内核，但是该特性可以支持其它架构下的模块。我们可以使用 `CONFIG_MODULE_FG_KASLR=y` 来开启这个特性。

### 关闭

通过在命令行使用 `nokaslr` 关闭 KASLR 也同时会关闭 FGKASLR。当然，我们可以单独使用 `nofgkaslr` 来关闭 FGKASLR。

## 缺点

根据 FGKASLR 的特点，我们可以发现它具有以下缺陷

- 函数粒度随机化，如果函数内的某个地址知道了，函数内部的相对地址也就知道了。
- `.text` 节区不参与函数随机化。因此，一旦知道其中的某个地址，就可以获取该节区所有的地址。有意思的是系统调用的入口代码都在该节区内，主要是因为这些代码都是汇编代码。此外，该节区具有以下一些不错的 gadget
    - swapgs_restore_regs_and_return_to_usermode，该部分的代码可以帮助我们绕过 KPTI 防护
    - memcpy 内存拷贝
    - sync_regs，可以把 RAX 放到 RDI 中
- `__ksymtab` 相对于内核镜像的偏移是固定的。因此，如果我们可以泄露数据，那就可以泄露出其它的符号地址，如prepare_kernel_cred、commit_creds。具体方式如下
    - 基于内核镜像地址获取 __ksymtab 地址
    - 基于 __ksymtab 获取对应符号记录项的地址
    - 根据符号记录项中具体的内容来获取对应符号的地址
- data 节区相对于内核镜像的偏移也是固定的。因此在获取了内核镜像的基地址后，就可以计算出数据区数据的地址。这个节区有一些可以重点关注的数据
    - modprobe_path

### __ksymtab 格式

__ksymtab 中每个记录项的名字的格式为 ` __ksymtab_func_name`，以 `prepare_kernel_cred` 为例，对应的记录项的名字为` __ksymtab_prepare_kernel_cred`，因此，我们可以直接通过该名字在 IDA 里找到对应的位置，如下

```assembly
__ksymtab:FFFFFFFF81F8D4FC __ksymtab_prepare_kernel_cred dd 0FF5392F4h
__ksymtab:FFFFFFFF81F8D500                 dd 134B2h
__ksymtab:FFFFFFFF81F8D504                 dd 1783Eh
```

`__ksymtab` 每一项的结构为

```c
struct kernel_symbol {
	int value_offset;
	int name_offset;
	int namespace_offset;
};
```

第一个表项记录了重定位表项相对于当前地址的偏移。那么，`prepare_kernel_cred` 的地址应该为 `0xFFFFFFFF81F8D4FC-(2**32-0xFF5392F4)=0xffffffff814c67f0`。实际上也确实如此。

```assembly
.text.prepare_kernel_cred:FFFFFFFF814C67F0                 public prepare_kernel_cred
.text.prepare_kernel_cred:FFFFFFFF814C67F0 prepare_kernel_cred proc near           ; CODE XREF: sub_FFFFFFFF814A5ED5+52↑p
```

## 参考

- https://lwn.net/Articles/832434/
- https://github.com/kaccardi/linux/compare/fg-kaslr
- https://elixir.bootlin.com/linux/latest/source/include/linux/export.h#L60
- https://www.youtube.com/watch?v=VcqhJKfOcx4
- https://www.phoronix.com/scan.php?page=article&item=kaslr-fgkaslr-benchmark&num=1
