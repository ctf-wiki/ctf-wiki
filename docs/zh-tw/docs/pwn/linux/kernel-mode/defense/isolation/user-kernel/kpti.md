# KPTI - Kernel Page Table Isolation

## 介紹

KPTI 機制最初的主要目的是爲了緩解 KASLR 的繞過以及 CPU 側信道攻擊。

在 KPTI 機制中，內核態空間的內存和用戶態空間的內存的隔離進一步得到了增強。

- 內核態中的頁表包括用戶空間內存的頁表和內核空間內存的頁表。
- 用戶態的頁表只包括用戶空間內存的頁表以及必要的內核空間內存的頁表，如用於處理系統調用、中斷等信息的內存。

![File:Kernel page-table isolation.svg](figure/476px-Kernel_page-table_isolation.svg.png)

在 x86_64 的 PTI 機制中，內核態的用戶空間內存映射部分被全部標記爲不可執行。也就是說，之前不具有 SMEP 特性的硬件，如果開啓了 KPTI 保護，也具有了類似於 SMEP 的特性。此外，SMAP 模擬也可以以類似的方式引入，只是現在還沒有引入。因此，在目前開啓了 KPTI 保護的內核中，如果沒有開啓 SMAP 保護，那麼內核仍然可以訪問用戶態空間的內存，只是不能跳轉到用戶態空間執行 Shellcode。

Linux 4.15 中引入了 KPTI 機制，並且該機制被反向移植到了 Linux 4.14.11，4.9.75，4.4.110。

## 發展歷史

TODO。

## 實現

TODO。

## 開啓與關閉

如果是使用 qemu 啓動的內核，我們可以在 `-append` 選項中添加 `kpti=1` 來開啓 KPTI。

如果是使用 qemu 啓動的內核，我們可以在 `-append` 選項中添加 `nopti` 來關閉 KPTI。

## 狀態查看

我們可以通過以下兩種方式來查看 KPTI 機制是否開啓。

```shell
/home/pwn # dmesg | grep 'page table'
[    0.000000] Kernel/User page tables isolation: enabled
/home/pwn # cat /proc/cpuinfo | grep pti
fpu_exception   : yes
flags           : ... pti smep smap
```

## Attack KPTI

KPTI 機制和 SMAP 、SMEP不太一樣，由於與源碼緊密結合，似乎沒有辦法在運行時刻關閉。

### 修改頁表

在開啓 KPTI 後，用戶態空間的所有數據都被標記了 NX 權限，但是，我們可以考慮修改對應的頁表權限，使其擁有可執行權限。當內核沒有開啓 smep 權限時，我們在修改了頁表權限後就可以返回到用戶態，並執行用戶態的代碼。

### SWITCH_TO_USER_CR3_STACK

在開啓 KPTI 機制後，用戶態進入到內核態時，會進行頁表切換；當從內核態恢復到用戶態時，也會進行頁表切換。那麼如果我們可以控制內核執行返回用戶態時所執行的切換頁表的代碼片段，也就可以正常地返回到用戶態。

通過分析內核態到用戶態切換的代碼，我們可以得知，頁表的切換主要靠`SWITCH_TO_USER_CR3_STACK` 彙編宏。因此，我們只需要能夠調用這部分代碼即可。

```assembly
.macro SWITCH_TO_USER_CR3_STACK	scratch_reg:req
	pushq	%rax
	SWITCH_TO_USER_CR3_NOSTACK scratch_reg=\scratch_reg scratch_reg2=%rax
	popq	%rax
.endm
.macro SWITCH_TO_USER_CR3_NOSTACK scratch_reg:req scratch_reg2:req
	ALTERNATIVE "jmp .Lend_\@", "", X86_FEATURE_PTI
	mov	%cr3, \scratch_reg

	ALTERNATIVE "jmp .Lwrcr3_\@", "", X86_FEATURE_PCID

	/*
	 * Test if the ASID needs a flush.
	 */
	movq	\scratch_reg, \scratch_reg2
	andq	$(0x7FF), \scratch_reg		/* mask ASID */
	bt	\scratch_reg, THIS_CPU_user_pcid_flush_mask
	jnc	.Lnoflush_\@

	/* Flush needed, clear the bit */
	btr	\scratch_reg, THIS_CPU_user_pcid_flush_mask
	movq	\scratch_reg2, \scratch_reg
	jmp	.Lwrcr3_pcid_\@

.Lnoflush_\@:
	movq	\scratch_reg2, \scratch_reg
	SET_NOFLUSH_BIT \scratch_reg

.Lwrcr3_pcid_\@:
	/* Flip the ASID to the user version */
	orq	$(PTI_USER_PCID_MASK), \scratch_reg

.Lwrcr3_\@:
	/* Flip the PGD to the user version */
	orq     $(PTI_USER_PGTABLE_MASK), \scratch_reg
	mov	\scratch_reg, %cr3
.Lend_\@:
.endm
```

事實上，我們不僅希望切換頁表，還希望能夠返回到用戶態，因此我們這裏也需要複用內核中返回至用戶態的代碼。內核返回到用戶態主要有兩種方式：iret 和 sysret。下面詳細介紹。

#### iret

```assembly
SYM_INNER_LABEL(swapgs_restore_regs_and_return_to_usermode, SYM_L_GLOBAL)
#ifdef CONFIG_DEBUG_ENTRY
	/* Assert that pt_regs indicates user mode. */
	testb	$3, CS(%rsp)
	jnz	1f
	ud2
1:
#endif
	POP_REGS pop_rdi=0

	/*
	 * The stack is now user RDI, orig_ax, RIP, CS, EFLAGS, RSP, SS.
	 * Save old stack pointer and switch to trampoline stack.
	 */
	movq	%rsp, %rdi
	movq	PER_CPU_VAR(cpu_tss_rw + TSS_sp0), %rsp
	UNWIND_HINT_EMPTY

	/* Copy the IRET frame to the trampoline stack. */
	pushq	6*8(%rdi)	/* SS */
	pushq	5*8(%rdi)	/* RSP */
	pushq	4*8(%rdi)	/* EFLAGS */
	pushq	3*8(%rdi)	/* CS */
	pushq	2*8(%rdi)	/* RIP */

	/* Push user RDI on the trampoline stack. */
	pushq	(%rdi)

	/*
	 * We are on the trampoline stack.  All regs except RDI are live.
	 * We can do future final exit work right here.
	 */
	STACKLEAK_ERASE_NOCLOBBER

	SWITCH_TO_USER_CR3_STACK scratch_reg=%rdi

	/* Restore RDI. */
	popq	%rdi
	SWAPGS
	INTERRUPT_RETURN

```

可以看到，通過僞造如下的棧，然後跳轉到 `movq	%rsp, %rdi`，我們就可以同時切換頁表和返回至用戶態。

```
fake rax
fake rdi
RIP
CS
EFLAGS
RSP
SS
```

#### sysret

在使用 sysret 時，我們首先需要確保 rcx 和 r11 爲如下的取值

```
rcx, save the rip of the code to be executed when returning to userspace
r11, save eflags
```

然後構造如下的棧

```
fake rdi
rsp, the stack of the userspace
```

最後跳轉至 entry_SYSCALL_64 的如下代碼，即可返回到用戶態。

```assembly
	SWITCH_TO_USER_CR3_STACK scratch_reg=%rdi

	popq	%rdi
	popq	%rsp
	swapgs
	sysretq
```

### signal handler

我們也可以考慮在用戶態註冊 signal handler 來執行位於用戶態的代碼。在這種方式下，我們無需切換頁表。

## 參考

- https://github.com/pr0cf5/kernel-exploit-practice/tree/master/bypass-smep#bypassing-smepkpti-via-rop
- https://outflux.net/blog/archives/2018/02/05/security-things-in-linux-v4-15/