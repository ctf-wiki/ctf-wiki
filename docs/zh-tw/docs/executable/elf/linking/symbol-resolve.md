# Symbol Reslove

## 基本原理

鏈接器在處理目標文件時，需要對目標文件中的某些位置進行重定位，即將符號指向恰當的位置，確保程序正常執行。例如，當程序調用了一個函數時，相關的調用指令必須把控制流交給適當的目標執行地址。

在 ELF 文件中，對於每一個需要重定位的 ELF 節都有對應的重定位表，比如說 .text 節如果需要重定位，那麼其對應的重定位表爲 .rel.text。

舉個例子，當一個程序導入某個函數時，.dynstr 就會包含對應函數名稱的字符串，.dynsym 中就會包含一個具有相應名稱的符號（Elf_Sym），在 .rel.plt 中就會包含一個指向這個符號的的重定位表項。即，這幾者之間的引用關係是

![image-20201029230806649](figure/image-20201029230806649-7093160.png)

總的來說，plt 表項主要進行了如下的函數調用來解析目標函數

```c
_dl_runtime_resolve(link_map_obj, reloc_index)
```

## 具體操作

### _dl_runtime_resolve

32 位和 64 位具有不同的 _dl_runtime_resolve 函數，32 位的版本如下

```assembly
        .text
        .globl _dl_runtime_resolve
        .type _dl_runtime_resolve, @function
        cfi_startproc
        .align 16
_dl_runtime_resolve:
        cfi_adjust_cfa_offset (8)
        _CET_ENDBR
        pushl %eax                # Preserve registers otherwise clobbered.
        cfi_adjust_cfa_offset (4)
        pushl %ecx
        cfi_adjust_cfa_offset (4)
        pushl %edx
        cfi_adjust_cfa_offset (4)
        movl 16(%esp), %edx        # Copy args pushed by PLT in register.  Note
        movl 12(%esp), %eax        # that `fixup' takes its parameters in regs.
        call _dl_fixup                # Call resolver.
        popl %edx                # Get register content back.
        cfi_adjust_cfa_offset (-4)
        movl (%esp), %ecx
        movl %eax, (%esp)        # Store the function address.
        movl 4(%esp), %eax
        ret $12                        # Jump to function address.
        cfi_endproc
        .size _dl_runtime_resolve, .-_dl_runtime_resolve
```

其中

- 以 cfi 開頭的都是一些提示性信息，可以不用管。可參考
    - https://stackoverflow.com/questions/51962243/what-is-cfi-adjust-cfa-offset-and-cfi-rel-offset
    - https://sourceware.org/binutils/docs/as/CFI-directives.html
- _CET_ENDBR  則與 Intel 的 CET 相關，標記着間接跳轉的位置。如果程序中的間接跳轉位置處沒有這個指令，那就會出現問題。

因此這部分代碼可以簡化爲

```assembly
        .text
        .globl _dl_runtime_resolve
        .type _dl_runtime_resolve, @function
        .align 16
_dl_runtime_resolve:
        pushl %eax                # Preserve registers otherwise clobbered.
        pushl %ecx
        pushl %edx
        movl 16(%esp), %edx        # Copy args pushed by PLT in register.  Note
        movl 12(%esp), %eax        # that `fixup' takes its parameters in regs.
        call _dl_fixup                # Call resolver.
        popl %edx                # Get register content back.
        movl (%esp), %ecx
        movl %eax, (%esp)        # Store the function address.
        movl 4(%esp), %eax
        ret $12                        # Jump to function address.
        .size _dl_runtime_resolve, .-_dl_runtime_resolve
```

即，`_dl_runtime_resolve` 保存了 eax，ecx，edx 三個寄存器後，然後把 link_map 的地址放到 eax 中，把待解析的符號的偏移放到 edx 中。然後就去執行 `_dl_fixup` 函數。在函數執行返回後，會按照如下的順序執行

- 先恢復 edx 寄存器的值
- 然後 恢復 ecx 的值
- 然後把  `_dl_fixup` 函數的返回值放到當前的棧上
- 然後恢復 eax 的值
- 執行 ret $12，此時棧上爲
    - 待解析的函數的地址
    - original eax
    - `link_map` 的地址
    - reloc_offset

64 位下的 _dl_runtime_resolve 與 32 位下類似，有幾點主要的區別

- 在剛進入函數時，會保存更多的信息
- _dl_fixup 會使用 rdi 和 rsi 傳參
- 最後執行目標函數時使用的是 jmp 指令

```assembly
        .globl _dl_runtime_resolve
        .hidden _dl_runtime_resolve
        .type _dl_runtime_resolve, @function
        .align 16
        cfi_startproc
_dl_runtime_resolve:
        cfi_adjust_cfa_offset(16) # Incorporate PLT
        _CET_ENDBR
# if DL_RUNTIME_RESOLVE_REALIGN_STACK
#  if LOCAL_STORAGE_AREA != 8
#   error LOCAL_STORAGE_AREA must be 8
#  endif
        pushq %rbx                        # push subtracts stack by 8.
        cfi_adjust_cfa_offset(8)
        cfi_rel_offset(%rbx, 0)
        mov %RSP_LP, %RBX_LP
        cfi_def_cfa_register(%rbx)
        and $-STATE_SAVE_ALIGNMENT, %RSP_LP
# endif
# ifdef REGISTER_SAVE_AREA
        sub $REGISTER_SAVE_AREA, %RSP_LP
#  if !DL_RUNTIME_RESOLVE_REALIGN_STACK
        cfi_adjust_cfa_offset(REGISTER_SAVE_AREA)
#  endif
# else
        # Allocate stack space of the required size to save the state.
#  if IS_IN (rtld)
        sub _rtld_local_ro+RTLD_GLOBAL_RO_DL_X86_CPU_FEATURES_OFFSET+XSAVE_STATE_SIZE_OFFSET(%rip), %RSP_LP
#  else
        sub _dl_x86_cpu_features+XSAVE_STATE_SIZE_OFFSET(%rip), %RSP_LP
#  endif
# endif
        # Preserve registers otherwise clobbered.
        movq %rax, REGISTER_SAVE_RAX(%rsp)
        movq %rcx, REGISTER_SAVE_RCX(%rsp)
        movq %rdx, REGISTER_SAVE_RDX(%rsp)
        movq %rsi, REGISTER_SAVE_RSI(%rsp)
        movq %rdi, REGISTER_SAVE_RDI(%rsp)
        movq %r8, REGISTER_SAVE_R8(%rsp)
        movq %r9, REGISTER_SAVE_R9(%rsp)
# ifdef USE_FXSAVE
        fxsave STATE_SAVE_OFFSET(%rsp)
# else
        movl $STATE_SAVE_MASK, %eax
        xorl %edx, %edx
        # Clear the XSAVE Header.
#  ifdef USE_XSAVE
        movq %rdx, (STATE_SAVE_OFFSET + 512)(%rsp)
        movq %rdx, (STATE_SAVE_OFFSET + 512 + 8)(%rsp)
#  endif
        movq %rdx, (STATE_SAVE_OFFSET + 512 + 8 * 2)(%rsp)
        movq %rdx, (STATE_SAVE_OFFSET + 512 + 8 * 3)(%rsp)
        movq %rdx, (STATE_SAVE_OFFSET + 512 + 8 * 4)(%rsp)
        movq %rdx, (STATE_SAVE_OFFSET + 512 + 8 * 5)(%rsp)
        movq %rdx, (STATE_SAVE_OFFSET + 512 + 8 * 6)(%rsp)
        movq %rdx, (STATE_SAVE_OFFSET + 512 + 8 * 7)(%rsp)
#  ifdef USE_XSAVE
        xsave STATE_SAVE_OFFSET(%rsp)
#  else
        xsavec STATE_SAVE_OFFSET(%rsp)
#  endif
# endif
        # Copy args pushed by PLT in register.
        # %rdi: link_map, %rsi: reloc_index
        mov (LOCAL_STORAGE_AREA + 8)(%BASE), %RSI_LP
        mov LOCAL_STORAGE_AREA(%BASE), %RDI_LP
        call _dl_fixup                # Call resolver.
        mov %RAX_LP, %R11_LP        # Save return value
        # Get register content back.
# ifdef USE_FXSAVE
        fxrstor STATE_SAVE_OFFSET(%rsp)
# else
        movl $STATE_SAVE_MASK, %eax
        xorl %edx, %edx
        xrstor STATE_SAVE_OFFSET(%rsp)
# endif
        movq REGISTER_SAVE_R9(%rsp), %r9
        movq REGISTER_SAVE_R8(%rsp), %r8
        movq REGISTER_SAVE_RDI(%rsp), %rdi
        movq REGISTER_SAVE_RSI(%rsp), %rsi
        movq REGISTER_SAVE_RDX(%rsp), %rdx
        movq REGISTER_SAVE_RCX(%rsp), %rcx
        movq REGISTER_SAVE_RAX(%rsp), %rax
# if DL_RUNTIME_RESOLVE_REALIGN_STACK
        mov %RBX_LP, %RSP_LP
        cfi_def_cfa_register(%rsp)
        movq (%rsp), %rbx
        cfi_restore(%rbx)
# endif
        # Adjust stack(PLT did 2 pushes)
        add $(LOCAL_STORAGE_AREA + 16), %RSP_LP
        cfi_adjust_cfa_offset(-(LOCAL_STORAGE_AREA + 16))
        # Preserve bound registers.
        PRESERVE_BND_REGS_PREFIX
        jmp *%r11                # Jump to function address.
        cfi_endproc
        .size _dl_runtime_resolve, .-_dl_runtime_resolve
#endif
```

### _dl_fixup

_dl_runtime_resolve 中執行的最核心的函數就是 _dl_fixup 了，如下（這裏也給出了一些相關的宏），需要注意的是，64 位下的 reloc_arg 就是 reloc_index。 

```c
/* We use this macro to refer to ELF types independent of the native wordsize.
   `ElfW(TYPE)' is used in place of `Elf32_TYPE' or `Elf64_TYPE'.  */
#define ElfW(type) _ElfW(Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e, w, t) _ElfW_1(e, w, _##t)
#define _ElfW_1(e, w, t) e##w##t

/* All references to the value of l_info[DT_PLTGOT],
  l_info[DT_STRTAB], l_info[DT_SYMTAB], l_info[DT_RELA],
  l_info[DT_REL], l_info[DT_JMPREL], and l_info[VERSYMIDX (DT_VERSYM)]
  have to be accessed via the D_PTR macro.  The macro is needed since for
  most architectures the entry is already relocated - but for some not
  and we need to relocate at access time.  */
#ifdef DL_RO_DYN_SECTION
#define D_PTR(map, i) ((map)->i->d_un.d_ptr + (map)->l_addr)
#else
#define D_PTR(map, i) (map)->i->d_un.d_ptr
#endif

#if (!ELF_MACHINE_NO_RELA && !defined ELF_MACHINE_PLT_REL) || ELF_MACHINE_NO_REL
#define PLTREL ElfW(Rela)
#else
#define PLTREL ElfW(Rel)
#endif

/* The type of the return value of fixup/profile_fixup.  */
#define DL_FIXUP_VALUE_TYPE ElfW(Addr)
/* Construct a value of type DL_FIXUP_VALUE_TYPE from a code address
   and a link map.  */
#define DL_FIXUP_MAKE_VALUE(map, addr) (addr)
/* Extract the code address from a value of type DL_FIXUP_MAKE_VALUE.
 */
#define DL_FIXUP_VALUE_CODE_ADDR(value) (value)
#define DL_FIXUP_VALUE_ADDR(value) (value)
#define DL_FIXUP_ADDR_VALUE(addr) (addr)

/* Result of the lookup functions and how to retrieve the base address.  */
typedef struct link_map *lookup_t;
#define LOOKUP_VALUE(map) map
#define LOOKUP_VALUE_ADDRESS(map, set) ((set) || (map) ? (map)->l_addr : 0)
/* Calculate the address of symbol REF using the base address from map MAP,
   if non-NULL.  Don't check for NULL map if MAP_SET is TRUE.  */
#define SYMBOL_ADDRESS(map, ref, map_set)                                                                  \
    ((ref) == NULL ? 0                                                                                     \
                   : (__glibc_unlikely((ref)->st_shndx == SHN_ABS) ? 0                                     \
                                                                   : LOOKUP_VALUE_ADDRESS(map, map_set)) + \
                         (ref)->st_value)

#ifndef reloc_offset
#define reloc_offset reloc_arg
#define reloc_index reloc_arg / sizeof(PLTREL)
#endif
/* This function is called through a special trampoline from the PLT the
   first time each PLT entry is called.  We must perform the relocation
   specified in the PLT of the given shared object, and return the resolved
   function address to the trampoline, which will restart the original call
   to that address.  Future calls will bounce directly from the PLT to the
   function.  */
DL_FIXUP_VALUE_TYPE
attribute_hidden __attribute((noinline)) ARCH_FIXUP_ATTRIBUTE
_dl_fixup(
#ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
    ELF_MACHINE_RUNTIME_FIXUP_ARGS,
#endif
    struct link_map *l, ElfW(Word) reloc_arg)
{
    // 獲取目標文件的動態符號表
    const ElfW(Sym) *const symtab = (const void *)D_PTR(l, l_info[DT_SYMTAB]);
    // 獲取目標文件的動態字符串表
    const char *strtab = (const void *)D_PTR(l, l_info[DT_STRTAB]);
    // 根據給定的偏移獲取待重定位的表項
    const PLTREL *const reloc = (const void *)(D_PTR(l, l_info[DT_JMPREL]) + reloc_offset);
    // 依據得到的重定位表項獲取待解析符號的符號信息
    const ElfW(Sym) *sym = &symtab[ELFW(R_SYM)(reloc->r_info)];
    const ElfW(Sym) *refsym = sym;
    // rel_addr 中最終存儲着要解析的符號的地址
    // 即 *rel_addr = addr_of_symbol_to_be_resolved
    void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
    lookup_t result;
    DL_FIXUP_VALUE_TYPE value;
    /* Sanity check that we're really looking at a PLT relocation.  */
    // 確保待重定位表項的類型爲 ELF_MACHINE_JMP_SLOT
    assert(ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
    /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
    // 判斷符號的可見性
    if (__builtin_expect(ELFW(ST_VISIBILITY)(sym->st_other), 0) == 0)
    {
        // 獲取符號的版本信息
        const struct r_found_version *version = NULL;
        if (l->l_info[VERSYMIDX(DT_VERSYM)] != NULL)
        {
            const ElfW(Half) *vernum = (const void *)D_PTR(l, l_info[VERSYMIDX(DT_VERSYM)]);
            ElfW(Half) ndx = vernum[ELFW(R_SYM)(reloc->r_info)] & 0x7fff;
            version = &l->l_versions[ndx];
            if (version->hash == 0)
                version = NULL;
        }
        /* We need to keep the scope around so do some locking.  This is
         not necessary for objects which cannot be unloaded or when
         we are not using any threads (yet).  */
        int flags = DL_LOOKUP_ADD_DEPENDENCY;
        if (!RTLD_SINGLE_THREAD_P)
        {
            THREAD_GSCOPE_SET_FLAG();
            flags |= DL_LOOKUP_GSCOPE_LOCK;
        }
#ifdef RTLD_ENABLE_FOREIGN_CALL
        RTLD_ENABLE_FOREIGN_CALL;
#endif
        // 查詢待解析符號所在的目標文件的 link_map
        result = _dl_lookup_symbol_x(strtab + sym->st_name, l, &sym, l->l_scope,
                                     version, ELF_RTYPE_CLASS_PLT, flags, NULL);
        /* We are done with the global scope.  */
        if (!RTLD_SINGLE_THREAD_P)
            THREAD_GSCOPE_RESET_FLAG();
#ifdef RTLD_FINALIZE_FOREIGN_CALL
        RTLD_FINALIZE_FOREIGN_CALL;
#endif
        /* Currently result contains the base load address (or link map)
         of the object that defines sym.  Now add in the symbol
         offset.  */
        // 基於查詢到的 link_map 計算符號的絕對地址: result->l_addr + sym->st_value
        // l_addr 爲待解析函數所在文件的基地址
        value = DL_FIXUP_MAKE_VALUE(result,
                                    SYMBOL_ADDRESS(result, sym, false));
    }
    else
    {
        /* We already found the symbol.  The module (and therefore its load
         address) is also known.  */
        value = DL_FIXUP_MAKE_VALUE(l, SYMBOL_ADDRESS(l, sym, true));
        result = l;
    }
    /* And now perhaps the relocation addend.  */
    value = elf_machine_plt_value(l, reloc, value);
    if (sym != NULL && __builtin_expect(ELFW(ST_TYPE)(sym->st_info) == STT_GNU_IFUNC, 0))
        value = elf_ifunc_invoke(DL_FIXUP_VALUE_ADDR(value));
    /* Finally, fix up the plt itself.  */
    // 修復 plt 表
    if (__glibc_unlikely(GLRO(dl_bind_not)))
        return value;
    return elf_machine_fixup_plt(l, result, refsym, sym, reloc, rel_addr, value);
}

static inline ElfW(Addr)
elf_machine_fixup_plt (struct link_map *map, lookup_t t,
                       const ElfW(Sym) *refsym, const ElfW(Sym) *sym,
                       const ElfW(Rela) *reloc,
                       ElfW(Addr) *reloc_addr, ElfW(Addr) value)
{
  return *reloc_addr = value;
}
/* Return the final value of a PLT relocation.  On x86-64 the
   JUMP_SLOT relocation ignores the addend.  */
static inline ElfW(Addr)
elf_machine_plt_value (struct link_map *map, const ElfW(Rela) *reloc,
                       ElfW(Addr) value)
{
  return value;
}
```

## 參考

- https://code.woboq.org/userspace/glibc/sysdeps/x86_64/dl-trampoline.h.html#60
- https://stackoverflow.com/questions/46374907/what-does-the-f-prefix-of-some-gcc-command-line-options-mean
- https://gcc.gnu.org/onlinedocs/gcc/Invoking-GCC.html