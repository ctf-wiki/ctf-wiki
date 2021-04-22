有些时候 pwn 题目中为了增加难度，会使用类似 [seccomp](https://en.wikipedia.org/wiki/Seccomp) 的函数来禁用一部分系统调用，往往会把 execve 这种系统调用禁用掉，基本上拿 shell 是不可能了，但是我们 pwn 题是面向 flag 的，所以还是可以通过 orw（ open-read-write ）的方法来读出 flag 的。在栈上的 orw 和 普通 rop 其实没有什么特别大的区别，这里主要谈一谈堆利用中的白名单绕过。

一般来说，开启了白名单的堆利用类题，我们会在劫持了某钩子函数如 __free_hook 或 got 表之后考虑实现 orw，这个时候我们只可以可以注入一个 gadget，一般来说我们希望这个 gadget 能够实现栈迁移，一种比较通用的做法是利用 setcontext 函数，其在 libc-2.29 中实现为

```
.text:0000000000055E00 ; __unwind {
.text:0000000000055E00                 push    rdi
.text:0000000000055E01                 lea     rsi, [rdi+128h] ; nset
.text:0000000000055E08                 xor     edx, edx        ; oset
.text:0000000000055E0A                 mov     edi, 2          ; how
.text:0000000000055E0F                 mov     r10d, 8         ; sigsetsize
.text:0000000000055E15                 mov     eax, 0Eh
.text:0000000000055E1A                 syscall                 ; LINUX - sys_rt_sigprocmask
.text:0000000000055E1C                 pop     rdx
.text:0000000000055E1D                 cmp     rax, 0FFFFFFFFFFFFF001h
.text:0000000000055E23                 jnb     short loc_55E80
.text:0000000000055E25                 mov     rcx, [rdx+0E0h]
.text:0000000000055E2C                 fldenv  byte ptr [rcx]
.text:0000000000055E2E                 ldmxcsr dword ptr [rdx+1C0h]
.text:0000000000055E35                 mov     rsp, [rdx+0A0h]
.text:0000000000055E3C                 mov     rbx, [rdx+80h]
.text:0000000000055E43                 mov     rbp, [rdx+78h]
.text:0000000000055E47                 mov     r12, [rdx+48h]
.text:0000000000055E4B                 mov     r13, [rdx+50h]
.text:0000000000055E4F                 mov     r14, [rdx+58h]
.text:0000000000055E53                 mov     r15, [rdx+60h]
.text:0000000000055E57                 mov     rcx, [rdx+0A8h]
.text:0000000000055E5E                 push    rcx
.text:0000000000055E5F                 mov     rsi, [rdx+70h]
.text:0000000000055E63                 mov     rdi, [rdx+68h]
.text:0000000000055E67                 mov     rcx, [rdx+98h]
.text:0000000000055E6E                 mov     r8, [rdx+28h]
.text:0000000000055E72                 mov     r9, [rdx+30h]
.text:0000000000055E76                 mov     rdx, [rdx+88h]
.text:0000000000055E76 ; } // starts at 55E00
```

当然其他版本也大同小异，可见在这个函数中有对 rsp 的赋值，如果我们可以控制 rdx，就可以控制 rsp 实现栈迁移了。

## 例题
### 
