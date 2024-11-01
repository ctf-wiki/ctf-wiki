# 花指令

## 簡介

花指令（junk code）是一種專門用來迷惑反編譯器的指令片段，這些指令片段不會影響程序的原有功能，但會使得反彙編器的結果出現偏差，從而使破解者分析失敗。比較經典的花指令技巧有利用 `jmp` 、`call`、`ret` 指令改變執行流，從而使得反彙編器解析出與運行時不相符的錯誤代碼。

## 例題：N1CTF2020 - oflo

### 逆向分析

慣例拖入 IDA，發現 `main()` 函數無法被反編譯，查看彙編代碼發現在 `0x400BB1` 處存在一個 原地 `jmp` 使得反彙編出錯：

```c
.text:0000000000400B54 ; int __fastcall main(int, char **, char **)
.text:0000000000400B54 main:                                   ; DATA XREF: start+1D↑o
.text:0000000000400B54                                         ; .text:0000000000400C21↓o
.text:0000000000400B54 ; __unwind {
.text:0000000000400B54                 push    rbp
.text:0000000000400B55                 mov     rbp, rsp
.text:0000000000400B58                 sub     rsp, 240h
.text:0000000000400B5F                 mov     rax, fs:28h
.text:0000000000400B68                 mov     [rbp-8], rax
.text:0000000000400B6C                 xor     eax, eax
.text:0000000000400B6E                 lea     rdx, [rbp-210h]
.text:0000000000400B75                 mov     eax, 0
.text:0000000000400B7A                 mov     ecx, 40h ; '@'
.text:0000000000400B7F                 mov     rdi, rdx
.text:0000000000400B82                 rep stosq
.text:0000000000400B85                 mov     qword ptr [rbp-230h], 0
.text:0000000000400B90                 mov     qword ptr [rbp-228h], 0
.text:0000000000400B9B                 mov     qword ptr [rbp-220h], 0
.text:0000000000400BA6                 mov     qword ptr [rbp-218h], 0
.text:0000000000400BB1
.text:0000000000400BB1 loc_400BB1:                             ; CODE XREF: .text:loc_400BB1↑j
.text:0000000000400BB1                 jmp     short near ptr loc_400BB1+1
.text:0000000000400BB3 ; ---------------------------------------------------------------------------
.text:0000000000400BB3                 ror     byte ptr [rax-70h], 90h
.text:0000000000400BB7                 call    loc_400BBF
.text:0000000000400BB7 ; ---------------------------------------------------------------------------
.text:0000000000400BBC                 db 0E8h, 0EBh, 12h
.text:0000000000400BBF ; ---------------------------------------------------------------------------
```

將 `0x400BB1` 處第一個字節改爲 `0x90` （`nop`），繼續進行反彙編，接下來來到一個奇怪的調用：

```c
.text:0000000000400BB1                 nop
.text:0000000000400BB2                 inc     eax
.text:0000000000400BB4                 xchg    rax, rax
.text:0000000000400BB6                 nop
.text:0000000000400BB7                 call    loc_400BBF
.text:0000000000400BB7 ; ---------------------------------------------------------------------------
.text:0000000000400BBC                 db 0E8h, 0EBh, 12h
.text:0000000000400BBF ; ---------------------------------------------------------------------------
.text:0000000000400BBF
.text:0000000000400BBF loc_400BBF:                             ; CODE XREF: .text:0000000000400BB7↑j
.text:0000000000400BBF                 pop     rax
.text:0000000000400BC0                 add     rax, 1
.text:0000000000400BC4                 push    rax
.text:0000000000400BC5                 mov     rax, rsp
.text:0000000000400BC8                 xchg    rax, [rax]
.text:0000000000400BCB                 pop     rsp
.text:0000000000400BCC                 mov     [rsp], rax
.text:0000000000400BD0                 retn
```

`call` 指令會將下一條指令的地址（`0x400BBC`）壓入棧上，而在代碼片段 `0x400BBF` 中返回地址會被從棧上彈出，值被加一後又壓回棧上並 `retn`，因此這裏實際的執行流從 `0x400BBD` 開始。因此這裏我們可以將 `call` 指令與代碼片段 `0x400BBF` 都 patch 爲 `nop`：

```python
import idc

for i in range(0x400BB7, 0x400BBC + 1):
    idc.patch_byte(i, 0x90)

for i in range(0x400BBF, 0x400BD0 + 1):
    idc.patch_byte(i, 0x90)
```

patch 後的邏輯比較簡單，就是跳到 `0x400BD1`，這裏會調用 `sub_4008B9()` 後直接 `exit()`：

```c
.text:0000000000400BB6                 nop
.text:0000000000400BB7                 nop
.text:0000000000400BB8                 nop
.text:0000000000400BB9                 nop
.text:0000000000400BBA                 nop
.text:0000000000400BBB                 nop
.text:0000000000400BBC                 nop
.text:0000000000400BBD                 jmp     short loc_400BD1
.text:0000000000400BBF ; ---------------------------------------------------------------------------
.text:0000000000400BBF
.text:0000000000400BBF loc_400BBF:                             ; CODE XREF: .text:0000000000400BB7↑j
.text:0000000000400BBF                 nop
.text:0000000000400BC0                 nop
.text:0000000000400BC1                 nop
.text:0000000000400BC2                 nop
.text:0000000000400BC3                 nop
.text:0000000000400BC4                 nop
.text:0000000000400BC5                 nop
.text:0000000000400BC6                 nop
.text:0000000000400BC7                 nop
.text:0000000000400BC8                 nop
.text:0000000000400BC9                 nop
.text:0000000000400BCA                 nop
.text:0000000000400BCB                 nop
.text:0000000000400BCC                 nop
.text:0000000000400BCD                 nop
.text:0000000000400BCE                 nop
.text:0000000000400BCF                 nop
.text:0000000000400BD0                 nop
.text:0000000000400BD1 ; ---------------------------------------------------------------------------
.text:0000000000400BD1
.text:0000000000400BD1 loc_400BD1:                             ; CODE XREF: .text:0000000000400BBD↑j
.text:0000000000400BD1                 lea     rax, [rbp-210h]
.text:0000000000400BD8                 mov     rdi, rax
.text:0000000000400BDB                 call    sub_4008B9
.text:0000000000400BE0                 cmp     eax, 0FFFFFFFFh
.text:0000000000400BE3                 jnz     short loc_400BEF
.text:0000000000400BE5                 mov     edi, 0
.text:0000000000400BEA                 call    exit
```

此時 `main()` 函數還是無法 `F5` ，我們繼續向下看是否還存在花指令，發現在 `0x400CB5` 處存在一個和前面一樣的混淆：

```c
.text:0000000000400CB5                 call    loc_400CBD
.text:0000000000400CB5 ; ---------------------------------------------------------------------------
.text:0000000000400CBA                 dw 0EBE8h
.text:0000000000400CBC                 db 12h
.text:0000000000400CBD ; ---------------------------------------------------------------------------
.text:0000000000400CBD
.text:0000000000400CBD loc_400CBD:                             ; CODE XREF: .text:0000000000400CB5↑j
.text:0000000000400CBD                 pop     rax
.text:0000000000400CBE                 add     rax, 1
.text:0000000000400CC2                 push    rax
.text:0000000000400CC3                 mov     rax, rsp
.text:0000000000400CC6                 xchg    rax, [rax]
.text:0000000000400CC9                 pop     rsp
.text:0000000000400CCA                 mov     [rsp], rax
.text:0000000000400CCE                 retn
```

直接 patch 爲 `nop`：

```python
import idc

for i in range(0x400CB5, 0x400CBA + 1):
    idc.patch_byte(i, 0x90)

for i in range(0x400CBD, 0x400CCE + 1):
    idc.patch_byte(i, 0x90)
```

獲得一個到 `0x400CCF` 的跳轉：

```c
.text:0000000000400CB9                 nop
.text:0000000000400CBA                 nop
.text:0000000000400CBB                 jmp     short loc_400CCF
.text:0000000000400CBD ; ---------------------------------------------------------------------------
.text:0000000000400CBD
.text:0000000000400CBD loc_400CBD:                             ; CODE XREF: .text:0000000000400CB5↑j
.text:0000000000400CBD                 nop
.text:0000000000400CBE                 nop
.text:0000000000400CBF                 nop
.text:0000000000400CC0                 nop
```

繼續向下看，在 `0x400D04` 又發現一個非常經典的花指令，還是直接將第一個字節 patch 爲 `nop` 即可：

```c
.text:0000000000400D04 loc_400D04:                             ; CODE XREF: .text:0000000000400CEE↑j
.text:0000000000400D04                                         ; .text:loc_400D04↑j
.text:0000000000400D04                 jmp     short near ptr loc_400D04+1
.text:0000000000400D04 ; ---------------------------------------------------------------------------
.text:0000000000400D06                 db 0C0h
.text:0000000000400D07                 db  48h ; H
.text:0000000000400D08                 db  90h
.text:0000000000400D09                 db  90h
.text:0000000000400D0A                 db 0BFh
```

現在看起來就是一個非常正常的函數末尾了：

```c
.text:0000000000400D04 loc_400D04:                             ; CODE XREF: .text:0000000000400CEE↑j
.text:0000000000400D04                 nop
.text:0000000000400D05                 inc     eax
.text:0000000000400D07                 xchg    rax, rax
.text:0000000000400D09                 nop
.text:0000000000400D0A                 mov     edi, 0
.text:0000000000400D0F                 call    exit
.text:0000000000400D14 ; ---------------------------------------------------------------------------
.text:0000000000400D14                 nop
.text:0000000000400D15                 mov     rax, [rbp-8]
.text:0000000000400D19                 xor     rax, fs:28h
.text:0000000000400D22                 jz      short locret_400D29
.text:0000000000400D24                 call    ___stack_chk_fail
.text:0000000000400D29 ; ---------------------------------------------------------------------------
.text:0000000000400D29
.text:0000000000400D29 locret_400D29:                          ; CODE XREF: .text:0000000000400D22↑j
.text:0000000000400D29                 leave
.text:0000000000400D2A                 retn
.text:0000000000400D2A ; } // starts at 400B54
```

現在我們回到 `main` 的開頭，`p` 一下重新建立函數，之後就可以正常 `F5` 反編譯了，`main()` 邏輯如下：

- 首先調用 `sub_4008B9()` 
- 接下來從輸入讀取 19 字節
- 調用 `mprotect()` 修改 `main & 0xFFFFC000` 處權限爲 `r | w | x`，由於權限控制粒度爲內存頁，因此這裏實際上會修改一整張內存頁的權限
- 修改 `sub_400A69()` 開頭的 10 個字節
- 調用 `sub_400A69()` 檢查 flag

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int v3; // ecx
  int v4; // er8
  int v5; // er9
  int i; // [rsp+4h] [rbp-23Ch]
  __int64 v7[4]; // [rsp+10h] [rbp-230h] BYREF
  char v8[520]; // [rsp+30h] [rbp-210h] BYREF
  unsigned __int64 v9; // [rsp+238h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  memset(v8, 0, 0x200uLL);
  v7[0] = 0LL;
  v7[1] = 0LL;
  v7[2] = 0LL;
  v7[3] = 0LL;
  if ( (unsigned int)sub_4008B9(v8, a2, v8) == -1 )
    exit(0LL);
  read(0LL, v7, 19LL);
  qword_602048 = (__int64)sub_400A69;
  mprotect((unsigned int)main & 0xFFFFC000, 16LL, 7LL);
  for ( i = 0; i <= 9; ++i )
  {
    v3 = i % 5;
    *(_BYTE *)(qword_602048 + i) ^= *((_BYTE *)v7 + i % 5);
  }
  if ( (unsigned int)sub_400A69((unsigned int)v8, (unsigned int)v7 + 5, (unsigned int)v8, v3, v4, v5) )
    write(1LL, "Cong!\n", 6LL);
  exit(0LL);
}
```

`sub_4008B9()` 會調用 `fork()` 分出父子進程，其中子進程會請求父進程調試執行 `/bin/cat /proc/version`：

```c
__int64 __fastcall sub_4008B9(__int64 a1)
{
  unsigned int v2; // [rsp+14h] [rbp-5Ch] BYREF
  int v3; // [rsp+18h] [rbp-58h]
  unsigned int v4; // [rsp+1Ch] [rbp-54h]
  __int64 v5; // [rsp+20h] [rbp-50h]
  __int64 v6; // [rsp+28h] [rbp-48h]
  __int64 v7; // [rsp+30h] [rbp-40h]
  __int64 v8; // [rsp+38h] [rbp-38h]
  __int64 v9; // [rsp+40h] [rbp-30h] BYREF
  __int64 v10[4]; // [rsp+50h] [rbp-20h] BYREF

  v10[3] = __readfsqword(0x28u);
  v4 = fork();
  if ( (v4 & 0x80000000) != 0 )
    v2 = -1;
  if ( !v4 )
  {
    v10[0] = (__int64)&unk_400DB8;
    v10[1] = (__int64)"/proc/version";
    v10[2] = 0LL;
    v9 = 0LL;
    ptrace(PTRACE_TRACEME, 0LL, 0LL, 0LL);
    execve("/bin/cat", v10, &v9);
    exit(127LL);
  }
```

父進程**以單個系統調用作爲步長進行單步調試**，這裏的 `PTRACE_PEEKUSER` 會根據提供的偏移值取出子進程對應寄存器的值，偏移值與寄存器間關係參見內核源碼 `/arch/x86/include/asm/user_64.h` 中的 `user_regs_struct` 結構體.

這裏偏移 `120` 取的是 `orig_rax`，即**系統調用號，也就是說直到系統調用號爲 `1`（即 `write`）時父進程纔會進入核心邏輯：獲取 `rsi` （偏移 `104`）與 `rdx` （偏移 `96`）並調用 `sub_4007D1()` ：

```c
  v3 = 0;
  v5 = a1;
  while ( 1 )
  {
    wait4(v4, &v2, 0LL, 0LL);
    if ( (v2 & 0x7F) == 0 )
      break;
    v6 = ptrace(PTRACE_PEEKUSER, v4, 120LL, 0LL);
    if ( v6 == 1 )
    {
      if ( v3 )
      {
        v3 = 0;
      }
      else
      {
        v3 = 1;
        v7 = ptrace(PTRACE_PEEKUSER, v4, 104LL, 0LL);
        v8 = ptrace(PTRACE_PEEKUSER, v4, 96LL, 0LL);
        sub_4007D1(v4, v7, v5, v8);
        v5 += v8;
      }
    }
    ptrace(PTRACE_SYSCALL, v4, 0LL, 0LL);
  }
  return v2;
}
```

`sub_4007D1()` 比較簡單，主要就是將子進程調用 `write()` 的輸出結果拷貝回父進程：

```c
__int64 __fastcall sub_4007D1(unsigned int a1, __int64 a2, __int64 a3, __int64 a4)
{
  __int64 result; // rax
  int v6; // [rsp+20h] [rbp-20h]
  int v7; // [rsp+24h] [rbp-1Ch]

  v6 = 0;
  v7 = a4 / 8;
  while ( v6 < v7 )
  {
    *(_QWORD *)(4 * v6 + a3) = ptrace(PTRACE_PEEKDATA, a1, a2 + 4 * v6, 0LL);
    ++v6;
  }
  result = a4 % 8;
  if ( (unsigned int)(a4 % 8) )
  {
    result = ptrace(PTRACE_PEEKDATA, a1, a2 + 4 * v6, 0LL);
    *(_QWORD *)(4 * v6 + a3) = result;
  }
  return result;
}
```

接下來我們回到 `main()` 中，由於 `sub_400A69()` 會在運行時被修改因此我們需要將修改結果直接應用到 IDA 中以獲得正確的反彙編結果，其會取 flag 的前 5 字節與代碼段進行運算，而 flag 的前 5 字節恆定爲 `n1ctf`，因此我們這樣修復 `sub_400A69()` ：

```python
import idc

s = 'n1ctf'

for i in range(0x400A69, 0x400A69 + 10):
    c = idc.get_db_byte(i)
    c ^= ord(s[(i - 0x400A69) % 5])
    idc.patch_byte(i, c)
```

在  `sub_400A69()` 當中還存在一個僞花指令，這裏直接將 `0x400AC4` 的 `jmp` 給 patch 爲 `nop` 即可：

```c
.text:0000000000400A69 sub_400A69      proc near               ; CODE XREF: main+193↓p
.text:0000000000400A69                                         ; DATA XREF: main+B4↓o
.text:0000000000400A69
.text:0000000000400A69 var_40          = qword ptr -40h
.text:0000000000400A69
.text:0000000000400A69 ; __unwind {
.text:0000000000400A69                 push    rbp
.text:0000000000400A6A                 mov     rbp, rsp
.text:0000000000400A6D                 sub     rsp, 40h
.text:0000000000400A71                 mov     [rbp-38h], rdi
.text:0000000000400A75                 mov     [rbp-40h], rsi
.text:0000000000400A79                 mov     rax, fs:28h
.text:0000000000400A82                 mov     [rbp-8], rax
.text:0000000000400A86                 xor     eax, eax
.text:0000000000400A88                 mov     byte ptr [rbp-20h], 35h ; '5'
.text:0000000000400A8C                 mov     byte ptr [rbp-1Fh], 2Dh ; '-'
.text:0000000000400A90                 mov     byte ptr [rbp-1Eh], 11h
.text:0000000000400A94                 mov     byte ptr [rbp-1Dh], 1Ah
.text:0000000000400A98                 mov     byte ptr [rbp-1Ch], 49h ; 'I'
.text:0000000000400A9C                 mov     byte ptr [rbp-1Bh], 7Dh ; '}'
.text:0000000000400AA0                 mov     byte ptr [rbp-1Ah], 11h
.text:0000000000400AA4                 mov     byte ptr [rbp-19h], 14h
.text:0000000000400AA8                 mov     byte ptr [rbp-18h], 2Bh ; '+'
.text:0000000000400AAC                 mov     byte ptr [rbp-17h], 3Bh ; ';'
.text:0000000000400AB0                 mov     byte ptr [rbp-16h], 3Eh ; '>'
.text:0000000000400AB4                 mov     byte ptr [rbp-15h], 3Dh ; '='
.text:0000000000400AB8                 mov     byte ptr [rbp-14h], 3Ch ; '<'
.text:0000000000400ABC                 mov     byte ptr [rbp-13h], 5Fh ; '_'
.text:0000000000400AC0                 jz      short loc_400AC9
.text:0000000000400AC2                 jnz     short loc_400AC9
.text:0000000000400AC4                 jmp     near ptr 801AC9h
```

在 `0x400B0E` 處還是存在一處和前面一樣的花指令，繼續 patch：

```c
.text:0000000000400B0E                 call    loc_400B16
.text:0000000000400B0E ; ---------------------------------------------------------------------------
.text:0000000000400B13                 db 0E8h
.text:0000000000400B14                 db 0EBh
.text:0000000000400B15                 db  12h
.text:0000000000400B16 ; ---------------------------------------------------------------------------
.text:0000000000400B16
.text:0000000000400B16 loc_400B16:                             ; CODE XREF: sub_400A69+A5↑j
.text:0000000000400B16                 pop     rax
.text:0000000000400B17                 add     rax, 1
.text:0000000000400B1B                 push    rax
.text:0000000000400B1C                 mov     rax, rsp
.text:0000000000400B1F                 xchg    rax, [rax]
.text:0000000000400B22                 pop     rsp
.text:0000000000400B23                 mov     [rsp+40h+var_40], rax
.text:0000000000400B27                 retn
```

接下來就能正常地反編譯 `sub_400A69()` 了，核心邏輯其實非常簡單，需要注意的是在 `main()` 中傳入的 flag 從 `n1ctf` 往後開始：

```c
__int64 __fastcall sub_400A69(__int64 a1, __int64 a2)
{
  __int64 v2; // rbp
  int i; // [rsp+14h] [rbp-2Ch]
  char v5[8]; // [rsp+18h] [rbp-28h]
  _BYTE v6[6]; // [rsp+20h] [rbp-20h] BYREF
  unsigned __int64 v7; // [rsp+30h] [rbp-10h]
  __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = v2;
  v7 = __readfsqword(0x28u);
  v5[0] = 53;
  v5[1] = 45;
  v5[2] = 17;
  v5[3] = 26;
  v5[4] = 73;
  v5[5] = 125;
  v5[6] = 17;
  v5[7] = 20;
  qmemcpy(v6, "+;>=<_", sizeof(v6));
  for ( i = 0; i <= 13; ++i )
  {
    if ( v5[i] != ((*(char *)(i + a1) + 2) ^ *(char *)(i + a2)) )
      return 0LL;
  }
  return 1LL;
}
```

### 求解

由於 `/proc/version` 的前 14 字節恆定爲 `"Linux version "` ，因此我們很容易便能得到 flag 內容：

```python
s = "5-\x11\x1AI}\x11\x14+;>=<_"
b = "Linux version "
ans = ""

for i in range(14):
    ans += chr(ord(s[i]) ^ (ord(b[i]) + 2))
print(ans)
# {Fam3_is_NULL}
```
