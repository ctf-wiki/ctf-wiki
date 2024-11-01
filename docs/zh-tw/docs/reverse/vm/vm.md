# 虛擬機分析

有關虛擬機分析部分, 我們以一道簡單的crackme來進行講解. 

對應的`crackme`可以點擊此處下載: [FuelVM.exe](https://github.com/ctf-wiki/ctf-challenges/blob/master/reverse/vm/fuelvm/FuelVM.exe)

對應的`keygenme`可以點擊此處下載: [fuelvm_keygen.py](https://github.com/ctf-wiki/ctf-challenges/blob/master/reverse/vm/fuelvm/fuelvm_keygen.py)

對應的`IDA數據庫`可以點擊此處下載: [FuelVM.idb](https://github.com/ctf-wiki/ctf-challenges/blob/master/reverse/vm/fuelvm/FuelVM.idb)

本題作者設計了一個具有多種指令的簡單虛擬機. 我們使用IDA來進行分析. 併爲了方便講解, 我對反彙編出的一些變量重新進行了命名. 

## 運行程序

我們運行程序 FuelVM.exe. 界面如下所示

![start.png](./figure/start.png)

在這個界面中, 我們看到右兩個輸入框, 一個用於輸入用戶名Name, 另一個則用於輸入密鑰Key. 還有兩個按鈕, Go用於提交輸入, 而Exit則用於退出程序.

## 獲取用戶輸入

那麼我們就可以從這裏入手. 程序想獲取用戶輸入, 需要調用的一個API是`GetDlgItemTextA()`

``` c
UINT GetDlgItemTextA(
  HWND  hDlg,
  int   nIDDlgItem,
  LPSTR lpString,
  int   cchMax
);
```

獲取的輸入字符串會保存在`lpString`裏. 那麼我們就可以打開IDA查找有交叉引用`GetDlgItemTextA()`的地方.

``` asm
.text:00401142                 push    0Ch             ; cchMax
.text:00401144                 push    offset inputName ; lpString
.text:00401149                 push    3F8h            ; nIDDlgItem
.text:0040114E                 push    [ebp+hWnd]      ; hDlg
.text:00401151                 call    GetDlgItemTextA
.text:00401156                 push    0Ch             ; cchMax
.text:00401158                 push    offset inputKey ; lpString
.text:0040115D                 push    3F9h            ; nIDDlgItem
.text:00401162                 push    [ebp+hWnd]      ; hDlg
.text:00401165                 call    GetDlgItemTextA
.text:0040116A                 mov     var_a, 0
.text:00401171                 call    process_input
.text:00401176                 jmp     short locExit
```

如上, IDA只有這裏調用過`GetDlgItemTextA`並且調用了兩次分別獲取`inputName`和`inputKey`. 隨後初始化了一個變量爲0, 因爲還不明白這個變量的作用, 因此先重命名爲`var_a`. 之後進行了一次函數調用並jmp跳轉. 因爲jmp跳轉位置的代碼是一些退出程序的代碼, 因此我們可以斷定上面的這個call, 是在調用處理用戶輸入的函數. 因此將jmp的位置重命名爲`locExit`, 函數則重命名爲`process_input`. 

## 處理用戶輸入

我們進入`process_input`函數, 該函數僅僅對輸入字符串進行了很簡單的處理. 

```c
  result = strlength((int)inputName);
  if ( v1 >= 7 )                                // v1 = length of inputName
  {
    *(_DWORD *)&lenOfName = v1;
    result = strlength((int)inputKey);
    if ( v2 >= 7 )                              // v2 = length of inputKey
    {
      i = 0;
      do
      {
        inputName[i] ^= i;
        ++i;
      }
      while ( i <= *(_DWORD *)&lenOfName );
      unk_4031CE = i;
      dword_4031C8 = dword_4035FF;
      initVM();
      initVM();
      __debugbreak();
      JUMPOUT(*(_DWORD *)&word_4012CE);
    }
  }
  return result;
```

首先是這個`strlength()`函數. 函數使用`cld; repne scasb; not ecx; dec ecx`來計算字符串長度並將結果保存在`ecx`裏. 是彙編基礎知識就不多介紹. 所以我們將該函數重命名爲`strlength`

```asm
.text:004011C2 arg_0           = dword ptr  8
.text:004011C2
.text:004011C2                 push    ebp
.text:004011C3                 mov     ebp, esp
.text:004011C5                 mov     edi, [ebp+arg_0]
.text:004011C8                 sub     ecx, ecx
.text:004011CA                 sub     al, al
.text:004011CC                 not     ecx
.text:004011CE                 cld
.text:004011CF                 repne scasb
.text:004011D1                 not     ecx
.text:004011D3                 dec     ecx
.text:004011D4                 leave
.text:004011D5                 retn    4
.text:004011D5 strlength       endp
```

而在IDA生成的僞C代碼處有`v1`和`v2`, 我對其進行了註解, 可以看彙編, 裏面是使用`ecx`與`7`進行比較, 而`ecx`是字符串的長度, 於是我們可以知道, 這裏對輸入的要求是: *inputName 和 inputKey 的長度均不少於 7*

當`inputName`和`inputKey`長度均不少於7時, 那麼就可以對輸入進行簡單的變換. 以下是一個循環

```c
      i = 0;
      do
      {
        inputName[i] ^= i;
        ++i;
      }
      while ( i <= *(_DWORD *)&lenOfName );
```

對應的python代碼即

``` python
def obfuscate(username):
    s = ""
    for i in range(len(username)):
        s += chr(ord(username[i]) ^ i)
    return s
```

函數之後對一些變量進行了賦值(這些並不重要, 就忽略不講了.) 

## 註冊SEH

```asm
.text:004012B5                 push    offset seh_handler
.text:004012BA                 push    large dword ptr fs:0
.text:004012C1                 mov     large fs:0, esp
.text:004012C8                 call    initVM
.text:004012CD                 int     3               ; Trap to Debugger
```

`initVM`完成的是一些虛擬機啓動前的初始化工作(其實就是對一些寄存器和相關的部分賦初值), 我們之後來討論. 這裏我們關注的是SEH部分. 這裏註冊了一個SEH句柄, 異常處理函數我重命名爲`seh_handler`, 並之後使用`int 3`手動觸發異常. 而在`seh_handler`位置, IDA並未正確識別出對應的代碼

``` 
.text:004012D7 seh_handler     db 64h                  ; DATA XREF: process_input+7Do
.text:004012D8                 dd 58Fh, 0C4830000h, 13066804h, 0FF640040h, 35h, 25896400h
.text:004012D8                 dd 0
.text:004012F4                 dd 1B8h, 0F7C93300h, 0F7C033F1h, 0FFC483E1h, 8F64FDEBh
.text:004012F4                 dd 5, 4C48300h, 40133068h, 35FF6400h, 0
.text:0040131C                 dd 258964h, 33000000h, 33198BC9h, 83E1F7C0h, 0FDEBFFC4h
.text:0040131C                 dd 58F64h, 83000000h, 5E6804C4h, 64004013h, 35FFh, 89640000h
.text:0040131C                 dd 25h, 0C033CC00h, 0C483E1F7h, 83FDEBFFh, 4035FF05h, 0D8B0200h
.text:0040131C                 dd 4035FFh, 3000B1FFh, 58F0040h, 4031C8h, 31C83D80h, 750A0040h
.text:0040131C                 dd 0B1FF4176h, 403000h, 31C8058Fh, 3D800040h, 4031C8h
```

我們可以點擊相應位置按下`c`鍵, 將這些數據轉換成代碼進行識別. (我們需要按下多次c鍵進行轉換), 得到如下代碼.

如下, 在`seh_handler`位置, 又用類似的方法註冊了一個位於`401306h`的異常處理函數, 並通過`xor ecx,ecx; div ecx`手動觸發了一個`除0異常`. 而在`loc_401301`位置, 這是一個反調試技巧, `jmp loc_401301+2`會使得`EIP`轉向一條指令中間, 使得無法繼續調試. 所以我們可以將`00401301~00401306`部分的代碼`nop`掉, 然後在`00401306`位置創建一個新函數`seh_handler2`

```
seh_handler:                            ; DATA XREF: process_input+7Do
.text:004012D7                 pop     large dword ptr fs:0
.text:004012DE                 add     esp, 4
.text:004012E1                 push    401306h
.text:004012E6                 push    large dword ptr fs:0
.text:004012ED                 mov     large fs:0, esp
.text:004012F4                 mov     eax, 1
.text:004012F9                 xor     ecx, ecx
.text:004012FB                 div     ecx
.text:004012FD                 xor     eax, eax
.text:004012FF                 mul     ecx
.text:00401301
.text:00401301 loc_401301:                             ; CODE XREF: .text:00401304j
.text:00401301                 add     esp, 0FFFFFFFFh
.text:00401304                 jmp     short near ptr loc_401301+2
.text:00401306 ; ---------------------------------------------------------------------------
.text:00401306                 pop     large dword ptr fs:0
.text:0040130D                 add     esp, 4
.text:00401310                 push    401330h
.text:00401315                 push    large dword ptr fs:0
.text:0040131C                 mov     large fs:0, esp
.text:00401323                 xor     ecx, ecx
.text:00401325                 mov     ebx, [ecx]
.text:00401327                 xor     eax, eax
.text:00401329                 mul     ecx
```

類似的, 還有`401330h`重命名爲`seh_handler3`, 而`40135Eh`是最後一個註冊的異常處理函數, 我們可以推測這纔是虛擬機真正的main函數, 因此我們將`40135Eh`重命名爲`vm_main`. (有關SEH和反調試的部分, 可以推薦大家自己去動態調試一番弄清楚)

## 恢復堆棧平衡

我們創建了一個`vm_main`函數(重命名後還需要創建函數, IDA才能識別), 然後按下`F5`提示失敗, 失敗的原因則是由於堆棧不平衡導致的.  因此我們可以點擊IDA菜單項`Options->General`在右側勾選`stack pointer`. 這樣就會顯示出對應的棧指針. 

```
.text:004017F2 000                 jmp     vm_main
.text:004017F7     ; ---------------------------------------------------------------------------
.text:004017F7 000                 push    0               ; uType
.text:004017F9 004                 push    offset aError   ; "Error"
.text:004017FE 008                 push    offset Text     ; "The key is wrong."
.text:00401803 00C                 push    0               ; hWnd
.text:00401805 010                 call    MessageBoxA
.text:0040180A
.text:0040180A     locret_40180A:                          ; CODE XREF: vm_main+492j
.text:0040180A 000                 leave
.text:0040180B -04                 leave
.text:0040180C -08                 leave
.text:0040180D -0C                 leave
.text:0040180E -10                 leave
.text:0040180F -14                 leave
.text:00401810 -18                 leave
.text:00401811 -1C                 retn
.text:00401811     vm_main         endp ; sp-analysis failed
```

我們來到最下顯示不平衡的位置. 最上的`jmp vm_main`表明虛擬機內在執行一個循環. 而`MessageBoxA`的調用則是顯示最後彈出的錯誤信息. 而在`locret_40180A`位置處, 經過多次leave堆棧嚴重不平衡, 因此我們需要手動恢復堆棧平衡. 

這裏也很簡單, 在`0040180A`位置已經堆棧平衡了(000), 因此我們只需要將這一句`leave`修改爲`retn`就可以了. 如下這樣

```
.text:0040180A     locret_40180A:                          ; CODE XREF: vm_main+492j
.text:0040180A 000                 retn
.text:0040180B     ; ---------------------------------------------------------------------------
.text:0040180B 004                 leave
.text:0040180C 004                 leave
.text:0040180D 004                 leave
```

然後你就可以發現`vm_main`可以F5生成僞C代碼了. 

## 虛擬機指令分析

說實話, 虛擬機的分析部分是一個比較枯燥的還原過程, 你需要比對各個小部分的操作來判斷這是一個怎樣的指令, 使用的是哪些寄存器. 像這個crackme中, vm進行的是一個`取指-譯碼-執行`的循環. `譯碼`過程可給予我們的信息最多, 不同的指令都會在這裏, 根據它們各自的`opcode`, 使用`if-else if-else`分支進行區分. 實際的還原過程並不複雜, 但有可能會因爲虛擬機實現的指令數量而顯得有些乏味. 

最後分析出的結果如下:

| opcode | value |
| ------ | ----- |
| push   | 0x0a  |
| pop    | 0x0b  |
| mov    | 0x0c  |
| cmp    | 0x0d  |
| inc    | 0x0e  |
| dec    | 0x0f  |
| and    | 0x1b  |
| or     | 0x1c  |
| xor    | 0x1d  |
| check  | 0xff  |

我們再來看分析後的`initVM`函數

```c
int initVM()
{
  int result; // eax@1

  r1 = 0;
  r2 = 0;
  r3 = 0;
  result = (unsigned __int8)inputName[(unsigned __int8)cur_index];
  r4 = (unsigned __int8)inputName[(unsigned __int8)cur_index];
  vm_sp = 0x32;
  vm_pc = 0;
  vm_flags_zf = 0;
  vm_flags_sf = 0;
  ++cur_index;
  return result;
}
```

這裏有4個通用寄存器(`r1/r2/r3/r4`), 1個`sp`指針和1個`pc`指針, 標誌`zf`和`sf`. 先前我們不知道的`var_a`也被重命名爲`cur_index`, 指向的是`inputName`當前正在處理的字符索引. 

對於VM實現的多個指令我們就不再多說, 重點來看下`check`部分的操作.

```c
int __fastcall check(int a1)
{
  char v1; // al@1
  int result; // eax@4

  v1 = r1;
  if ( (unsigned __int8)r1 < 0x21u )
    v1 = r1 + 0x21;
  LOBYTE(a1) = cur_index;
  if ( v1 == inputKey[a1] )
  {
    if ( (unsigned __int8)cur_index >= (unsigned __int8)lenOfName )
      result = MessageBoxA(0, aGoodJobNowWrit, Caption, 0);
    else
      result = initVM();
  }
  else
  {
    result = MessageBoxA(0, Text, Caption, 0);
  }
  return result;
}
```

如果`r1`中的值跟`inputKey[cur_index]`相等, 那麼會繼續判斷是否已經檢查完了整個`inputName`, 如果沒有出錯且比對結束, 那麼就會彈出`Good job! Now write a keygen.`的消息框. 否則會繼續`initVM`進入下一輪循環.(出錯了當然是彈出消息框提示錯誤了. )

`cur_index`會在`initVM`中自增1, 那麼還記得之前在`process_input`裏有執行2次`initVM`嗎. 因爲有執行2次`initVM`, 所以我們的`inputKey`的前2位可以是任意字符. 

```c
      unk_4031CE = i;
      opcode = vm_pc;
      initVM();
      initVM();
      __debugbreak();
      JUMPOUT(*(_DWORD *)&word_4012CE);
```

 故而我們分析完了整個虛擬機, 便可以開始着手編寫`Keygen`. 

對應的`keygenme`可以點擊此處下載: [fuelvm_keygen.py](https://github.com/ctf-wiki/ctf-challenges/blob/master/reverse/vm/fuelvm/fuelvm_keygen.py)

```bash
$ python2 fuelvm_keygen.py ctf-wiki
[*] Password for user 'ctf-wiki' is: 4mRC*TKJI
```

對應的`IDA數據庫`可以點擊此處下載: [FuelVM.idb](https://github.com/ctf-wiki/ctf-challenges/blob/master/reverse/vm/fuelvm/FuelVM.idb)