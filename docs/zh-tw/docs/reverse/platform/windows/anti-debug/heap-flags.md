# Heap Flags

## 關於Heap flags

`Heap flags`包含有兩個與`NtGlobalFlag`一起初始化的標誌: `Flags`和`ForceFlags`. 這兩個字段的值不僅會受調試器的影響, 還會由windows版本而不同, 字段的位置也取決於windows的版本. 

* Flags字段:
    * 在32位Windows NT, Windows 2000和Windows XP中, `Flags`位於堆的`0x0C`偏移處. 在32位Windows Vista及更新的系統中, 它位於`0x40`偏移處. 
    * 在64位Windows XP中, `Flags`字段位於堆的`0x14`偏移處, 而在64位Windows Vista及更新的系統中, 它則是位於`0x70`偏移處.
* ForceFlags字段:
    * 在32位Windows NT, Windows 2000和Windows XP中, `ForceFlags`位於堆的`0x10`偏移處. 在32位Windows Vista及更新的系統中, 它位於`0x44`偏移處. 
    * 在64位Windows XP中, `ForceFlags`字段位於堆的`0x18`偏移處, 而在64位Windows Vista及更新的系統中, 它則是位於`0x74`偏移處.

在所有版本的Windows中, `Flags`字段的值正常情況都設爲`HEAP_GROWABLE(2)`, 而`ForceFlags`字段正常情況都設爲`0`. 然而對於一個32位進程(64位程序不會有此困擾), 這兩個默認值, 都取決於它的宿主進程(host process)的[`subsystem`](https://msdn.microsoft.com/en-us/library/ms933120.aspx)版本(這裏不是指所說的比如win10的linux子系統). 只有當`subsystem`在`3.51`及更高的版本, 字段的默認值才如前所述. 如果是在`3.10-3.50`版本之間, 則兩個字段的`HEAP_CREATE_ALIGN_16 (0x10000)`都會被設置. 如果版本低於`3.10`, 那麼這個程序文件就根本不會被運行. 

如果某操作將`Flags`和`ForgeFlags`字段的值分別設爲`2`和`0`, 但是卻未對`subsystem`版本進行檢查, 那麼就可以表明該動作是爲了隱藏調試器而進行的. 

當調試器存在時, 在`Windows NT`, `Windows 2000`和32位`Windows XP`系統下, `Flags`字段會設置以下標誌:

``` c
HEAP_GROWABLE (2)
HEAP_TAIL_CHECKING_ENABLED (0x20)
HEAP_FREE_CHECKING_ENABLED (0x40)
HEAP_SKIP_VALIDATION_CHECKS (0x10000000)
HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)
```

在64位`Windows XP`系統, `Windows Vista`及更新的系統版本, `Flags`字段則會設置以下標誌(少了`HEAP_SKIP_VALIDATION_CHECKS (0x10000000)`):

``` c
HEAP_GROWABLE (2)
HEAP_TAIL_CHECKING_ENABLED (0x20)
HEAP_FREE_CHECKING_ENABLED (0x40)
HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)
```

而對於`ForgeFlags`字段, 正常情況則會設置以下標誌:

``` c
HEAP_TAIL_CHECKING_ENABLED (0x20)
HEAP_FREE_CHECKING_ENABLED (0x40)
HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)
```

因爲`NtGlobalFlag`標誌的關係, `heap`也會設置一些標誌位

* 如果在`NtGlobalFlag`字段中有設置`FLG_HEAP_ENABLE_TAIL_CHECK`標誌, 那麼在`heap`字段中就會設置`HEAP_TAIL_CHECKING_ENABLED`標誌. 
* 如果在`NtGlobalFlag`字段中有設置`FLG_HEAP_ENABLE_FREE_CHECK`標誌, 那麼在`heap`字段中就會設置`FLG_HEAP_ENABLE_FREE_CHECK`標誌.
* 如果在`NtGlobalFlag`字段中有設置`FLG_HEAP_VALIDATE_PARAMETERS`標誌, 那麼在`heap`字段中就會設置`HEAP_VALIDATE_PARAMETERS_ENABLED`標誌(在`Windows NT`和`Windows 2000`中還會設置`HEAP_CREATE_ALIGN_16 (0x10000)`標誌).

`heap flags`同樣也如上節的`NtGlobalFlag`那樣, 不過它受到註冊表`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<filename>`位置的`PageHeapFlags"`鍵的控制. 

## 獲取heap位置

有多種方法能獲知`heap`的位置, 方法之一就是`kernel32`的`GetProcessHeap()`函數, 當然也可以用以下的32位彙編代碼來檢測32位環境(實際上就有一些殼避免使用該api函數, 直接查詢PEB):

``` asm
mov eax, fs:[30h] ;Process Environment Block
mov eax, [eax+18h] ;get process heap base
```

或使用以下64位代碼來檢測64位環境

``` asm
push 60h
pop rsi
gs:lodsq ;Process Environment Block
mov eax, [rax+30h] ;get process heap base
```

或使用以下32位代碼檢測64位環境

``` asm
mov eax, fs:[30h] ;Process Environment Block
;64-bit Process Environment Block
;follows 32-bit Process Environment Block
mov eax, [eax+1030h] ;get process heap base
```

另外一種方法則是使用`kernel32`的`GetProcessHeaps()`函數, 其實它只是簡單的轉給了`ntdll`的`RtlGetProcessHeaps()`函數, 這個函數會返回屬於當前進程的堆的數組, 而數組的第一個堆, 就跟`kernel32`的`GetProcessHeap()`函數所返回的是一樣的.



這個過程可以用32位代碼檢測32位windows環境來實現:

``` asm
push 30h
pop esi
fs:lodsd ;Process Environment Block
;get process heaps list base
mov esi, [esi+eax+5ch]
lodsd
```

同上, 用64位代碼檢測64位windows環境的代碼是:

``` asm
push 60h
pop rsi
gs:lodsq ;Process Environment Block
;get process heaps list base
mov esi, [rsi*2+rax+20h]
lodsd
```

或使用32位代碼檢測64位window環境:

``` asm
mov eax, fs:[30h] ;Process Environment Block
;64-bit Process Environment Block
;follows 32-bit Process Environment Block
mov esi, [eax+10f0h] ;get process heaps list base
lodsd
```

## 檢測Flags字段

那麼顯然, 檢測調試器我們就可以從檢測那幾個`Flags`和`ForgeFlags`的標誌位入手. 

先看`Flags`字段的檢測代碼, 用32位代碼檢測32位windows環境, 且`subsystem`版本在`3.10-3.50`之間:

``` asm
call GetVersion
cmp al, 6
cmc
sbb ebx, ebx
and ebx, 34h
mov eax, fs:[30h] ;Process Environment Block
mov eax, [eax+18h] ;get process heap base
mov eax, [eax+ebx+0ch] ;Flags
;neither HEAP_CREATE_ALIGN_16
;nor HEAP_SKIP_VALIDATION_CHECKS
and eax, 0effeffffh
;HEAP_GROWABLE
;+ HEAP_TAIL_CHECKING_ENABLED
;+ HEAP_FREE_CHECKING_ENABLED
;+ HEAP_VALIDATE_PARAMETERS_ENABLED
cmp eax, 40000062h
je being_debugged
```

32位代碼檢測32位windows環境, 且`subsystem`爲`3.51`及更高版本:

``` asm
call GetVersion
cmp al, 6
cmc
sbb ebx, ebx
and ebx, 34h
mov eax, fs:[30h] ;Process Environment Block
mov eax, [eax+18h] ;get process heap base
mov eax, [eax+ebx+0ch] ;Flags
;not HEAP_SKIP_VALIDATION_CHECKS
bswap eax
and al, 0efh
;HEAP_GROWABLE
;+ HEAP_TAIL_CHECKING_ENABLED
;+ HEAP_FREE_CHECKING_ENABLED
;+ HEAP_VALIDATE_PARAMETERS_ENABLED
;reversed by bswap
cmp eax, 62000040h
je being_debugged
```

64位代碼檢測64位windows環境(64位進程不必受`subsystem`版本困擾):

``` asm
push 60h
pop rsi
gs:lodsq ;Process Environment Block
mov ebx, [rax+30h] ;get process heap base
call GetVersion
cmp al, 6
sbb rax, rax
and al, 0a4h
;HEAP_GROWABLE
;+ HEAP_TAIL_CHECKING_ENABLED
;+ HEAP_FREE_CHECKING_ENABLED
;+ HEAP_VALIDATE_PARAMETERS_ENABLED
cmp d [rbx+rax+70h], 40000062h ;Flags
je being_debugged
```

用32位代碼檢測64位windows環境:

``` asm
push 30h
pop eax
mov ebx, fs:[eax] ;Process Environment Block
;64-bit Process Environment Block
;follows 32-bit Process Environment Block
mov ah, 10h
mov ebx, [ebx+eax] ;get process heap base
call GetVersion
cmp al, 6
sbb eax, eax
and al, 0a4h
;Flags
;HEAP_GROWABLE
;+ HEAP_TAIL_CHECKING_ENABLED
;+ HEAP_FREE_CHECKING_ENABLED
;+ HEAP_VALIDATE_PARAMETERS_ENABLED
cmp [ebx+eax+70h], 40000062h
je being_debugged
```

如果是直接通過`KUSER_SHARED_DATA`結構的`NtMajorVersion`字段(位於2G用戶空間的`0x7ffe026c`偏移處)獲取該值(在所有32位/64位版本的Windows都可以獲取該值), 可以進一步混淆`kernel32`的`GetVersion()`函數調用操作.


## 檢測ForgeFlags字段

當然另一個方法就是檢測`ForgeFlags`字段, 以下是32位代碼檢測32位Windows環境, `subsystem`版本在`3.10-3.50`之間:

``` asm
call GetVersion
cmp al, 6
cmc
sbb ebx, ebx
and ebx, 34h
mov eax, fs:[30h] ;Process Environment Block
mov eax, [eax+18h] ;get process heap base
mov eax, [eax+ebx+10h] ;ForceFlags
;not HEAP_CREATE_ALIGN_16
btr eax, 10h
;HEAP_TAIL_CHECKING_ENABLED
;+ HEAP_FREE_CHECKING_ENABLED
;+ HEAP_VALIDATE_PARAMETERS_ENABLED
cmp eax, 40000060h
je being_debugged
```

32位代碼檢測32位windows環境, 且`subsystem`爲`3.51`及更高版本:

``` asm
call GetVersion
cmp al, 6
cmc
sbb ebx, ebx
and ebx, 34h
mov eax, fs:[30h] ;Process Environment Block
mov eax, [eax+18h] ;get process heap base
;ForceFlags
;HEAP_TAIL_CHECKING_ENABLED
;+ HEAP_FREE_CHECKING_ENABLED
;+ HEAP_VALIDATE_PARAMETERS_ENABLED
cmp [eax+ebx+10h], 40000060h
je being_debugged
```

64位代碼檢測64位windows環境(64位進程不必受`subsystem`版本困擾):

``` asm
push 60h
pop rsi
gs:lodsq ;Process Environment Block
mov ebx, [rax+30h] ;get process heap base
call GetVersion
cmp al, 6
sbb rax, rax
and al, 0a4h
;ForceFlags
;HEAP_TAIL_CHECKING_ENABLED
;+ HEAP_FREE_CHECKING_ENABLED
;+ HEAP_VALIDATE_PARAMETERS_ENABLED
cmp d [rbx+rax+74h], 40000060h
je being_debugged
```
用32位代碼檢測64位windows環境:

``` asm
call GetVersion
cmp al, 6
push 30h
pop eax
mov ebx, fs:[eax] ;Process Environment Block
;64-bit Process Environment Block
;follows 32-bit Process Environment Block
mov ah, 10h
mov ebx, [ebx+eax] ;get process heap base
sbb eax, eax
and al, 0a4h
;ForceFlags
;HEAP_TAIL_CHECKING_ENABLED
;+ HEAP_FREE_CHECKING_ENABLED
;+ HEAP_VALIDATE_PARAMETERS_ENABLED
cmp [ebx+eax+74h], 40000060h
je being_debugged
```

## 參考鏈接

* [The "Ultimate" Anti-Debugging Reference](http://anti-reversing.com/Downloads/Anti-Reversing/The_Ultimate_Anti-Reversing_Reference.pdf)