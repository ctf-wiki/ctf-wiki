[EN](./heap-flags.md) | [ZH](./heap-flags-zh.md)
## 关于Heap flags

`Heap flags`包含有两个与`NtGlobalFlag`一起初始化的标志: `Flags`和`ForceFlags`. 这两个字段的值不仅会受调试器的影响, 还会由windows版本而不同, 字段的位置也取决于windows的版本. 

* Flags字段:
    * 在32位Windows NT, Windows 2000和Windows XP中, `Flags`位于堆的`0x0C`偏移处. 在32位Windows Vista及更新的系统中, 它位于`0x40`偏移处. 
    * 在64位Windows XP中, `Flags`字段位于堆的`0x14`偏移处, 而在64位Windows Vista及更新的系统中, 它则是位于`0x70`偏移处.
* ForceFlags字段:
    * 在32位Windows NT, Windows 2000和Windows XP中, `ForceFlags`位于堆的`0x10`偏移处. 在32位Windows Vista及更新的系统中, 它位于`0x44`偏移处. 
    * 在64位Windows XP中, `ForceFlags`字段位于堆的`0x18`偏移处, 而在64位Windows Vista及更新的系统中, 它则是位于`0x74`偏移处.

在所有版本的Windows中, `Flags`字段的值正常情况都设为`HEAP_GROWABLE(2)`, 而`ForceFlags`字段正常情况都设为`0`. 然而对于一个32位进程(64位程序不会有此困扰), 这两个默认值, 都取决于它的宿主进程(host process)的[`subsystem`](https://msdn.microsoft.com/en-us/library/ms933120.aspx)版本(这里不是指所说的比如win10的linux子系统). 只有当`subsystem`在`3.51`及更高的版本, 字段的默认值才如前所述. 如果是在`3.10-3.50`版本之间, 则两个字段的`HEAP_CREATE_ALIGN_16 (0x10000)`都会被设置. 如果版本低于`3.10`, 那么这个程序文件就根本不会被运行. 

如果某操作将`Flags`和`ForgeFlags`字段的值分别设为`2`和`0`, 但是却未对`subsystem`版本进行检查, 那么就可以表明该动作是为了隐藏调试器而进行的. 

当调试器存在时, 在`Windows NT`, `Windows 2000`和32位`Windows XP`系统下, `Flags`字段会设置以下标志:

``` c
HEAP_GROWABLE (2)
HEAP_TAIL_CHECKING_ENABLED (0x20)
HEAP_FREE_CHECKING_ENABLED (0x40)
HEAP_SKIP_VALIDATION_CHECKS (0x10000000)
HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)
```

在64位`Windows XP`系统, `Windows Vista`及更新的系统版本, `Flags`字段则会设置以下标志(少了`HEAP_SKIP_VALIDATION_CHECKS (0x10000000)`):

``` c
HEAP_GROWABLE (2)
HEAP_TAIL_CHECKING_ENABLED (0x20)
HEAP_FREE_CHECKING_ENABLED (0x40)
HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)
```

而对于`ForgeFlags`字段, 正常情况则会设置以下标志:

``` c
HEAP_TAIL_CHECKING_ENABLED (0x20)
HEAP_FREE_CHECKING_ENABLED (0x40)
HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)
```

因为`NtGlobalFlag`标志的关系, `heap`也会设置一些标志位

* 如果在`NtGlobalFlag`字段中有设置`FLG_HEAP_ENABLE_TAIL_CHECK`标志, 那么在`heap`字段中就会设置`HEAP_TAIL_CHECKING_ENABLED`标志. 
* 如果在`NtGlobalFlag`字段中有设置`FLG_HEAP_ENABLE_FREE_CHECK`标志, 那么在`heap`字段中就会设置`FLG_HEAP_ENABLE_FREE_CHECK`标志.
* 如果在`NtGlobalFlag`字段中有设置`FLG_HEAP_VALIDATE_PARAMETERS`标志, 那么在`heap`字段中就会设置`HEAP_VALIDATE_PARAMETERS_ENABLED`标志(在`Windows NT`和`Windows 2000`中还会设置`HEAP_CREATE_ALIGN_16 (0x10000)`标志).

`heap flags`同样也如上节的`NtGlobalFlag`那样, 不过它受到注册表`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<filename>`位置的`PageHeapFlags"`键的控制. 

## 获取heap位置

有多种方法能获知`heap`的位置, 方法之一就是`kernel32`的`GetProcessHeap()`函数, 当然也可以用以下的32位汇编代码来检测32位环境(实际上就有一些壳避免使用该api函数, 直接查询PEB):

``` asm
mov eax, fs:[30h] ;Process Environment Block
mov eax, [eax+18h] ;get process heap base
```

或使用以下64位代码来检测64位环境

``` asm
push 60h
pop rsi
gs:lodsq ;Process Environment Block
mov eax, [rax+30h] ;get process heap base
```

或使用以下32位代码检测64位环境

``` asm
mov eax, fs:[30h] ;Process Environment Block
;64-bit Process Environment Block
;follows 32-bit Process Environment Block
mov eax, [eax+1030h] ;get process heap base
```

另外一种方法则是使用`kernel32`的`GetProcessHeaps()`函数, 其实它只是简单的转给了`ntdll`的`RtlGetProcessHeaps()`函数, 这个函数会返回属于当前进程的堆的数组, 而数组的第一个堆, 就跟`kernel32`的`GetProcessHeap()`函数所返回的是一样的.



这个过程可以用32位代码检测32位windows环境来实现:

``` asm
push 30h
pop esi
fs:lodsd ;Process Environment Block
;get process heaps list base
mov esi, [esi+eax+5ch]
lodsd
```

同上, 用64位代码检测64位windows环境的代码是:

``` asm
push 60h
pop rsi
gs:lodsq ;Process Environment Block
;get process heaps list base
mov esi, [rsi*2+rax+20h]
lodsd
```

或使用32位代码检测64位window环境:

``` asm
mov eax, fs:[30h] ;Process Environment Block
;64-bit Process Environment Block
;follows 32-bit Process Environment Block
mov esi, [eax+10f0h] ;get process heaps list base
lodsd
```

## 检测Flags字段

那么显然, 检测调试器我们就可以从检测那几个`Flags`和`ForgeFlags`的标志位入手. 

先看`Flags`字段的检测代码, 用32位代码检测32位windows环境, 且`subsystem`版本在`3.10-3.50`之间:

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

32位代码检测32位windows环境, 且`subsystem`为`3.51`及更高版本:

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

64位代码检测64位windows环境(64位进程不必受`subsystem`版本困扰):

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

用32位代码检测64位windows环境:

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

如果是直接通过`KUSER_SHARED_DATA`结构的`NtMajorVersion`字段(位于2G用户空间的`0x7ffe026c`偏移处)获取该值(在所有32位/64位版本的Windows都可以获取该值), 可以进一步混淆`kernel32`的`GetVersion()`函数调用操作.


## 检测ForgeFlags字段

当然另一个方法就是检测`ForgeFlags`字段, 以下是32位代码检测32位Windows环境, `subsystem`版本在`3.10-3.50`之间:

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

32位代码检测32位windows环境, 且`subsystem`为`3.51`及更高版本:

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

64位代码检测64位windows环境(64位进程不必受`subsystem`版本困扰):

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
用32位代码检测64位windows环境:

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

## 参考链接

* [The "Ultimate" Anti-Debugging Reference](http://anti-reversing.com/Downloads/Anti-Reversing/The_Ultimate_Anti-Reversing_Reference.pdf)