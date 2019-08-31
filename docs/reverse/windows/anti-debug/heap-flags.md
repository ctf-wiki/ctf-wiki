[EN](./heap-flags.md) | [ZH](./heap-flags-zh.md)
## About Heap flags


`Heap flags` contains two flags initialized with `NtGlobalFlag`: `Flags` and `ForceFlags`. The values of these two fields will not only be affected by the debugger, but also by the windows version, the location of the fields. Also depends on the version of windows.


* Flags field:
* In 32-bit Windows NT, Windows 2000 and Windows XP, `Flags` is at the `0x0C` offset of the heap. On 32-bit Windows Vista and newer systems, it is located at the offset of `0x40`.
* In 64-bit Windows XP, the `Flags` field is at the `0x14` offset of the heap, and on 64-bit Windows Vista and newer systems, it is at the `0x70` offset.
* ForceFlags field:
* In 32-bit Windows NT, Windows 2000 and Windows XP, `ForceFlags` is located at the `0x10` offset of the heap. On 32-bit Windows Vista and newer systems, it is located at the offset of `0x44`.
* In 64-bit Windows XP, the `ForceFlags` field is at the `0x18` offset of the heap, and on 64-bit Windows Vista and newer systems, it is at the `0x74` offset.


In all versions of Windows, the value of the `Flags` field is normally set to `HEAP_GROWABLE(2)`, and the `ForceFlags` field is normally set to `0`. However for a 32-bit process (64-bit programs are not There will be troubles. Both of these default values depend on the [`subsystem`] of its host process (https://msdn.microsoft.com/en-us/library/ms933120.aspx) Version (this does not refer to the Linux subsystem such as win10). Only when `subsystem` is in `3.51` and higher, the default value of the field is as described above. If it is in `3.10-3.50` Between, the two fields of `HEAP_CREATE_ALIGN_16 (0x10000)` will be set. If the version is lower than `3.10`, then this program file will not be run at all.


If an operation sets the values of the `Flags` and `ForgeFlags` fields to `2` and `0`, respectively, but does not check the `subsystem` version, then it can be indicated that the action is to hide the debugger. .


When the debugger is present, under the `Windows NT`, `Windows 2000` and 32-bit `Windows XP` systems, the `Flags` field will set the following flags:


``` c

HEAP_GROWABLE (2)

HEAP_TAIL_CHECKING_ENABLED (0x20)

HEAP_FREE_CHECKING_ENABLED (0x40)

HEAP_SKIP_VALIDATION_CHECKS (0x10000000)

HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)

```



On the 64-bit `Windows XP` system, `Windows Vista` and newer system versions, the `Flags` field will set the following flags (less `HEAP_SKIP_VALIDATION_CHECKS (0x10000000)`):


``` c

HEAP_GROWABLE (2)

HEAP_TAIL_CHECKING_ENABLED (0x20)

HEAP_FREE_CHECKING_ENABLED (0x40)

HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)

```



For the `ForgeFlags` field, the following flags are normally set:


``` c

HEAP_TAIL_CHECKING_ENABLED (0x20)

HEAP_FREE_CHECKING_ENABLED (0x40)

HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)

```



Because of the relationship of the `NtGlobalFlag` flag, `heap` will also set some flag bits.


* If the `FLG_HEAP_ENABLE_TAIL_CHECK` flag is set in the `NtGlobalFlag` field, the `HEAP_TAIL_CHECKING_ENABLED` flag will be set in the `heap` field.
* If the `FLG_HEAP_ENABLE_FREE_CHECK` flag is set in the `NtGlobalFlag` field, the `FLG_HEAP_ENABLE_FREE_CHECK` flag will be set in the `heap` field.
* If the `FLG_HEAP_VALIDATE_PARAMETERS` flag is set in the `NtGlobalFlag` field, the `HEAP_VALIDATE_PARAMETERS_ENABLED` flag will be set in the `heap` field (the `HEAP_CREATE_ALIGN_16 (0x10000) will also be set in `Windows NT` and `Windows 2000`. Sign).


`heap flags` is also the same as `NtGlobalFlag` in the previous section, but it is subject to the registry `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ <filename> `Location&#39;s `PageHeapFlags&quot;` key control.


## Get the heap location


There are several ways to know the location of the `heap`. One of the methods is the `GetProcessHeap()` function of `kernel32`. Of course, you can also use the following 32-bit assembly code to detect the 32-bit environment (there are actually some shells to avoid). Use this api function to directly query PEB):


`` `asm
mov eax, fs:[30h] ;Process Environment Block

mov eax, [eax+18h] ;get process heap base

```



Or use the following 64-bit code to detect a 64-bit environment


`` `asm
push 60h

pop rsi
gs:lodsq ;Process Environment Block

mov eax, [rax+30h] ;get process heap base

```



Or use the following 32-bit code to detect a 64-bit environment


`` `asm
mov eax, fs:[30h] ;Process Environment Block

;64-bit Process Environment Block

;follows 32-bit Process Environment Block

mov eax, [eax+1030h] ;get process heap base

```



The other method is to use the `GetProcessHeaps()` function of `kernel32`. In fact, it is simply transferred to the `ntdll` `RtlGetProcessHeaps()` function, which returns an array of the heap belonging to the current process. The first heap of the array is the same as the `GetProcessHeap()` function of `kernel32`.






This process can be implemented with 32-bit code detection for 32-bit windows environments:


`` `asm
push 30h

pop how
fs:lodsd ;Process Environment Block

;get process heaps list base

mov how, [how + eax + 5ch]
lodsd

```



As above, the code for detecting 64-bit windows environment with 64-bit code is:


`` `asm
push 60h

pop rsi
gs:lodsq ;Process Environment Block

;get process heaps list base

mov esi, [rsi * 2 + rax + 20h]
lodsd

```



Or use a 32-bit code to detect a 64-bit window environment:


`` `asm
mov eax, fs:[30h] ;Process Environment Block

;64-bit Process Environment Block

;follows 32-bit Process Environment Block

mov esi, [eax+10f0h] ;get process heaps list base

lodsd

```



## Detect Flags field


So obviously, we can detect the debuggers from the flags of `Flags` and `ForgeFlags`.


First look at the detection code of the `Flags` field, use a 32-bit code to detect the 32-bit windows environment, and the `subsystem` version is between `3.10-3.50`:


`` `asm
call GetVersion

cmp al, 6
cc
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



The 32-bit code detects the 32-bit windows environment, and the `subsystem` is `3.51` and higher:


`` `asm
call GetVersion

cmp al, 6
cc
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



64-bit code detects 64-bit windows environments (64-bit processes don&#39;t have to be bothered by the `subsystem` version):


`` `asm
push 60h

pop rsi
gs:lodsq ;Process Environment Block

mov ebx, [rax+30h] ;get process heap base

call GetVersion

cmp al, 6
as rax, rax
and al, 0a4h

;HEAP_GROWABLE

;+ HEAP_TAIL_CHECKING_ENABLED

;+ HEAP_FREE_CHECKING_ENABLED

;+ HEAP_VALIDATE_PARAMETERS_ENABLED

cmp d [rbx+rax+70h], 40000062h ;Flags

je being_debugged

```



Detect 64-bit windows environment with 32-bit code:


`` `asm
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



If you get this value directly through the `NtMajorVersion` field of the `KUSER_SHARED_DATA` structure (located at the offset of `0x7ffe026c` in 2G user space) (this value can be obtained on all 32-bit/64-bit versions of Windows), you can further confuse The `GetVersion()` function call operation of `kernel32`.




## Detecting ForgeFlags field


Of course, another method is to detect the `ForgeFlags` field. The following is a 32-bit code detection for a 32-bit Windows environment. The `subsystem` version is between `3.10-3.50`:


`` `asm
call GetVersion

cmp al, 6
cc
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



The 32-bit code detects the 32-bit windows environment, and the `subsystem` is `3.51` and higher:


`` `asm
call GetVersion

cmp al, 6
cc
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



64-bit code detects 64-bit windows environments (64-bit processes don&#39;t have to be bothered by the `subsystem` version):


`` `asm
push 60h

pop rsi
gs:lodsq ;Process Environment Block

mov ebx, [rax+30h] ;get process heap base
call GetVersion

cmp al, 6
as rax, rax
and al, 0a4h

;ForceFlags

;HEAP_TAIL_CHECKING_ENABLED

;+ HEAP_FREE_CHECKING_ENABLED

;+ HEAP_VALIDATE_PARAMETERS_ENABLED

cmp d [rbx+rax+74h], 40000060h

je being_debugged

```

Detect 64-bit windows environment with 32-bit code:


`` `asm
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



## Reference link


* [The "Ultimate" Anti-Debugging Reference](http://anti-reversing.com/Downloads/Anti-Reversing/The_Ultimate_Anti-Reversing_Reference.pdf)