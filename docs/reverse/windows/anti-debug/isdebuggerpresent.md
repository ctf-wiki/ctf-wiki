[EN](./isdebuggerpresent.md) | [ZH](./isdebuggerpresent-zh.md)
## About IsDebuggerPresent


When the debugger exists, the `IsDebuggerPresent()` function of `kernel32` returns a `non-zero value`.


``` c++

BOOL WINAPI IsDebuggerPresent(void);

```



## Detection code


Its detection method is very simple, such as using the following code (32 or 64 bits are the same code) to detect in a 32-bit/64-bit environment:


`` `asm
call IsDebuggerPresent

test al, al
jne being_debugged

```



In fact, this function simply returns the value of the `BeingDebugged` flag. The method of checking the `BeingDebugged` flag can also be implemented by examining the 32-bit environment with the following 32-bit code:


`` `asm
mov eax, fs:[30h] ;Process Environment Block

cmp b [eax+2], 0 ;check BeingDebugged

jne being_debugged

```



Or use 64-bit code to detect 64-bit environments


`` `asm
push 60h

pop rsi
gs:lodsq ;Process Environment Block

cmp b [rax+2], 0 ;check BeingDebugged

jne being_debugged

```



Or use a 32-bit code to detect a 64-bit environment


`` `asm
mov eax, fs:[30h] ;Process Environment Block

;64-bit Process Environment Block

;follows 32-bit Process Environment Block

cmp b [eax+1002h], 0 ;check BeingDebugged

jne being_debugged

```



## How to bypass


To overcome these tests, just set the `BeingDebugged` flag to `0` (or change the return value).