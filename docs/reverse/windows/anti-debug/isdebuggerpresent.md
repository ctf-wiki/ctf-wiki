## 关于IsDebuggerPresent

当调试器存在时, `kernel32`的`IsDebuggerPresent()`函数返回的是一个`非0值`. 

``` c++
BOOL WINAPI IsDebuggerPresent(void);
```

## 检测代码

它的检测方法非常简单, 比如用以下代码(32位还是64位都是相同的这份代码)在32位/64位环境中检测:

``` asm
call IsDebuggerPresent
test al, al
jne being_debugged
```

实际上, 这个函数只是单纯地返回了`BeingDebugged`标志的值. 检查`BeingDebugged`标志位的方法也可以用以下32代码位代码检查32位环境来实现:

``` asm
mov eax, fs:[30h] ;Process Environment Block
cmp b [eax+2], 0 ;check BeingDebugged
jne being_debugged
```

或使用64位代码检测64位环境

``` asm
push 60h
pop rsi
gs:lodsq ;Process Environment Block
cmp b [rax+2], 0 ;check BeingDebugged
jne being_debugged
```

或使用32位代码检测64位环境

``` asm
mov eax, fs:[30h] ;Process Environment Block
;64-bit Process Environment Block
;follows 32-bit Process Environment Block
cmp b [eax+1002h], 0 ;check BeingDebugged
jne being_debugged
```

## 如何绕过

想要克服这些检测, 只需要将`BeingDebugged`标志设为`0`即可(或改变一下返回值).