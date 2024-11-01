# IsDebuggerPresent

## 關於IsDebuggerPresent

當調試器存在時, `kernel32`的`IsDebuggerPresent()`函數返回的是一個`非0值`. 

``` c++
BOOL WINAPI IsDebuggerPresent(void);
```

## 檢測代碼

它的檢測方法非常簡單, 比如用以下代碼(32位還是64位都是相同的這份代碼)在32位/64位環境中檢測:

``` asm
call IsDebuggerPresent
test al, al
jne being_debugged
```

實際上, 這個函數只是單純地返回了`BeingDebugged`標誌的值. 檢查`BeingDebugged`標誌位的方法也可以用以下32代碼位代碼檢查32位環境來實現:

``` asm
mov eax, fs:[30h] ;Process Environment Block
cmp b [eax+2], 0 ;check BeingDebugged
jne being_debugged
```

或使用64位代碼檢測64位環境

``` asm
push 60h
pop rsi
gs:lodsq ;Process Environment Block
cmp b [rax+2], 0 ;check BeingDebugged
jne being_debugged
```

或使用32位代碼檢測64位環境

``` asm
mov eax, fs:[30h] ;Process Environment Block
;64-bit Process Environment Block
;follows 32-bit Process Environment Block
cmp b [eax+1002h], 0 ;check BeingDebugged
jne being_debugged
```

## 如何繞過

想要克服這些檢測, 只需要將`BeingDebugged`標誌設爲`0`即可(或改變一下返回值).