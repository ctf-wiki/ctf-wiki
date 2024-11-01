# NtQueryInformationProcess


``` c++
NTSTATUS WINAPI NtQueryInformationProcess(
  _In_      HANDLE           ProcessHandle,
  _In_      PROCESSINFOCLASS ProcessInformationClass,
  _Out_     PVOID            ProcessInformation,
  _In_      ULONG            ProcessInformationLength,
  _Out_opt_ PULONG           ReturnLength
);
```

## ProcessDebugPort

未公開的`ntdll`的`NtQueryInformationProcess()`函數接受一個信息類的參數用於查詢. `ProcessDebugPort(7)`是其中的一個信息類. `kernel32`的`CheckRemoteDebuggerPresent()`函數內部通過調用`NtQueryInformationProcess()`來檢測調試, 而`NtQueryInformationProcess`內部則是查詢`EPROCESS`結構體的`DebugPort`字段, 當進程正在被調試時, 返回值爲`0xffffffff`. 

可以用以下32位代碼在32位環境進行檢測:

``` asm
push eax
mov eax, esp
push 0
push 4 ;ProcessInformationLength
push eax
push 7 ;ProcessDebugPort
push -1 ;GetCurrentProcess()
call NtQueryInformationProcess
pop eax
inc eax
je being_debugged
```

用以下64位代碼在64位環境進行檢測:

``` asm
xor ebp, ebp
enter 20h, 0
push 8 ;ProcessInformationLength
pop r9
push rbp
pop r8
push 7 ;ProcessDebugPort
pop rdx
or rcx, -1 ;GetCurrentProcess()
call NtQueryInformationProcess
leave
test ebp, ebp
jne being_debugged
```

由於信息傳自內核, 所以在用戶模式下的代碼沒有輕鬆的方法阻止該函數檢測調試器. 

## ProcessDebugObjectHandle

Windows XP引入了`debug對象`, 當一個調試會話啓動, 會同時創建一個`debug`對象以及與之關聯的句柄. 我們可以使用`ProcessDebugObjectHandle (0x1e)`類來查詢這個句柄的值

可以用以下32位代碼在32位環境進行檢測:

``` asm
push 0
mov eax, esp
push 0
push 4 ;ProcessInformationLength
push eax
push 1eh ;ProcessDebugObjectHandle
push -1 ;GetCurrentProcess()
call NtQueryInformationProcess
pop eax
test eax, eax
jne being_debugged
```

用以下64位代碼在64位環境進行檢測:

``` asm
xor ebp, ebp
enter 20h, 0
push 8 ;ProcessInformationLength
pop r9
push rbp
pop r8
push 1eh ;ProcessDebugObjectHandle
pop rdx
or rcx, -1 ;GetCurrentProcess()
call NtQueryInformationProcess
leave
test ebp, ebp
jne being_debugged
```

## ProcessDebugFlags

`ProcessDebugFlags (0x1f)`類返回`EPROCESS`結構體的`NoDebugInherit`的相反數. 意思是, 當調試器存在時, 返回值爲`0`, 不存在時則返回`1`. 

可以用以下32位代碼在32位環境進行檢測:

``` asm
push eax
mov eax, esp
push 0
push 4 ;ProcessInformationLength
push eax
push 1fh ;ProcessDebugFlags
push -1 ;GetCurrentProcess()
call NtQueryInformationProcess
pop eax
test eax, eax
je being_debugged
```

用以下64位代碼在64位環境進行檢測:

``` asm
xor ebp, ebp
enter 20h, 0
push 4 ;ProcessInformationLength
pop r9
push rbp
pop r8
push 1fh ;ProcessDebugFlags
pop rdx
or rcx, -1 ;GetCurrentProcess()
call NtQueryInformationProcess
leave
test ebp, ebp
je being_debugged
```