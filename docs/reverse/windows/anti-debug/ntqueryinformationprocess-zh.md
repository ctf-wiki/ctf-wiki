[EN](./ntqueryinformationprocess.md) | [ZH](./ntqueryinformationprocess-zh.md)
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

未公开的`ntdll`的`NtQueryInformationProcess()`函数接受一个信息类的参数用于查询. `ProcessDebugPort(7)`是其中的一个信息类. `kernel32`的`CheckRemoteDebuggerPresent()`函数内部通过调用`NtQueryInformationProcess()`来检测调试, 而`NtQueryInformationProcess`内部则是查询`EPROCESS`结构体的`DebugPort`字段, 当进程正在被调试时, 返回值为`0xffffffff`. 

可以用以下32位代码在32位环境进行检测:

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

用以下64位代码在64位环境进行检测:

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

由于信息传自内核, 所以在用户模式下的代码没有轻松的方法阻止该函数检测调试器. 

## ProcessDebugObjectHandle

Windows XP引入了`debug对象`, 当一个调试会话启动, 会同时创建一个`debug`对象以及与之关联的句柄. 我们可以使用`ProcessDebugObjectHandle (0x1e)`类来查询这个句柄的值

可以用以下32位代码在32位环境进行检测:

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

用以下64位代码在64位环境进行检测:

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

`ProcessDebugFlags (0x1f)`类返回`EPROCESS`结构体的`NoDebugInherit`的相反数. 意思是, 当调试器存在时, 返回值为`0`, 不存在时则返回`1`. 

可以用以下32位代码在32位环境进行检测:

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

用以下64位代码在64位环境进行检测:

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