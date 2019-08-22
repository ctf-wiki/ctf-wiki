[EN](./ntqueryinformationprocess.md) | [ZH](./ntqueryinformationprocess-zh.md)
``` c++

NTSTATUS WINAPI NtQueryInformationProcess(

  _In_      HANDLE           ProcessHandle,

  _In_      PROCESSINFOCLASS ProcessInformationClass,

  _Out_     PVOID            ProcessInformation,

  _In_      ULONG            ProcessInformationLength,

_Out_opt_ MEMBER OF ReturnLength
);

```



## ProcessDebugPort



The undocumented `ntdll` `NtQueryInformationProcess()` function accepts an information class parameter for query. `ProcessDebugPort(7)` is one of the information classes. `kernel32``CheckRemoteDebuggerPresent()` function is called internally. NtQueryInformationProcess()` is used to detect debugging, while `NtQueryInformationProcess` internally queries the `DebugPort` field of the `EPROCESS` structure. When the process is being debugged, the return value is `0xffffffff`.


It can be detected in a 32-bit environment with the following 32-bit code:


`` `asm
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



Detect in a 64-bit environment with the following 64-bit code:


`` `asm
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



Since the information is passed from the kernel, there is no easy way to prevent the function from detecting the debugger in user mode.


## ProcessDebugObjectHandle



Windows XP introduces the `debug object`. When a debug session starts, it creates a `debug` object and a handle associated with it. We can use the `ProcessDebugObjectHandle (0x1e)` class to query the value of this handle.


It can be detected in a 32-bit environment with the following 32-bit code:


`` `asm
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



Detect in a 64-bit environment with the following 64-bit code:


`` `asm
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



The `ProcessDebugFlags (0x1f)` class returns the opposite of `NoDebugInherit` of the `EPROCESS` structure. This means that when the debugger exists, the return value is `0`, and when it does not exist, it returns `1`.


It can be detected in a 32-bit environment with the following 32-bit code:


`` `asm
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



Detect in a 64-bit environment with the following 64-bit code:


`` `asm
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