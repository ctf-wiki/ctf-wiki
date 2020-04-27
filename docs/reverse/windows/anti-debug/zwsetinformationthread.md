[EN](./zwsetinformationthread.md) | [ZH](./zwsetinformationthread-zh.md)
## About ZwSetInformationThread

ZwSetInformationThread is same as NtSetInformationThread. By setting the ThreadHideFromDebugger for a thread, you can disable the thread from generating debugging events. The code is as follows  
```c
#include <Windows.h>
#include <stdio.h>

typedef DWORD(WINAPI* ZW_SET_INFORMATION_THREAD) (HANDLE, DWORD, PVOID, ULONG);
#define ThreadHideFromDebugger 0x11
VOID DisableDebugEvent(VOID)
{
    HINSTANCE hModule;
    ZW_SET_INFORMATION_THREAD ZwSetInformationThread;
    hModule = GetModuleHandleA("Ntdll");
    ZwSetInformationThread = (ZW_SET_INFORMATION_THREAD)GetProcAddress(hModule, "ZwSetInformationThread");
    ZwSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, 0, 0);
}

int main()
{
    printf("Begin\n");
    DisableDebugEvent();
    printf("End\n");
    return 0;
}
```

The key code is `ZwSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, 0, 0);`. If it is in debugging state, the program will exit after executing this line of code.  

## How to bypass

Note that the second parameter of the ZwSetInformationThread function is ThreadHideFromDebugger, which value is 0x11. When debugging the function and the second parameter value is 0x11, skip the function or change 0x11 to other value.  