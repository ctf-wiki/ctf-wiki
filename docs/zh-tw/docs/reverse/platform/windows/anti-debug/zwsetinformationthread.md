# ZwSetInformationThread

## 關於ZwSetInformationThread

ZwSetInformationThread 等同於 NtSetInformationThread，通過爲線程設置 ThreadHideFromDebugger，可以禁止線程產生調試事件，代碼如下  
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

關鍵代碼爲`ZwSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, 0, 0);`，如果處於調試狀態，執行完該行代碼，程序就會退出  

## 如何繞過

注意到該處 ZwSetInformationThread 函數的第 2 個參數爲 ThreadHideFromDebugger，其值爲 0x11。調試執行到該函數時，若發現第 2 個參數值爲 0x11，跳過或者將 0x11 修改爲其他值即可  