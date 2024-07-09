# CheckRemoteDebuggerPresent

## 關於CheckRemoteDebuggerPresent

`kernel32`的`CheckRemoteDebuggerPresent()`函數用於檢測指定進程是否正在被調試. `Remote`在單詞裏是指同一個機器中的不同進程.

``` c
BOOL WINAPI CheckRemoteDebuggerPresent(
  _In_    HANDLE hProcess,
  _Inout_ PBOOL  pbDebuggerPresent
);
```

如果調試器存在(通常是檢測自己是否正在被調試), 該函數會將`pbDebuggerPresent`指向的值設爲`0xffffffff`.

## 檢測代碼

可以用以下32位代碼檢測32位環境

``` asm
push eax
push esp
push -1 ;GetCurrentProcess()
call CheckRemoteDebuggerPresent
pop eax
test eax, eax
jne being_debugged
```

或64位代碼檢測64位環境

``` asm
enter 20h, 0
mov edx, ebp
or rcx, -1 ;GetCurrentProcess()
call CheckRemoteDebuggerPresent
leave
test ebp, ebp
jne being_debugged
```

## 如何繞過

比如有如下的代碼

``` c++
int main(int argc, char *argv[])
{
    BOOL isDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent ))
    {
        if (isDebuggerPresent )
        {
            std::cout << "Stop debugging program!" << std::endl;
            exit(-1);
        }
    }
    return 0;
}
```

我們可以直接修改`isDebuggerPresent`的值或修改跳轉條件來繞過(注意不是`CheckRemoteDebuggerPresent`的izhi, 它的返回值是用於表示函數是否正確執行).

但如果要針對`CheckRemoteDebuggerPresent`這個api函數進行修改的話. 首先要知道`CheckRemoteDebuggerPresent`內部其實是通過調用`NtQueryInformationProcess`來完成功能的. 而我們就需要對`NtQueryInformationProcess`的返回值進行修改. 我們將在[ NtQueryInformationProcess 篇](./ntqueryinformationprocess.md)進行介紹.
