## 关于CheckRemoteDebuggerPresent

`kernel32`的`CheckRemoteDebuggerPresent()`函数用于检测指定进程是否正在被调试. `Remote`在单词里是指同一个机器中的不同进程. 

``` c
BOOL WINAPI CheckRemoteDebuggerPresent(
  _In_    HANDLE hProcess,
  _Inout_ PBOOL  pbDebuggerPresent
);
```

如果调试器存在(通常是检测自己是否正在被调试), 该函数会将`pbDebuggerPresent`指向的值设为`0xffffffff`. 

## 检测代码

可以用以下32位代码检测32位环境

``` asm
push eax
push esp
push -1 ;GetCurrentProcess()
call CheckRemoteDebuggerPresent
pop eax
test eax, eax
jne being_debugged
```

或64位代码检测64位环境

``` asm
enter 20h, 0
mov edx, ebp
or rcx, -1 ;GetCurrentProcess()
call CheckRemoteDebuggerPresent
leave
test ebp, ebp
jne being_debugged
```

## 如何绕过

比如有如下的代码

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

我们可以直接修改`isDebuggerPresent`的值或修改跳转条件来绕过(注意不是`CheckRemoteDebuggerPresent`的izhi, 它的返回值是用于表示函数是否正确执行). 

但如果要针对`CheckRemoteDebuggerPresent`这个api函数进行修改的话. 首先要知道`CheckRemoteDebuggerPresent`内部其实是通过调用`NtQueryInformationProcess`来完成功能的. 而我们就需要对`NtQueryInformationProcess`的返回值进行修改. 我们将在[ NtQueryInformationProcess 篇](/reverse/anti-debug/ntqueryinformationprocess/index.html)进行介绍.
