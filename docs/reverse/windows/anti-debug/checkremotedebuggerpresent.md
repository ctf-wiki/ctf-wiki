[EN](./checkremotedebuggerpresent.md) | [ZH](./checkremotedebuggerpresent-zh.md)
## About CheckRemoteDebuggerPresent


The `CheckRemoteDebuggerPresent()` function of `kernel32` is used to detect if the specified process is being debugged. `Remote` refers to a different process in the same machine.


``` c

BOOL WINAPI CheckRemoteDebuggerPresent(

  _In_    HANDLE hProcess,

  _Inout_ PBOOL  pbDebuggerPresent

);

```



If the debugger exists (usually to detect if it is being debugged), the function will set the value pointed to by `pbDebuggerPresent` to `0xffffffff`.


## Detection code


The 32-bit environment can be detected with the following 32-bit code


`` `asm
push eax

push esp

push -1 ;GetCurrentProcess()

call CheckRemoteDebuggerPresent

pop eax

test eax, eax

jne being_debugged

```



Or 64-bit code to detect 64-bit environments


`` `asm
enter 20h, 0

mov edx, ebp

or rcx, -1 ;GetCurrentProcess()

call CheckRemoteDebuggerPresent

leave

test ebp, ebp

jne being_debugged

```



## How to bypass


For example, there is the following code


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



We can directly modify the value of `isDebuggerPresent` or modify the jump condition to bypass (note that izhi is not `CheckRemoteDebuggerPresent`, its return value is used to indicate whether the function is executed correctly).


But if you want to modify the api function of `CheckRemoteDebuggerPresent`. First of all, you need to know that `CheckRemoteDebuggerPresent` internally does the function by calling `NtQueryInformationProcess`. And we need to modify the return value of `NtQueryInformationProcess`. We will be [NtQueryInformationProcess] (./ntqueryinformationprocess/index.html) for introduction.