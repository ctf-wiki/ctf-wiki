# GS(Buffer Security Check)
## Introduction
正如Linux中存在栈溢出的防护机制 Canary 一样，windows 中也存在类似的机制。与 Canary 的思想一致，GS 也是在栈中插入一个值，当函数返回之时检测 GS 的值是否经过了改变，以此来判断 stack/buffer overflow 是否发生。

## GS 原理
使用Visual Studio编译时，、GS默认为打开的状态，可以在打开项目的”属性页“中修改。

### 在/ GS编译器选项保护下列项目：
    函数调用的返回地址。
    函数的异常处理程序的地址。
    脆弱的功能参数。

## GS 实现原理
开启 GS 保护的 stack 结构大概如下：
```
        Low
        Address |  Local Variable |
                +-----------------+
      rbp-8 =>  |    GS_Cookie    |
                +-----------------+
        rbp =>  |     old ebp     |
                +-----------------+
                | return address  |
                +-----------------+
                |      args       |
                +-----------------+
        High    |                 | 
        Address
```
当程序开启了 GS 保护时，在函数序言部分会将 ___security_cookie 与 ebp 进行异或运算，然后存放在 ebp-0x1C 的位置
```asm
mov     eax, ___security_cookie
xor     eax, ebp
mov     [ebp - 0x1C], eax
```
在函数返回之前，会将该值取出，和 ebp 进行异或运算后，与 ___security_cookie 比较是否相等。
```asm
mov     ecx, [ebp+var_1C]
xor     ecx, ebp
call    j_@__security_check_cookie@4 ; __security_check_cookie(x)
------------------------------------------------------------------
; __fastcall __security_check_cookie(x)
@__security_check_cookie@4 proc near
        cmp     ecx, ___security_cookie
        bnd jnz short loc_4086E5
        bnd retn
loc_4086E5:
        bnd jmp sub_4010B9
```
如果 GS_Cookie 已经被非法修改，此时程序流程会走到抛出异常并退出的流程。
```asm
push    offset ExceptionInfo ; ExceptionInfo
call    sub_401A87
```
其中 ___security_cookie 是存放在 .data 段上的数据，
```
.data:0047C004 ___security_cookie dd 0BB40E64Eh
```
其每次运行都会重新赋值为新的值
```C
void sub_409366()
{
  int v0; // ecx
  unsigned int v1; // eax

  v0 = __security_cookie;
  if ( __security_cookie == 0xBB40E64E || !(__security_cookie & 0xFFFF0000) )
  {
    v1 = sub_409306();
    v0 = v1;
    if ( v1 == 0xBB40E64E )
    {
      v0 = 0xBB40E64F;
    }
    else if ( !(v1 & 0xFFFF0000) )
    {
      v0 = ((v1 | 0x4711) << 16) | v1;
    }
    __security_cookie = v0;
  }
  dword_47C000 = ~v0;
}

unsigned int sub_409306()
{
  LARGE_INTEGER PerformanceCount; // [esp+0h] [ebp-14h]
  struct _FILETIME SystemTimeAsFileTime; // [esp+8h] [ebp-Ch]
  DWORD v3; // [esp+10h] [ebp-4h]

  SystemTimeAsFileTime.dwLowDateTime = 0;
  SystemTimeAsFileTime.dwHighDateTime = 0;
  GetSystemTimeAsFileTime(&SystemTimeAsFileTime);
  v3 = SystemTimeAsFileTime.dwLowDateTime ^ SystemTimeAsFileTime.dwHighDateTime;
  v3 ^= GetCurrentThreadId();
  v3 ^= GetCurrentProcessId();
  QueryPerformanceCounter(&PerformanceCount);
  return (unsigned int)&v3 ^ v3 ^ PerformanceCount.LowPart ^ PerformanceCount.HighPart;
}
```
但是由于其存储在程序段上，所以比起 Canary 更容易读取利用。
