# 虚拟机分析

有关虚拟机分析部分, 我们以一道简单的crackme来进行讲解. 

对应的`crackme`可以点击此处下载: [FuelVM.exe](https://github.com/ctf-wiki/ctf-challenges/blob/master/reverse/vm/fuelvm/FuelVM.exe)

对应的`keygenme`可以点击此处下载: [fuelvm_keygen.py](https://github.com/ctf-wiki/ctf-challenges/blob/master/reverse/vm/fuelvm/fuelvm_keygen.py)

对应的`IDA数据库`可以点击此处下载: [FuelVM.idb](https://github.com/ctf-wiki/ctf-challenges/blob/master/reverse/vm/fuelvm/FuelVM.idb)

本题作者设计了一个具有多种指令的简单虚拟机. 我们使用IDA来进行分析. 并为了方便讲解, 我对反汇编出的一些变量重新进行了命名. 

## 运行程序

我们运行程序 FuelVM.exe. 界面如下所示

![start.png](./figure/start.png)

在这个界面中, 我们看到右两个输入框, 一个用于输入用户名Name, 另一个则用于输入密钥Key. 还有两个按钮, Go用于提交输入, 而Exit则用于退出程序.

## 获取用户输入

那么我们就可以从这里入手. 程序想获取用户输入, 需要调用的一个API是`GetDlgItemTextA()`

``` c
UINT GetDlgItemTextA(
  HWND  hDlg,
  int   nIDDlgItem,
  LPSTR lpString,
  int   cchMax
);
```

获取的输入字符串会保存在`lpString`里. 那么我们就可以打开IDA查找有交叉引用`GetDlgItemTextA()`的地方.

``` asm
.text:00401142                 push    0Ch             ; cchMax
.text:00401144                 push    offset inputName ; lpString
.text:00401149                 push    3F8h            ; nIDDlgItem
.text:0040114E                 push    [ebp+hWnd]      ; hDlg
.text:00401151                 call    GetDlgItemTextA
.text:00401156                 push    0Ch             ; cchMax
.text:00401158                 push    offset inputKey ; lpString
.text:0040115D                 push    3F9h            ; nIDDlgItem
.text:00401162                 push    [ebp+hWnd]      ; hDlg
.text:00401165                 call    GetDlgItemTextA
.text:0040116A                 mov     var_a, 0
.text:00401171                 call    process_input
.text:00401176                 jmp     short locExit
```

如上, IDA只有这里调用过`GetDlgItemTextA`并且调用了两次分别获取`inputName`和`inputKey`. 随后初始化了一个变量为0, 因为还不明白这个变量的作用, 因此先重命名为`var_a`. 之后进行了一次函数调用并jmp跳转. 因为jmp跳转位置的代码是一些退出程序的代码, 因此我们可以断定上面的这个call, 是在调用处理用户输入的函数. 因此将jmp的位置重命名为`locExit`, 函数则重命名为`process_input`. 

## 处理用户输入

我们进入`process_input`函数, 该函数仅仅对输入字符串进行了很简单的处理. 

```c
  result = strlength((int)inputName);
  if ( v1 >= 7 )                                // v1 = length of inputName
  {
    *(_DWORD *)&lenOfName = v1;
    result = strlength((int)inputKey);
    if ( v2 >= 7 )                              // v2 = length of inputKey
    {
      i = 0;
      do
      {
        inputName[i] ^= i;
        ++i;
      }
      while ( i <= *(_DWORD *)&lenOfName );
      unk_4031CE = i;
      dword_4031C8 = dword_4035FF;
      initVM();
      initVM();
      __debugbreak();
      JUMPOUT(*(_DWORD *)&word_4012CE);
    }
  }
  return result;
```

首先是这个`strlength()`函数. 函数使用`cld; repne scasb; not ecx; dec ecx`来计算字符串长度并将结果保存在`ecx`里. 是汇编基础知识就不多介绍. 所以我们将该函数重命名为`strlength`

```asm
.text:004011C2 arg_0           = dword ptr  8
.text:004011C2
.text:004011C2                 push    ebp
.text:004011C3                 mov     ebp, esp
.text:004011C5                 mov     edi, [ebp+arg_0]
.text:004011C8                 sub     ecx, ecx
.text:004011CA                 sub     al, al
.text:004011CC                 not     ecx
.text:004011CE                 cld
.text:004011CF                 repne scasb
.text:004011D1                 not     ecx
.text:004011D3                 dec     ecx
.text:004011D4                 leave
.text:004011D5                 retn    4
.text:004011D5 strlength       endp
```

而在IDA生成的伪C代码处有`v1`和`v2`, 我对其进行了注解, 可以看汇编, 里面是使用`ecx`与`7`进行比较, 而`ecx`是字符串的长度, 于是我们可以知道, 这里对输入的要求是: *inputName 和 inputKey 的长度均不少于 7*

当`inputName`和`inputKey`长度均不少于7时, 那么就可以对输入进行简单的变换. 以下是一个循环

```c
      i = 0;
      do
      {
        inputName[i] ^= i;
        ++i;
      }
      while ( i <= *(_DWORD *)&lenOfName );
```

对应的python代码即

``` python
def obfuscate(username):
    s = ""
    for i in range(len(username)):
        s += chr(ord(username[i]) ^ i)
    return s
```

函数之后对一些变量进行了赋值(这些并不重要, 就忽略不讲了.) 

## 注册SEH

```asm
.text:004012B5                 push    offset seh_handler
.text:004012BA                 push    large dword ptr fs:0
.text:004012C1                 mov     large fs:0, esp
.text:004012C8                 call    initVM
.text:004012CD                 int     3               ; Trap to Debugger
```

`initVM`完成的是一些虚拟机启动前的初始化工作(其实就是对一些寄存器和相关的部分赋初值), 我们之后来讨论. 这里我们关注的是SEH部分. 这里注册了一个SEH句柄, 异常处理函数我重命名为`seh_handler`, 并之后使用`int 3`手动触发异常. 而在`seh_handler`位置, IDA并未正确识别出对应的代码

``` 
.text:004012D7 seh_handler     db 64h                  ; DATA XREF: process_input+7Do
.text:004012D8                 dd 58Fh, 0C4830000h, 13066804h, 0FF640040h, 35h, 25896400h
.text:004012D8                 dd 0
.text:004012F4                 dd 1B8h, 0F7C93300h, 0F7C033F1h, 0FFC483E1h, 8F64FDEBh
.text:004012F4                 dd 5, 4C48300h, 40133068h, 35FF6400h, 0
.text:0040131C                 dd 258964h, 33000000h, 33198BC9h, 83E1F7C0h, 0FDEBFFC4h
.text:0040131C                 dd 58F64h, 83000000h, 5E6804C4h, 64004013h, 35FFh, 89640000h
.text:0040131C                 dd 25h, 0C033CC00h, 0C483E1F7h, 83FDEBFFh, 4035FF05h, 0D8B0200h
.text:0040131C                 dd 4035FFh, 3000B1FFh, 58F0040h, 4031C8h, 31C83D80h, 750A0040h
.text:0040131C                 dd 0B1FF4176h, 403000h, 31C8058Fh, 3D800040h, 4031C8h
```

我们可以点击相应位置按下`c`键, 将这些数据转换成代码进行识别. (我们需要按下多次c键进行转换), 得到如下代码.

如下, 在`seh_handler`位置, 又用类似的方法注册了一个位于`401306h`的异常处理函数, 并通过`xor ecx,ecx; div ecx`手动触发了一个`除0异常`. 而在`loc_401301`位置, 这是一个反调试技巧, `jmp loc_401301+2`会使得`EIP`转向一条指令中间, 使得无法继续调试. 所以我们可以将`00401301~00401306`部分的代码`nop`掉, 然后在`00401306`位置创建一个新函数`seh_handler2`

```
seh_handler:                            ; DATA XREF: process_input+7Do
.text:004012D7                 pop     large dword ptr fs:0
.text:004012DE                 add     esp, 4
.text:004012E1                 push    401306h
.text:004012E6                 push    large dword ptr fs:0
.text:004012ED                 mov     large fs:0, esp
.text:004012F4                 mov     eax, 1
.text:004012F9                 xor     ecx, ecx
.text:004012FB                 div     ecx
.text:004012FD                 xor     eax, eax
.text:004012FF                 mul     ecx
.text:00401301
.text:00401301 loc_401301:                             ; CODE XREF: .text:00401304j
.text:00401301                 add     esp, 0FFFFFFFFh
.text:00401304                 jmp     short near ptr loc_401301+2
.text:00401306 ; ---------------------------------------------------------------------------
.text:00401306                 pop     large dword ptr fs:0
.text:0040130D                 add     esp, 4
.text:00401310                 push    401330h
.text:00401315                 push    large dword ptr fs:0
.text:0040131C                 mov     large fs:0, esp
.text:00401323                 xor     ecx, ecx
.text:00401325                 mov     ebx, [ecx]
.text:00401327                 xor     eax, eax
.text:00401329                 mul     ecx
```

类似的, 还有`401330h`重命名为`seh_handler3`, 而`40135Eh`是最后一个注册的异常处理函数, 我们可以推测这才是虚拟机真正的main函数, 因此我们将`40135Eh`重命名为`vm_main`. (有关SEH和反调试的部分, 可以推荐大家自己去动态调试一番弄清楚)

## 恢复堆栈平衡

我们创建了一个`vm_main`函数(重命名后还需要创建函数, IDA才能识别), 然后按下`F5`提示失败, 失败的原因则是由于堆栈不平衡导致的.  因此我们可以点击IDA菜单项`Options->General`在右侧勾选`stack pointer`. 这样就会显示出对应的栈指针. 

```
.text:004017F2 000                 jmp     vm_main
.text:004017F7     ; ---------------------------------------------------------------------------
.text:004017F7 000                 push    0               ; uType
.text:004017F9 004                 push    offset aError   ; "Error"
.text:004017FE 008                 push    offset Text     ; "The key is wrong."
.text:00401803 00C                 push    0               ; hWnd
.text:00401805 010                 call    MessageBoxA
.text:0040180A
.text:0040180A     locret_40180A:                          ; CODE XREF: vm_main+492j
.text:0040180A 000                 leave
.text:0040180B -04                 leave
.text:0040180C -08                 leave
.text:0040180D -0C                 leave
.text:0040180E -10                 leave
.text:0040180F -14                 leave
.text:00401810 -18                 leave
.text:00401811 -1C                 retn
.text:00401811     vm_main         endp ; sp-analysis failed
```

我们来到最下显示不平衡的位置. 最上的`jmp vm_main`表明虚拟机内在执行一个循环. 而`MessageBoxA`的调用则是显示最后弹出的错误信息. 而在`locret_40180A`位置处, 经过多次leave堆栈严重不平衡, 因此我们需要手动恢复堆栈平衡. 

这里也很简单, 在`0040180A`位置已经堆栈平衡了(000), 因此我们只需要将这一句`leave`修改为`retn`就可以了. 如下这样

```
.text:0040180A     locret_40180A:                          ; CODE XREF: vm_main+492j
.text:0040180A 000                 retn
.text:0040180B     ; ---------------------------------------------------------------------------
.text:0040180B 004                 leave
.text:0040180C 004                 leave
.text:0040180D 004                 leave
```

然后你就可以发现`vm_main`可以F5生成伪C代码了. 

## 虚拟机指令分析

说实话, 虚拟机的分析部分是一个比较枯燥的还原过程, 你需要比对各个小部分的操作来判断这是一个怎样的指令, 使用的是哪些寄存器. 像这个crackme中, vm进行的是一个`取指-译码-执行`的循环. `译码`过程可给予我们的信息最多, 不同的指令都会在这里, 根据它们各自的`opcode`, 使用`if-else if-else`分支进行区分. 实际的还原过程并不复杂, 但有可能会因为虚拟机实现的指令数量而显得有些乏味. 

最后分析出的结果如下:

| opcode | value |
| ------ | ----- |
| push   | 0x0a  |
| pop    | 0x0b  |
| mov    | 0x0c  |
| cmp    | 0x0d  |
| inc    | 0x0e  |
| dec    | 0x0f  |
| and    | 0x1b  |
| or     | 0x1c  |
| xor    | 0x1d  |
| check  | 0xff  |

我们再来看分析后的`initVM`函数

```c
int initVM()
{
  int result; // eax@1

  r1 = 0;
  r2 = 0;
  r3 = 0;
  result = (unsigned __int8)inputName[(unsigned __int8)cur_index];
  r4 = (unsigned __int8)inputName[(unsigned __int8)cur_index];
  vm_sp = 0x32;
  vm_pc = 0;
  vm_flags_zf = 0;
  vm_flags_sf = 0;
  ++cur_index;
  return result;
}
```

这里有4个通用寄存器(`r1/r2/r3/r4`), 1个`sp`指针和1个`pc`指针, 标志`zf`和`sf`. 先前我们不知道的`var_a`也被重命名为`cur_index`, 指向的是`inputName`当前正在处理的字符索引. 

对于VM实现的多个指令我们就不再多说, 重点来看下`check`部分的操作.

```c
int __fastcall check(int a1)
{
  char v1; // al@1
  int result; // eax@4

  v1 = r1;
  if ( (unsigned __int8)r1 < 0x21u )
    v1 = r1 + 0x21;
  LOBYTE(a1) = cur_index;
  if ( v1 == inputKey[a1] )
  {
    if ( (unsigned __int8)cur_index >= (unsigned __int8)lenOfName )
      result = MessageBoxA(0, aGoodJobNowWrit, Caption, 0);
    else
      result = initVM();
  }
  else
  {
    result = MessageBoxA(0, Text, Caption, 0);
  }
  return result;
}
```

如果`r1`中的值跟`inputKey[cur_index]`相等, 那么会继续判断是否已经检查完了整个`inputName`, 如果没有出错且比对结束, 那么就会弹出`Good job! Now write a keygen.`的消息框. 否则会继续`initVM`进入下一轮循环.(出错了当然是弹出消息框提示错误了. )

`cur_index`会在`initVM`中自增1, 那么还记得之前在`process_input`里有执行2次`initVM`吗. 因为有执行2次`initVM`, 所以我们的`inputKey`的前2位可以是任意字符. 

```c
      unk_4031CE = i;
      opcode = vm_pc;
      initVM();
      initVM();
      __debugbreak();
      JUMPOUT(*(_DWORD *)&word_4012CE);
```

 故而我们分析完了整个虚拟机, 便可以开始着手编写`Keygen`. 

对应的`keygenme`可以点击此处下载: [fuelvm_keygen.py](https://github.com/ctf-wiki/ctf-challenges/blob/master/reverse/vm/fuelvm/fuelvm_keygen.py)

```bash
$ python2 fuelvm_keygen.py ctf-wiki
[*] Password for user 'ctf-wiki' is: 4mRC*TKJI
```

对应的`IDA数据库`可以点击此处下载: [FuelVM.idb](https://github.com/ctf-wiki/ctf-challenges/blob/master/reverse/vm/fuelvm/FuelVM.idb)