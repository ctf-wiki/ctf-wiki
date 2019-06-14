## 关于NtGlobalFlag

在32位机器上, `NtGlobalFlag`字段位于`PEB`(进程环境块)`0x68`的偏移处, 64位机器则是在偏移`0xBC`位置. 该字段的默认值为0. 当调试器正在运行时, 该字段会被设置为一个特定的值. 尽管该值并不能十分可信地表明某个调试器真的有在运行, 但该字段常出于该目的而被使用.

该字段包含有一系列的标志位. 由调试器创建的进程会设置以下标志位:

```c
FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
FLG_HEAP_ENABLE_FREE_CHECK (0x20)
FLG_HEAP_VALIDATE_PARAMETERS (0x40)
```

## 检测代码

因此, 可以检查这几个标志位来检测调试器是否存在. 比如用形如以下的32位的代码在32位机器上进行检测:

``` asm
mov eax, fs:[30h] ;Process Environment Block
mov al, [eax+68h] ;NtGlobalFlag
and al, 70h
cmp al, 70h
je being_debugged
```

以下是64位的代码在64位机器上的检测代码:

``` asm
push 60h
pop rsi
gs:lodsq                ;Process Environment Block
mov al, [rsi*2+rax-14h] ;NtGlobalFlag
and al, 70h
cmp al, 70h
je being_debugged
```

要注意的是, 如果是一个32位程序在64位机器上运行, 那么实际上会存在两个PEB: 一个是32位部分的而另一个是64位. 64位的PEB的对应字段也会像在32位的那样而改变.

于是我们就还有以下的, 用32位的代码检测64位机器环境:

```
mov eax, fs:[30h] ; Process Environment Block
;64-bit Process Environment Block
;follows 32-bit Process Environment Block
mov al, [eax+10bch] ;NtGlobalFlag
and al, 70h
cmp al, 70h
je being_debugged
```

切记不要在没有掩盖其他位的情况下直接进行比较, 那样会无法检测到调试器.

在`ExeCryptor`就有使用`NtGlobalFlag`来检测调试器, 不过`NtGlobalFlag`的那3个标志位只有当程序是`由调试器创建`, 而非`由调试器附加`上去的进程时, 才会被设置.

## 改变NtGlobalFlag初值

当然绕过这种检测的方法也十分简单, 那就是调试器想办法将该字段重新设置为0. 然而这个默认的初值可以用以下四种方法任意一种改变:

1. 注册表`HKLM\System\CurrentControlSet\Control\SessionManager`的`GlobalFlag`的值会替换进行`NtGlobalFlag`字段. 尽管它随后还可能由Windows改变(以下会介绍), 注册表键值会对系统中所有进程产生影响并在重启后生效.

    ![GlobalFlag.png](./figure/globalflag.png)

    当然这也产生了另一种检测调试器的方法: 如果一个调试器为了隐藏自己, 而将注册表中的键值复制到`NtGlobalFlag`字段中, 然而注册表中的键值事先已经替换并且尚未重启生效. 那么调试器只是复制了一个假的值, 而非真正需要的那个. 如果程序知道真正的值而非注册表中的那个假的值, 那么就可以察觉到调试器的存在.

    当然调试器也可以运行其他进程然后查询`NtGlobalFlag`字段来获取真正的值.

2. 依旧是`GlobalFlag`, 不过这里的是`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<filename>`. (映像劫持), 这里需要将`<filename>`替换为需要更改的可执行文件的文件名(不需要指定路径). 设置好`GlobalFlag`后, 系统会将其值覆盖到`NtGlobalFlag`字段(只单独为指定的进程覆盖). 不过也还是可以再次由Windows改变(见下).
3. 在加载配置表(`Load Configuration Table`)的两个字段: `GlobalFlagsClear`和`GlobalFlagsSet`.

    `GlobalFlagsClear`列出需要清空的标志位, 而`GlobalFlagsSet`则列出需要设置的标志位, 这些设置会在`GlobalFlag`应用之后再生效, 因此它可以覆盖掉`GlobalFlag`指定的值. 然而它无法覆盖掉Windows指定设置的标志位. 比如设置`FLG_USER_STACK_TRACE_DB (0x1000)`可以让Windows设置`FLG_HEAP_VALIDATE_PARAMETERS (0x40)`标志位, 就算`FLG_HEAP_VALIDATE_PARAMETERS`在加载配置表(`Load Configuration Table`)中被清空了, Windows也会在随后的进程加载过程中重新设置.

4. 当调试器创建进程时, Windows会做出一些改变. 通过设置环境变量中的`_NO_DEBUG_HEAP`, `NtGlobalFlag`将会因为调试器而不会设置其中的3个堆的标志位. 当然它们依旧可以通过`GlobalFlag`或加载配置表中的`GlobalFlagsSet`继续设置.


## 如何绕过检测?

有以下3种方法来绕过`NtGlobalFlag`的检测

* 手动修改标志位的值(`FLG_HEAP_ENABLE_TAIL_CHECK`, `FLG_HEAP_ENABLE_FREE_CHECK`, `FLG_HEAP_VALIDATE_PARAMETERS`)
* 在Ollydbg中使用`hide-debug`插件
* 在Windbg禁用调试堆的方式启动程序(`windbg -hd program.exe`)

## 手动绕过示例

以下是一个演示如何手动绕过检测的示例

``` asm
.text:00403594     64 A1 30 00 00 00          mov     eax, large fs:30h   ; PEB struct loaded into EAX
.text:0040359A                                db      3Eh                 ; IDA Pro display error (the byte is actually used in the next instruction)
.text:0040359A     3E 8B 40 68                mov     eax, [eax+68h]      ; NtGlobalFlag (offset 0x68 relative to PEB) saved to EAX
.text:0040359E     83 E8 70                   sub     eax, 70h            ; Value 0x70 corresponds to all flags on (FLG_HEAP_ENABLE_TAIL_CHECK, FLG_HEAP_ENABLE_FREE_CHECK, FLG_HEAP_VALIDATE_PARAMETERS)
.text:004035A1     89 85 D8 E7 FF FF          mov     [ebp+var_1828], eax
.text:004035A7     83 BD D8 E7 FF FF 00       cmp     [ebp+var_1828], 0   ; Check whether 3 debug flags were on (result of substraction should be 0 if debugged)
.text:004035AE     75 05                      jnz     short loc_4035B5    ; No debugger, program continues...
.text:004035B0     E8 4B DA FF FF             call    s_selfDelete        ; ...else, malware deleted
```

在Ollydbg中在偏移`0x40359A`设置断点, 运行程序触发断点. 然后打开`CommandLine`插件用`dump fs:[30]+0x68`dump出`NtGlobalFlag `的内容

![Manually-set-peb-ntglobalflag.png](./figure/manually_set_peb_ntglobalflag.png)

右键选择`Binary->Fill with 00's`将值`0x70`替换为`0x00`即可.

## 参考链接

* [The "Ultimate" Anti-Debugging Reference](http://anti-reversing.com/Downloads/Anti-Reversing/The_Ultimate_Anti-Reversing_Reference.pdf)
* [PEB-Process-Environment-Block/NtGlobalFlag](https://www.aldeid.com/wiki/PEB-Process-Environment-Block/NtGlobalFlag)
