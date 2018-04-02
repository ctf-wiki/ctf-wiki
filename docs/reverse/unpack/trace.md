单步跟踪法的原理就是通过Ollydbg的步过(F8), 步入(F7)和运行到(F4)功能, 完整走过程序的自脱壳过程, 跳过一些循环恢复代码的片段, 并用单步进入确保程序不会略过OEP. 这样可以在软件自动脱壳模块运行完毕后, 到达OEP, 并dump程序. 

## 要点

1. 打开程序按F8单步向下, 尽量实现向下的jmp跳转
2. 会经常遇到大的循环, 这时要多用 F4 来跳过循环
3. 如果函数载入时不远处就是一个call(近call), 那么我们尽量不要直接跳过, 而是进入这个call
4. 一般跳转幅度大的jmp指令, 都极有可能是跳转到了原程序入口点(OEP)

## 示例

示例程序可以点击此处下载: [1_trace.zip](/reverse/unpack/example/1_trace.zip)

单步跟踪法其实就是一步一步尽量从程序入口点往下走, 在单步的过程中注意EIP不要跑偏了, 但是对于一些比较复杂的壳而言, 单步的过程会显得异常枯燥而且容易把自己绕晕. 所以单步跟踪也常用于分析一些关键代码部分(跟静态分析相结合), 而不是完全地从头分析到尾, 这有违逆向工程的理念. 

用Ollydbg打开压缩包内的Notepad.exe, 停在了下图位置. 入口点是一个`pushad`保存所有寄存器状态到栈中, 随后便是一个`call`调用位于`0040D00A`处的函数. 调用后便无条件跳转到`459DD4F7`处, 之后的`push ebp`和`retn`显然没有任何意义. 像这种入口点附近就是一个`call`的我们称为`近call`, 对于近call我们选择步进, 按下F7(当然你也只能选择步进, 不然EIP就跑偏程序停止了). 

![trace_01.png](/reverse/unpack/figure/trace_01.png)

步进后又是一个`call`, 我们继续步进, 按F7, 跟进后发现没有近call了, 我们可以看到程序在调`GetModuleHandleA`, `GetProcAddress`等API, 继续向下分析. 

![trace_02.png](/reverse/unpack/figure/trace_02.png)

之后会遇到多个跳转，我们尽量满足向下的跳转，对于向上的跳转不予实现并利用F4跳出循环，直到`0040D3AF`处, 我们看以下的代码

``` asm
0040D3AF    61              	popad
0040D3B0    75 08           	jnz short NotePad.0040D3BA
0040D3B2    B8 01000000    	    mov eax,0x1
0040D3B7    C2 0C00         	retn 0xC
0040D3BA    68 CC104000     	push NotePad.004010CC
0040D3BF    C3              	retn
```

这里`popad`可以恢复在程序入口点处保存的寄存器状态, 然后`jnz`跳转到`0040D3BA`处, 这里是利用`push`和`retn`来将`EIP`改变为`004010CC`, 也就是说在壳解压完代码等资源完毕后, 将通过`jnz`跳转到`push`处, 然后通过`push`和`ret`将`EIP`设置为程序原来的入口点(OEP)并返回到OEP处, 然后继续执行原程序的代码. 我们执行到`retn`返回后, 可以看到如下:

![trace_03.png](/reverse/unpack/figure/trace_03.png)

显然, 我们到了一堆被`Ollydbg`误认为是数据的地方继续执行, 显然`Ollydbg`分析错误了, 我们需要让`Ollydbg`重新分析, 我们可以右键选择`分析->从模块中删除分析`, 或是按下`ctrl+a`, 这时正确地显示出OEP处的汇编指令. 

![trace_04.png](/reverse/unpack/figure/trace_04.png)