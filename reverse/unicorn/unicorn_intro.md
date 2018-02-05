# Unicorn Engine简介

## 什么是Unicorn引擎

Unicorn是一个轻量级, 多平台, 多架构的CPU模拟器框架. 我们可以更好地关注CPU操作, 忽略机器设备的差异. 想象一下, 我们可以将其应用于这些情景: 比如我们单纯只是需要模拟代码的执行而非需要一个真的CPU去完成那些操作, 又或者想要更安全地分析恶意代码, 检测病毒特征, 或者想要在逆向过程中验证某些代码的含义. 使用CPU模拟器可以很好地帮助我们提供便捷.

它的亮点(这也归功于Unicorn是基于[qemu](http://www.qemu.org)而开发的)有:

* 支持多种架构: Arm, Arm64 (Armv8), M68K, Mips, Sparc, & X86 (include X86_64).
* 对Windows和*nix系统(已确认包含Mac OSX, Linux, *BSD & Solaris)的原生支持
* 具有平台独立且简洁易于使用的API
* 使用JIT编译技术, 性能表现优异

你可以在[Black Hat USA 2015](http://www.unicorn-engine.org/BHUSA2015-unicorn.pdf)获悉有关Unicorn引擎的更多技术细节. Github项目主页: [unicorn](https://github.com/unicorn-engine/unicorn)

尽管它不同寻常, 但它无法模拟整个程序或系统, 也不支持系统调用. 你需要手动映射内存并写入数据进去, 随后你才能从指定地址开始模拟. 

## 应用的情景

什么时候能够用到Unicorn引擎呢? 

* 你可以调用恶意软件中一些有趣的函数, 而不用创建一个有害的进程.
* 用于CTF竞赛
* 用于模糊测试
* 用于gdb插件, 基于代码模拟执行的插件
* 模拟执行一些混淆代码

## 如何安装

安装Unicorn最简单的方式就是使用pip安装, 只要在命令行中运行以下命令即可(这是适合于喜爱用python的用户的安装方法, 对于那些想要使用C的用户, 则需要去官网查看文档编译源码包):

``` shell
pip install unicorn
```

但如果你想用源代码进行本地编译的话, 你需要在[下载](http://www.unicorn-engine.org/download/)页面中下载源代码包, 然后可以按照以下命令执行:

* *nix 平台用户

``` shell
$ cd bindings/python
$ sudo make install
```

* Windows平台用户

``` shell
cd bindings/python
python setup.py install
```

对于Windows, 在执行完上述命令后, 还需要将[下载](http://www.unicorn-engine.org/download/)页面的`Windows core engine`的所有dll文件复制到`C:\locationtopython\Lib\site-packages\unicorn`位置处. 

## 使用unicorn的快速指南

我们将会展示如何使用python调用unicorn的api以及它是如何轻易地模拟二进制代码. 当然这里用的api仅是一小部分, 但对于入门已经足够了.

``` python
 1 from __future__ import print_function
 2 from unicorn import *
 3 from unicorn.x86_const import *
 4 
 5 # code to be emulated
 6 X86_CODE32 = b"\x41\x4a" # INC ecx; DEC edx
 7 
 8 # memory address where emulation starts
 9 ADDRESS = 0x1000000
10 
11 print("Emulate i386 code")
12 try:
13     # Initialize emulator in X86-32bit mode
14     mu = Uc(UC_ARCH_X86, UC_MODE_32)
15 
16     # map 2MB memory for this emulation
17     mu.mem_map(ADDRESS, 2 * 1024 * 1024)
18 
19     # write machine code to be emulated to memory
20     mu.mem_write(ADDRESS, X86_CODE32)
21 
22     # initialize machine registers
23     mu.reg_write(UC_X86_REG_ECX, 0x1234)
24     mu.reg_write(UC_X86_REG_EDX, 0x7890)
25 
26     # emulate code in infinite time & unlimited instructions
27     mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))
28 
29     # now print out some registers
30     print("Emulation done. Below is the CPU context")
31 
32     r_ecx = mu.reg_read(UC_X86_REG_ECX)
33     r_edx = mu.reg_read(UC_X86_REG_EDX)
34     print(">>> ECX = 0x%x" %r_ecx)
35     print(">>> EDX = 0x%x" %r_edx)
36 
37 except UcError as e:
38     print("ERROR: %s" % e)
```

运行结果如下:

``` shell
$ python test1.py 
Emulate i386 code
Emulation done. Below is the CPU context
>>> ECX = 0x1235
>>> EDX = 0x788f
```

样例里的注释已经非常直观, 但我们还是对每一行代码做出解释:
* 行号2~3: 在使用Unicorn前导入`unicorn`模块. 样例中使用了一些x86寄存器常量, 所以也需要导入`unicorn.x86_const`模块
* 行号6: 这是我们需要模拟的二进制机器码, 使用十六进制表示, 代表的汇编指令是: "INC ecx" 和 "DEC edx".
* 行号9: 我们将模拟执行上述指令的所在虚拟地址
* 行号14: 使用`Uc`类初始化Unicorn, 该类接受2个参数: 硬件架构和硬件位数(模式). 在样例中我们需要模拟执行x86架构的32位代码, 我们使用变量`mu`来接受返回值.
* 行号17: 使用`mem_map `方法根据在行号9处声明的地址, 映射2MB用于模拟执行的内存空间. 所有进程中的CPU操作都应该只访问该内存区域. 映射的内存具有默认的读,写和执行权限.
* 行号20: 将需要模拟执行的代码写入我们刚刚映射的内存中. `mem_write`方法接受2个参数: 要写入的内存地址和需要写入内存的代码.
* 行号23~24: 使用`reg_write`方法设置`ECX`和`EDX`寄存器的值
* 行号27: 使用`emu_start`方法开始模拟执行, 该API接受4个参数: 要模拟执行的代码地址, 模拟执行停止的内存地址(这里是`X86_CODE32`的最后1字节处), 模拟执行的时间和需要执行的指令数目. 如果我们像样例一样忽略后两个参数, Unicorn将会默认以无穷时间和无穷指令数目的条件来模拟执行代码. 
* 行号32~35: 打印输出`ECX`和`EDX`寄存器的值. 我们使用函数`reg_read`来读取寄存器的值.


要想查看更多的python示例, 可以查看文件夹[bindings/python](https://github.com/unicorn-engine/unicorn/tree/master/bindings/python)下的代码. 而C的示例则可以查看[sample](https://github.com/unicorn-engine/unicorn/tree/master/samples)文件夹下的代码. 


## 参考链接

* [Unicorn Official Site](http://www.unicorn-engine.org/)
* [Quick tutorial on programming with Unicorn - with C & Python.](http://www.unicorn-engine.org/docs/)