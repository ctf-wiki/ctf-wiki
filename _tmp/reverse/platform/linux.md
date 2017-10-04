# 简介

使用逆向工程方法，通过反编译和动态调试等手段对ELF文件进行分析，理解程序结构、执行流程，明白程序的功能特性并利用改造。

# ELF文件生成

本节示例程序：<a href="/reverse/examples/linux逆向/1-ELF文件生成.tar.gz">1-ELF文件生成.tar.gz</a>

ELF文件生成的主要流程为如下

![ELF文件生成流程图](/reverse/images/ELF-generate.png)

* 预处理Pre-Processing

主要工作是`引入头文件`(如stdio.h)、进行`宏的替换`、`删除注释`。

我们使用`-E`选项可以指定gcc编译只进行预处理

```bash
gcc -E Hello.c -o Hello.i
```

![预处理](/reverse/images/pre-processing.png)

* 编译 Compile

GCC首先`检查代码规范及语法错误`，无误后将代码`翻译成汇编语言`

我们使用`-S`选项可以指定gcc编译只进行编译
```bash
gcc -S Hello.i -o Hello.s
```
![编译](/reverse/images/compile.png)


* 汇编 Assembly

将.s的汇编文件`翻译成二进制机器指令`文件.o, 也即`目标文件`(object file)

我们使用`-E`选项可以指定gcc编译只进行预处理

```bash
gcc -c Hello.s -o Hello.o
```
![汇编](/reverse/images/assembly.png)


* 链接 Link

链接函数库，生成最终ELF文件

```bash
gcc Hello.o -o Hello
```

# ELF文件结构

![ELF文件结构图](/reverse/images/ELF-structure.png)

## ELF文件头

本节示例程序：<a href="/reverse/examples/linux逆向/2-ELF文件结构.tar.gz">1-ELF文件结构.tar.gz</a>

我们可以使用如下命令读取 ELF 文件的文件头

```bash
readelf -h 1-ELF_Headers
```

![ELF文件头](/reverse/images/ELF-headers.png)

* ELF Header 指明ELF文件头开始
* Magic  魔数,用来指名该文件是一个 ELF 目标文件.第一个字节7F是个固定的数.后面的3个字节则是 `E` `L` `F` 三个字母.
* Class 表示文件类型,这里是64位的 ELF 格式.
* Data 表示文件中的数据是按照什么格式组织(大端或小端)的,不同处理器平台数据组织格式可能就不同,如x86平台为`小端存储格式`
* Version 当前ELF文件头版本号,这里版本号为1.
* OS/ABI 指出操作系统类型。ABI 是 Application Binary Interface 的缩写。
* ABI VERSION 表示ABI 版本号,当前为 0
* Type 表示文件类型.ELF 文件有 3 种类型
  * 一种是如上所示的Relocatable file`可重定位目标文件`，
  * 一种是`可执行文件`(Executable)，
  * 另一种是`共享库`(Shared Library) 。
* Machine 机器平台类型
* Version 当前目标文件的版本号
* Entry point address 程序的虚拟地址入口点,如果是不可运行的程序则为0
* Start of program headers 程序头的起始位置
* Start of section headers 节区头的起始位置
* Flags 是一个与处理器相关联的标志, x86平台上该处为0

## 区段布局

![ELF文件区段布局图](/reverse/images/ELF-layout.png)

* text 存放程序代码与函数指令
* data 存放已初始化的全局变量和静态变量
* bss 存放未初始化的全局变量和静态变量,bss段的长度一般为0

这里有几点说明，首先，局部变量动态的分配和释放,在elf中并没有对应的段，另外动态申请(malloc,free)的空间在运行时在堆中分配,elf中也没有对应的段

## 虚拟内存分布

![进程空间分布](/reverse/images/ELF-image-layout.png)

* .text
代码段, 用于存放程序执行代码的一块内存空间, 一般只读(对应ELF段(.init .rodata .text))
* .data
数据段, 用于存放程序中已初始化的全局变量和静态变量(static)的一块内存空间(对应ELF段(.data .bss)
* .stack
栈段, 用于存放程序的局部变量以及函数参数。函数调用结束后,返回值也会存放在栈中
* .heap
堆段, 用于存放进程运行中被动态分配的内存段, 大小可以动态扩张(malloc等)和缩减(free).


## 物理地址空间

![物理地址空间分布](/reverse/images/physics-space.png)

* 4G进程空间
  * 32位操作系统中指针长度为4字节
  * 指针最大寻址能力为4G(0xFFFFFFFF)
  * 通常是一些操作寄存器或立即数的算术指令

* 虚拟内存空间
  * 相当于一个"中间层"
  * 避免直接操作物理内存(操作其他进程)
  * 提高内存使用效率
  * 内核区为2GB,供所有的进程共享

* 物理地址空间
  * 进程间彼此隔离
  * 避免直接操作物理内存(操作其他进程)
  * 提高内存使用效率
  * 内核区为2GB,供所有的进程共享

# 静态分析

# 动态调试
