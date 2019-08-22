[EN](./stack-intro.md) | [ZH](./stack-intro-zh.md)
#栈介绍


## Basic stack introduction


The stack is a typical data structure of Last in First Out. Its operations mainly include push and pop operations, as shown in the following figure (Wikipedia). Both operations operate on the top of the stack, and of course, it also has a stack.


![Basic stack operation] (./figure/Data_stack.png)


High-level languages are converted to assembler at runtime, making full use of this data structure while the assembler is running. Each program has a virtual address space at runtime, and a part of it is the stack corresponding to the program, which is used to save function call information and local variables. In addition, common operations are also stacking and popping. It should be noted that the stack of the ** program is growing from the high address of the process address space to the low address.


## function call stack


Be sure to take a closer look at the following article to learn the basic function call stack.


- [C language function call stack (1)] (http://www.cnblogs.com/clover-toeic/p/3755401.html)
- [C language function call stack (2)] (http://www.cnblogs.com/clover-toeic/p/3756668.html)


Here is another diagram of the register.


![](./figure/register.png)



It should be noted that 32-bit and 64-bit programs have the following simple differences.


- **x86**

- **Function parameter ** above the ** function return address**
- **x64**

- System V AMD64 ABI (used in Linux, FreeBSD, macOS, etc.) The first six integer or pointer parameters are stored in the **RDI, RSI, RDX, RCX, R8 and R9 registers**, if there are more The parameters will be saved on the stack.
- The memory address cannot be greater than 0x00007FFFFFFFFFFF, **6 bytes long**, otherwise an exception will be thrown.


## Reference reading


- a tap
- Calling conventions for different C++ compilers and operating systems, Agner Fog
