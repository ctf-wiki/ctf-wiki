# 控制程序执行流

在控制程序执行流的过程中，我们可以考虑如下方式。

## 直接控制 EIP



## 返回地址

即控制程序栈上的返回地址。

## 跳转指针

这里我们可以考虑如下方式

- call 
- jmp

## 函数指针

常见的函数指针具有

- vtable,  function table，如 IO_FILE 的 vtable，printf function table。
- hook  指针，如 `malloc_hook`，`free_hook`。
- handler

## 修改控制流相关变量