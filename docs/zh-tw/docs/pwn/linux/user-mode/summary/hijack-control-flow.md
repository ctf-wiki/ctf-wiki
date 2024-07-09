# 控制程序執行流

在控制程序執行流的過程中，我們可以考慮如下方式。

## 直接控制 EIP



## 返回地址

即控制程序棧上的返回地址。

## 跳轉指針

這裏我們可以考慮如下方式

- call 
- jmp

## 函數指針

常見的函數指針具有

- vtable,  function table，如 IO_FILE 的 vtable，printf function table。
- hook  指針，如 `malloc_hook`，`free_hook`。
- handler

## 修改控制流相關變量