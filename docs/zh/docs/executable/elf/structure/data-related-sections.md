# Data Related Sections

## .BSS Section

未初始化的全局变量对应的节。此节区不占用 ELF 文件空间，但占用程序的内存映像中的空间。当程序开始执行时，系统将把这些数据初始化为 0。bss其实是block started by symbol 的简写。

## .data Section

这些节区包含初始化了的数据，会在程序的内存映像中出现。

## .rodata Section

这些节区包含只读数据，这些数据通常参与进程映像的不可写段。

