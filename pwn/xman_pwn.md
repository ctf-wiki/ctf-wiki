# XMan 二进制漏洞发掘与利用技术

> 陈星漫  
> 2016 年 8 月 16 日

## 软件安全基础

* 专注于研究软件的设计和实现的安全
* 研究对象：代码（源码、字节码、汇编）
* 研究目标：减少软件漏洞
* PWN: 

### 漏洞的分类

* 逻辑漏洞
* 内存破坏漏洞
  * 缓冲区溢出（Stack Heap）
  * 整数溢出（Integer Overflow）
  * 格式化字符串（Format String）
  * 初始化（UAF）等

### 漏洞的危害

* 内核漏洞
  * iOS 越狱，Linux / Android 提权
* 库漏洞
  * openssl 信息泄露
* 软件漏洞
  * 浏览器 RCE
  * nginx RCE
  * 路由器 RCE
  * 等等

### x86 汇编模型

### Memory Mapping

### Lazy Binding

* Static Link
  * 不依赖本地函数库
* Dynamic Link
  * 链接器将符号的引用标记为一个动态链接的符号，在装载时进行地址的重定位
  * 通过 `_dl_runtime_resolve()` 进行索引

### GOT

* Global Offset Table
* 当执行到 library 的 function 时才会去寻找 function，got table 用于

### x86 内存分布

* 堆
* 共享库
* 栈
* Data(Global / Static)
* Text

### Stack

* 内存中的一块区域，用栈的数据结构来管理
* 从高地址向低地址增长
* x86 用 ESP 寄存器和 EBP 寄存器来管理

### Heap

* Glibc - ptmalloc
* Structure
  * chunk 与 bin
* 以 chunk（块）为单位进行管理
  * malloc chunk
  * free chunk
  * top chunk
* Bin 索引空间状态的块
* 数据结构：链表
  * fast bin
  * small bin
  * large bin
  * unsorted bin

## 漏洞利用概述

### 常见漏洞类型

* BOF(Buffer Overflow)
  * Stack
  * Heap
* FMS(Format String)
* Integer Overflow
* Others
  * Race Condition
  * Logic Condition

### 常见漏洞利用姿势

* Shellcode

  实现弹 shell

* Ret2libc

* ROP(Return Oriented Programing)

  将可用的代码片段进行组合

* Heap Overflow

  * 破坏 chunk 中的 metadata，利用 ptmalloc 管理中的操作达到目的，如 dword shoot
  * Unlink
    * assert(P->fd->bk == P)
    * assert(P->bk->fd == P)
  * Bypass
    * Find a pointer *X = P
    * Set P->fd and ->bk to X
    * Unlink(P)
    * *P = X

* Got Overwrite

  * 覆盖 Got 表的关键函数
  * `free(strdup("/bin/sh") => system("/bin/sh"))`

* Stack pivot

  * 将栈迁移到一个大小足够的地方
  * xchg eax,esp

### Mitigation

* NX
  * 堆栈不可执行
  * shellcode 不可用
* Canary
  * 覆盖返回地址基本不可利用
* PIE
  * 攻击时需要泄露地址
* RELRO
  * Partial：不可修改 strtab
  * Full：程序装载时即填充 Got 表

### Tools

* Desassembler
  * IDA
* Debug
  * GDB
* Tools
  * pwntools
  * peda
  * checksec
  * libcdb
  * Ropgadget

## 漏洞利用题解分享



## 漏洞利用实战演练