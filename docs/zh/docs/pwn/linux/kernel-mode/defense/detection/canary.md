# Kernel Stack Canary

Canary 是一种典型的检测机制。在 Linux 内核中，Canary 的实现是与架构相关的，所以这里我们分别从不同的架构来介绍。

## x86

### 介绍

在 x86 架构中，同一个 task 中使用相同的 Canary。

### 发展历史

TODO。

### 实现

TODO。

### 使用

#### 开启

在编译内核时，我们可以设置 CONFIG_CC_STACKPROTECTOR 选项，来开启该保护。

#### 关闭

我们需要重新编译内核，并关闭编译选项才可以关闭  Canary 保护。

### 状态检查

我们可以使用如下方式来检查是否开启了 Canary 保护

1. `checksec` 
2. 人工分析二进制文件，看函数中是否有保存和检查 Canary 的代码

### 特点

可以发现，x86 架构下 Canary 实现的特点是同一个 task 共享 Canary。

### 攻击

根据 x86 架构下 Canary 实现的特点，我们只要泄漏了一次系统调用中的 Canary，同一 task 的其它系统调用中的 Canary 也就都被泄漏了。

## 参考

- https://www.workofard.com/2018/01/per-task-stack-canaries-for-arm64/
- [PESC: A Per System-Call Stack Canary Design for Linux Kernel](https://yajin.org/papers/pesc.pdf)
