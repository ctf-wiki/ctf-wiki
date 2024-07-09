# Kernel Stack Canary

Canary 是一種典型的檢測機制。在 Linux 內核中，Canary 的實現是與架構相關的，所以這裏我們分別從不同的架構來介紹。

## x86

### 介紹

在 x86 架構中，同一個 task 中使用相同的 Canary。

### 發展歷史

TODO。

### 實現

TODO。

### 使用

#### 開啓

在編譯內核時，我們可以設置 CONFIG_CC_STACKPROTECTOR 選項，來開啓該保護。

#### 關閉

我們需要重新編譯內核，並關閉編譯選項纔可以關閉  Canary 保護。

### 狀態檢查

我們可以使用如下方式來檢查是否開啓了 Canary 保護

1. `checksec` 
2. 人工分析二進制文件，看函數中是否有保存和檢查 Canary 的代碼

### 特點

可以發現，x86 架構下 Canary 實現的特點是同一個 task 共享 Canary。

### 攻擊

根據 x86 架構下 Canary 實現的特點，我們只要泄漏了一次系統調用中的 Canary，同一 task 的其它系統調用中的 Canary 也就都被泄漏了。

## 參考

- https://www.workofard.com/2018/01/per-task-stack-canaries-for-arm64/
- [PESC: A Per System-Call Stack Canary Design for Linux Kernel](https://yajin.org/papers/pesc.pdf)
