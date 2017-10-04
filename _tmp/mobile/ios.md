> 王铁磊  
> 盘古团队  
> 2016 年 8 月 18 日

# iOS 安全概要

苹果公司通常会发布 iOS 安全架构白皮书

* Isolations
* Restricted Sandbox
* Code Signing
* Exploit Mitigation (ASLR, DEP)
* Data Protection
* Hypervisor

# 主要安全特性的时间线

从无到有，从弱到强

# iOS 漏洞挖掘

* 识别 Attack Surface
* 理解数据交互过程
* 审计代码实现和逻辑
* 挖掘漏洞构造触发样本

## iOS 本地攻击面

1. USB
   * 文件访问接口
   * 备份还原接口
   * 应用管理接口
   * 开发者接口
2. 安装的应用
   * Jekyll 类型应用 （USENIX Security「13）
   * Masque Attacks (FireEye Research)

## 用户态远程攻击面攻击

1. 任何网络连接都可能成为攻击面
   * Mobile Safari
     * JailbreakMe
     * Mobile Pwn2Own
   * Messager
     * CVE-2009-2204, SMS vulnerability, Charlie Miller
     * CVE-2015-1157, crafted Unicode text reboot bug
   * 系统中的网络服务进程
     * CVE-2015-1118, crafted configuration profile reboot bug

## 内核攻击面分析

1. 用户态和内核的任何通信渠道都是潜在的攻击面
2. 进一步细分
3. 文件系统
   * HFS legacy volume name stack buffer overflow
     * JailbreakMe 3 for iOS 4.2.x
   * HFS heap overflow
     * Corona for iOS 5.0
4. ioctl
   * Packet Filter Kernel Exploit
     * DIOCADDRULE ioctl 处理函数未初始化变量漏洞
       * 可以使任意内核地址的内容减一
5. /dev/*
   * ptmx＿get＿ioctl 内存越界访问漏洞
     * ptmx 设备在处理 minor 参数
6. IOKit
   * IOSurface
   * IOMobileFrameBuffer
   * IOUSBDeviceFamily
   * IOSharedDataQueue
   * IOHIDFamily

# 漏洞实例分享

## iOS / OS X 进程间通信

* iOS / OS X 上大量进程间通信方式 IPC
  * 好处
    * 功能和权限分离
    * 稳定性
  * 坏处
    * IPC 数据自身的数据处理可能导致安全问题
* 基于 Mach Message 的安全研究
  * Mach Message 是各种 IPC 通信的基础
    * 通过
  * Mach Message 格式