> 刘惠明  
> 腾讯玄武实验室  
> 2016 年 8 月 12 日

# 安卓背景介绍
## 安卓生态圈简介
### 安卓是什么
2003 年创立
2005 年被谷歌收购
2008 年 HTC G1 第一款安卓手机

安卓开源吗？

- 什么是开源？

  - 源代码公开？Open Source
  - 免费试用？Free Charge
  - 自由？Free.GNU

- 这很复杂！

  ![](/mobile/images/license.jpg)

- 硬件开发商不愿意将自己的代码公开，所以谷歌用了一个阴招：HAL

  > 1. 修改内核，增加一些 HAL 接口，这些代码试用 GPL 协议，完全公开
  > 2. 增加 HAL 层，调用上一步定义好的内核接口
  > 3. 在 HAL 层中定义好上层调用所需的统一 API

### 常见问题解释

1. 安卓碎片化 Android-fragmentation

   - 碎片化对攻击者更有利还是对用户更有利？
     - 难以通用攻击
     - 难以完全防御
   - iOS 还是 Android 系统应用更新快？
   - 对开发者：Android 手机型号数量、厂商数量

2. Android 和 Java 有什么关系？

   听说用 Java 就可以写 Android 应用？是的

   那 Android 执行环境用的就是 JVM 么？不是

   - Java 虚拟机
   - Dalvik 虚拟机
   - Android Runtime

   你需要了解的：

   - Java 基于堆栈，Dalvik 基于寄存器
   - 二进制代码比虚拟机执行更快
   - ART 使用了 AOT，提前将应用编译成二进制代码

   不用 Java 可以写出 Android 应用么？可以

3. 我们为什么要给应用签名？

   开发应用的最后一步，必须使用开发者的密钥签名

   * Jarsigner
   * 自行生成密钥库

   安卓应用市场 vs 苹果 AppStore

   * 开放 vs 封闭

   * 用户可以自行安装应用市场 vs 必须用内置 AppStore（企业越狱或越狱除外）

   * 可以自行下载应用自己装 vs 不能

   * 需要签名 vs 需要签名

   签名有什么功能？

   * 不打开非官方应用也能安装的限制，AOSP 也不能安装自签名应用
   * 应用干了坏事，如果是个小白，可能会从签名中注册的地址查水表
   * 应用自己验证自己的签名，放置被重打包
   * 权限管理
   * ......

   有，总比没有强，还有其他系统级别的签名——OTA 升级，某些设备的 LKM 权限管理是什么？

## 安卓安全架构
### 安卓权限管理

1. 权限申请——我开发的应用想联网、拍照、打电话、发短信。。。
   * 在应用开发时即定义好
   * AndroidManifest.xml 文件中 `<user-permission>`
   * 应用安装时，若用户同意，则永久申请成功；若不同意，应用安装失败
   * AndroidManifest 会被编译为二进制文件提升查找速度，乱码，不要介意
   * 权限存储在 `/data/system/packages.xml` 文件中
   * 以后重启手机，不需要重新加载一次
2. 权限隔离——有 `root` 就能为所欲为？
   * 自助访问控制、强制访问控制
   * PID/UID  SELinux
3. IPC——通信是刚需
   * `Binder`
   * `Intent`
   * `ContentProvider`, `Broadcast Receiver`, `Activity`
   * 眼耳鼻肤口，5 个 Sensor，但输出 6 种感觉（加速度），`onXXXSensorChanged callback` 函数在大脑中，每个人都可以随时自定义 `callback` 函数内容
   * `ContentProvider` 记忆
   * `Broadcast Receiver` 指令接受，并进行动作输出
   * `Intent` 神经递质
   * `Binder` 大脑（意识）

### 自主访问控制
## 常用概念和技术介绍

### Android 漏洞挖掘：漏洞好吃么？

漏洞类型：

- 应用漏洞 vs 系统漏洞
- Java 漏洞 vs Native 漏洞
- 内核漏洞、HAL 漏洞、Service Lib 漏洞、Framework 漏洞、应用层漏洞

思考方向：

- 攻击面
- 用户输入 -> 应用 -> Framework -> Service/Lib -> HAL -> 内核

漏洞有什么好吃的？

漏洞挖掘方法：

- Fuzz
- 人眼看
- 符号执行

### Root

名词解释：

- Root 权限 s 位
- `Bootloader`
- `Recovery`
- `Baseband`
- `Android`

Root 类型：

- 永久 Root
- 临时 Root
- 取消 Root

Root 方式：

- 直接使用 `Recovery` 刷入 `su` 和 `deamon-su`
- 使用`Bootloader` 替换 `Recovery` 之后，刷入 `su` / `deamon-su`
- 用内核漏洞 Exploit 获取 Root

### Android 漏洞利用

调试：

* IDA Pro
* GDB

Canary, DEP, ASLR

* HeapSpray
* 信息泄露漏洞
* ROP

### Android 系统启动

详见另一个 PPT

# Android 代码保护与逆向技术的对抗

1. 安卓的「钱途」

   市场占有率 > 78%

   利益丰厚

2. 应用逻辑保护技术的必要性

   * 安全问题
     * 正向：
       * 盗版、破解、恶意修改、逆向程序逻辑
       * 26.3 盗版/应用
       * 86% 恶意样本通过重打包分发
     * 反向：
       * 恶意代码隐藏、免杀
       * 手机病毒新增 1670 万，被支付类病毒感染 2505 万
       * 可无感知盗取用户资金

3. 安卓系统基础背景知识

   * Android 应用
     * Java -> class -> dex
     * smali/baksmali, dex2jar
     * 支持 JNI 调用原生代码
   * Android 系统
     * 基于 Linux
     * 权限保护：内核/用户
     * Root：非万能，MAC（SELinux）
     * TrustZone, Secure Element

## 编译与反编译

Java 层

* Java -> jvm 字节码 -> dalvik 字节码
* dex 文件 -> smali(baksmali)
* dex 文件 -> smali, 伪 Java
* dex 文件 -> Java 字节码
* Java 字节码 -> 伪 Java

Native 层

* C/C++ -> ELF (gcc g++)
* ELF -> ARM 汇编（IDA，objdump/readelf 等）
* 反编译为伪 C/C++ 代码（IDA 等）

## 加壳与脱壳

### 加固平台加固技术

* 梆梆加固、爱加密、腾讯、阿里、百度、360
* 学术界：DIVILAR 等

### 开发者自行加固

* DEX 层：与加固平台技术类似
* Native 层：关键逻辑放在原生层（.so），并使用 JNI 调用

### 加壳技术反制（脱壳）

* 针对特定加固方案的特殊对抗方案
  * 钩子技术（Hook）
    * 基于 Xposed 的 ZJDroid 等
  * Dump 内存重建 DEX
    * 需要较多手动分析
* 基于修改 Android 运行时的通用加固对抗方案
  * Android 系统本身不支持加固
  * Android 运行时收到的是正常的逻辑
  * DexHunter / AppSpear，可对抗已知所有加固平台
* DexHunter
  * 类第一次加载时，遍历所有DEX 类，加载并初始化；
  * 通过内存中数据结构定位需要获取的程序逻辑；
  * 获取程序逻辑并保存；
  * 改正并重建整个 dex 文件。
* Appspear
  * 监控 JNI 调用等加固关键指令，正确程序已释放之后；
  * 查找 dex 文件的 dds 逆向重建 dex 文件
  * 收集并打包其他信息

## 原生代码混淆与解混淆

加固平台均为 DEX 层加固技术（兼容性好）

加固强度不够 -> 原生层保护程序逻辑

* 支持指令和数据混合存放
* 支持指令修改自身的内存空间
* 支持自修改指令
* 加载、运行速度快、占用空间小

现有 Android 应用中已经大量使用原生代码

* 但是开发维护难度较大，较不适合小型开发者

### 原生代码混淆

C/C++ 源码 -> 混淆后的 ELF

混淆工具

* LLVM-Obfuscator (strong codes)
* CXX-Obfuscator 等

混淆技术

* 指令替换
* 伪造控制流
* 扁平化控制流
* 字符串混淆

### OLLVM 混淆强度分析

原生代码逆向分析技术

* 静态分析
  * 混淆后增加了很多间接跳转
  * 无法自动化简洁化逻辑
* 符号执行等动态分析
  * 由于核心代码量小，路径爆炸不严重，理论上可行
  * 暂未有相关工具
* 人工辅助逆向技术
  * 需要大量人工，难度较大
  * 简单 APK 通过系统加固后的逆向分析题目

## 隐藏与取证

Rootkit 技术

* 长老木马，PoisonCake 等
* Hook 技术修改系统文件甚至内核以隐藏自身

取证技术

* 直接修改系统，以取证
* LKM 进入内核获取动态内存
* 不支持 LKM 是否可取证？

# 题目解析

## 简单逆向类（LoopAndLoop，Timer 等）

* 直接用反编译工具看懂逻辑即可
* 有时候需要重新打包

## 加壳（Jumble 等）

* 直接逆，把逻辑看懂

## 混淆（Steady 等）

* 硬逆
* 由于 flag 取值空间小，可爆破

## 隐藏、取证

## 逆向对策

* 尽量用已有工具
  * IDA 等，时间最重要
  * 脱壳工具
* 开脑洞
* 强行逆向
  * 通用解法
  * 出题者尽力想达到的目标

# CTF 竞赛中非传统应用的逆向和加固

## 非传统应用

移动平台 + 新的开发语言 / 环境

* 原生应用（传统应用）
  * Android + Java
  * iOS + Objective C
  * iOS + Swift
  * Windows + ?
  * Linux + ?
* 非传统开发方式
  * 开发速度快
  * 跨平台
  * 安全（托管型）

![](/mobile/images/new-platform.jpg)

## CTF 竞赛中的非传统应用

* React AliCTF 2016 Mobile 300
* evilAPK AliCTF
* 360 CTF 2015 RE2

## 两个例子

* js-evaluator
* React