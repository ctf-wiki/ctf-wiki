# IE 漏洞挖掘

> 古河  
> 360 Vulcan Team  
> 2016 年 8 月 10 日

## IE Fuzz 漏洞挖掘介绍与实践
### IE UAF 漏洞
#### 引用计数
* IE objects/elements 通过引用计数管理
* 当引用计数为 0，对象内存释放或回收
* 大部分 IE UAF 漏洞成因都是引用计数处理不当。


## 内部结构
* DOM Tree
* Random Tree


逆向工程、分析样本 POC、旧版本 Windows 代码


### IE Fuzzer 设计
#### 框架
* Grinder
    * 通过 dll 注入 / Hook + JS 记录 log
    * 通过调试方法记录 crash
    * 兼容性有问题
* NodeFuzz
    * 通过 websocket 记录 log

    * 没有 crash 监控，需要自己提供



#### 方法
* 静态
    * 静态生成测试用例

    * 浏览器访问测试用例

    * 不太依赖动态 JS

    * @swan

* 动态
    * Fuzzer 本身就是一个 HTML / JS，浏览器来加载

    * Fuzzer 动态随机生成测试用例

    * 比较依赖 JS 脚本

    * Grinder / NodeFuzz / 大部分研究员



#### Log
在 Fuzzer 中，Log 的任务是忠实的记录你做的任何操作
* 精确
* 同步
* 比较好的时间：`eval + log`
    * `var statement = 'a.b(1,2,3);'`

    * `LOG(statement)`

    * `Eval(statement)`

* 在回调函数中做 Log

    * `Event Handlers`

    * `Websocket/Ajax/WebWorker`

* 在回调中做静态操作还是动态操作？


#### Crash 管理
成百上千的 crashes
大多数是空指针或栈耗尽
* 一般来讲可以忽略
* 但有一小部分是漏洞


如或过滤相同的 bugs
* Grinder
    * 通过崩溃地址/返回值组合的 hash 定位

    * 版本不同怎么办
* 更好的方式
    *  组合寄存器值



#### Idea
Idea 是最关键的
创建尽量随机 / 复杂的 DOM Tree & Render Tree
改变其中对象的状态
释放 objects
深入分析已有的漏洞
啃文档  太新的或太旧的特性
让目标更容易 crash
Windows 下 Page Heap
Linux 下 ASAN


> https://github.com/jpp-ffm/bamboo
> ndjua


## 漏洞缓解机制与对抗实例
### 控制流保护
* Windows 8.1 Preview 中加入的新安全机制


#### Control Flow Guard 原理
* 阻止不合法的间接调用
* 在程序运行时

### 对抗 Windows 平台的控制流保护


## 二进制漏洞研究工作介绍
### 挖洞是不是很难
* 并不难
    * 可以看做软件测试的一种
    * 只要有基本的计算机知识和动手能力，能够熟练查阅文档

* 难的是几个环节的持续积累和融会贯通
    * 漏洞分析
    * 漏洞挖掘
    * 漏洞利用
    * 漏洞检测

### 挖掘方法
* 逆向/调试
* 源码审计
* 动态/静态工具
* 白盒/黑盒测试，Fuzz 测试


### 如何入门和提高
*   基础很重要
    * 计算机组成原理、数据结构、操作系统
    * 汇编，高级语言
    * 调试逆向技术
*   兴趣是最好的老师
    * 找到兴趣点
*   重视实际操作
*   分析调试真实的漏洞
    * 详细分析 30 份漏洞

    * 成因、利用、为什么能找到、代入自己