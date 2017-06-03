# XMan 计算机软件攻防对抗技术

> yuange  
> 真名：袁仁广  
> 腾讯湛卢实验室总监  
> 2016 年 8 月 16 日

## 病毒对抗技术

* 幽灵病毒
  * 变形对抗特征码查杀，现在缓冲溢出 shellcode 编码
* DIR-2 病毒
  * 修改文件目录中文件入口表对抗
  * 用读命令代替写命令，拦截 int 13 配合
* 清华大学发现的不知名病毒
  * 拦截 int 13 指向 BIOS 区 CD XX 指令地址，最早的 ROP

## 磁盘加解密对抗

* 拦截 int 13 对抗，指向 BIOS 区 CD XX 指令地址，最早的 ROP
* 拦截 DMA 硬件完成中断
  * 程序代码流程中的另一条隐蔽线
  * 利用异常结构链突破堆栈溢出保护，思路来源于此

## 对抗防火墙

* 数据通道技术
  * client <--> proxy <--> firewall <--> server
* ecb
  * ecb -> ReadClient
  * ecb -> WriteClient
* 查找 socket
  * getpeername 查找 socket
  * 字串匹配查找 socket
* 有线程 recv 的处理技术
  * wins
    * shellcode hook close socket
    * exploit 发送错误数据，server 关闭 socket，shellcode 拦截
  * rpc 的端口复用技术
    * shellcode hook 服务的 rpcnum 入口
    * exploit 调用 NdrSendReceive

## 对抗 IDS

* shellcode 编码框架
  * 解决了 shellcode 的非法字符问题，又对抗了 IDS、URLSCAN 等
* 注意利用解释型语言与 CPU 代码相结合的新型病毒

## 对抗 WEB 保护

* 内存 hook 技术
  * 拦截 socket 调用，直接内存返回修改页面
* ecb
  * ecb -> ReadClient
  * ecb -> WriteClient

## XP 挑战赛对抗沙箱

```assembly
mov ebx,0x40
mov eax,[edi+ebx]
mov ecx,[esi+ebx]
mov [esi+ebx],eax    //替换 token
mov dword ptr [esi-4],0    //原有代码加一句 PID=0 过沙箱
```

## APT 对抗时代

* 对抗 DEP + ASLR + EMET + CFI
* 如何对抗 ANTI APT 设备
  * 无关键代码缓存
  * 无事后关键代码追踪线索
  * 旁路无法分析关键代码

## APT 高级漏洞利用技术

* DVE 数据虚拟执行技术
* 原理，97 年两篇文章
  * 《注意利用解释型语言与 CPU 代码结合的新型病毒》
  * 《文本病毒（病毒新理论）》
* 解释执行也是执行
* 利用漏洞增强指令集
* 构造指针突破解释执行虚拟机
* 远程代码执行转换成本地提权突破

## 具体利用实现细节

* 通过漏洞修改 vartype vt
* 修改 vt 后需要的数组，c / c++ 指针
* 通过数组修改关键数据
* 通过修改保护模式实现控件加载
* 通过控件实现完全控制
* 脚本就是 shellcode