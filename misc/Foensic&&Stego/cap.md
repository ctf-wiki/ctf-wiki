分析流量需要对一些常用的协议有简单的了解。

- IP / TCP
- UDP / TCP
- DNS
- HTTP / HTTPS

## 基本工具

- [Wireshark](http://tools.40huo.cn/#!web.md#抓包)

### 技巧

- 统计流量，以便于知道该流量包主要利用了哪些协议。
- `ip contains "xxx"`，过滤内容
- 流重组：Follow TCP Stream。
- 提取流中的文件数据。

## 常见题型

- 直接包含 flag

直接使用 Wireshark 的过滤条件，`ip contains "flag"`。之所以会选择 IP，是因为信息一般要么走 UDP 要么走 TCP，都会封装到 IP 段。
- WiFi 包

  使用 aircrack 破解，[可用的字典](https://github.com/berzerk0/Probable-Wordlists)。或使用 [Elcomsoft Wireless Security Auditor](http://tools.40huo.cn/#!MISC.md#无线密码) 破解。


## 题目

- CFF 2016 简单网管协议
  - Jarvis OJ - MISC - 简单网管协议
- CFF 2016 远程登录协议
  - Jarvis OJ - MISC - 远程登录协议
- CFF 2016 Structs 漏洞
  - Jarvis OJ - MISC - Structs 漏洞
- Jarvis OJ - Basic - 握手包