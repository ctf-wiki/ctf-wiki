# 介绍

对于cap来说，一般就是分析流量，然后获取相关的信息。需要对一些常用的协议有简单的了解

- IP/TCP
- UDP/TCP
- DNS

# 基本工具

## wireshark

### 技巧

- 统计流量，以便于知道该流量包主要利用了哪些协议。
- ip contains “xxx”，过滤内容
- 流重组：Follow TCP Stream。
- 提取流中的文件数据。

# 类型1-直接包含flag

- 直接使用wireshark的过滤条件
  - ip contains "flag"
  - 之所以会选择ip，是因为信息一般要么走UDP要么走TCP，都会封装到ip段。

# 类型2-wifi包

使用aircrack 破解。可用的字典参见

- https://github.com/berzerk0/Probable-Wordlists



# 题目

- CFF2016 简单网管协议
  - jarvisoj misc 简单网管协议
- CFF2016 远程登录协议
  - jarvisoj misc 远程登录协议
- CFF2016 Structs漏洞
  - jarvisoj misc structs漏洞
- jarvisoj-basic-握手包