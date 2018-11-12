## PCAP文件结构

一般来说,对于 `PCAP` 文件格式考察较少，且通常都能借助于现成的工具如 `pcapfix` 直接修复，这里大致介绍下几个常见的块，详细可以翻看[Here](http://www.tcpdump.org/pcap/pcap.html)。

- Tools
    - [PcapFix Online](https://f00l.de/hacking/pcapfix.php)
    - [PcapFix](https://github.com/Rup0rt/pcapfix/tree/devel)

一般文件结构

```shell
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Block Type                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                          Block Body                           /
   /          /* variable length, aligned to 32 bits */            /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

目前所定义的常见块类型有

1. Section Header Block: it defines the most important characteristics of the capture file.
2. Interface Description Block: it defines the most important characteristics of the interface(s) used for capturing traffic.
3. Packet Block: it contains a single captured packet, or a portion of it.
4. Simple Packet Block: it contains a single captured packet, or a portion of it, with only a minimal set of information about it.
5. Name Resolution Block: it defines the mapping from numeric addresses present in the packet dump and the canonical name counterpart.
6. Capture Statistics Block: it defines how to store some statistical data (e.g. packet dropped, etc) which can be useful to undestand the conditions in which the capture has been made.

## 常见块

### Section Header BlocK(文件头)

必须存在,意味着文件的开始

```shell
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Byte-Order Magic (0x1A2B3C4D)                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Major Version(主版本号)   |    Minor Version(次版本号)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                          Section Length                       |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Interface Description Block(接口描述)

必须存在,描述接口特性

```shell
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           LinkType            |           Reserved            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  SnapLen(每个数据包最大字节数)                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Packet Block(数据块)

```sh
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Interface ID          |          Drops Count          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Timestamp (High)   标准的Unix格式          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Timestamp (Low)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Captured Len                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Packet Len                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                          Packet Data                          /
   /          /* variable length, aligned to 32 bits */            /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                      Options (variable)                       /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## 例题

> 题目：第一届“百度杯”信息安全攻防总决赛 线上选拔赛：find the flag
>
> WP：https://www.cnblogs.com/ECJTUACM-873284962/p/9884447.html

首先我们拿到这样一道流量包的题目，题目名称为 `find the flag` 。这里面给了很多提示信息，要我们去找到 `flag` 。

**第一步，搜索 `flag` 字样**

我们先去搜索看看流量包里面有没有 `flag` 。我们使用 `strings` 命令去找一下流量包， `Windows` 的朋友可以用 `notepad++` 的搜索功能去寻找。

搜索命令如下：

```shell
strings findtheflag.cap | grep flag
```

搜索结果如下：

![strings-to-flag](./figure/strings-to-flag.png)

我们发现搜出了一大堆的东西，我们通过管道去过滤出 `flag` 信息，似乎没有发现我们所需要找的答案。

**第二步，流量包修复**

我们用 `wireshark` 打开这个流量包

![wireshark-to-error](./figure/wireshark-to-error.png)

我们发现这个流量包出现了异常现象，我们可以修复一下这个流量包。

这里我们用到一个在线工具：http://f00l.de/hacking/pcapfix.php

这个工具可以帮助我们快速地将其流量包修复为 `pcap` 包。

我们对其进行在线修复。

![repaire-to-pcap](./figure/repaire-to-pcap.png)

修复完毕后点击 `Get your repaired PCAP-file here.` 即可下载流量包，然后我们用 `wireshark` 打开。

既然还是要找 `flag` ，我们可以先看看这个流量包。

**第三步，追踪TCP流**

我们追踪一下TCP流，看看有没有什么突破？

![wireshark-to-stream](./figure/wireshark-to-stream.png)

我们通过追踪 `TCP` 流，可以看到一些版本信息， `cookie` 等等，我们还是发现了一些很有意思的东西。

从 `tcp.stream eq 29` 到 `tcp.stream eq 41` 只显示了 `where is the flag?` 这个字样，难道这是出题人在告诉我们 `flag` 在这里嘛？

**第四步，查找分组字节流**

我们追踪到 `tcp.stream eq 29` 的时候，在 `Identification` 信息中看到了 `flag` 中的 `lf` 字样，我们可以继续追踪下一个流，在 `tcp.stream eq 30` 的 `Identification` 信息中看到了 `flag` 中的 `ga` 字样，我们发现将两个包中 `Identification` 信息对应的字段从右至左组合，恰好就是 `flag` ！于是我们可以大胆地猜测， `flag` 肯定是藏在这里面。

我们直接通过搜索->字符串搜索->分组字节流->搜索关键字 `flag` 即可，按照同样的方式连接后面相连数据包的 `Identification` 信息对应的字段，即可找到最终的flag！

下面是搜索的截图：

![find-the-flag](./figure/find-the-flag-01.png)

![find-the-flag](./figure/find-the-flag-02.png)

![find-the-flag](./figure/find-the-flag-03.png)

![find-the-flag](./figure/find-the-flag-04.png)

![find-the-flag](./figure/find-the-flag-05.png)

![find-the-flag](./figure/find-the-flag-06.png)

![find-the-flag](./figure/find-the-flag-07.png)

![find-the-flag](./figure/find-the-flag-08.png)

![find-the-flag](./figure/find-the-flag-09.png)

![find-the-flag](./figure/find-the-flag-10.png)

![find-the-flag](./figure/find-the-flag-11.png)

![find-the-flag](./figure/find-the-flag-12.png)

所以最终的 `flag` 为：**flag{aha!_you_found_it!}**

## 参考文献

- http://www.tcpdump.org/pcap/pcap.html
- https://zhuanlan.zhihu.com/p/27470338
- https://www.cnblogs.com/ECJTUACM-873284962/p/9884447.html



