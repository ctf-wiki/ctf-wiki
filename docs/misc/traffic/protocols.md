## Wireshark 常用功能介绍

### 显示过滤器

显示过滤器可以用很多不同的参数来作为匹配标准，比如IP地址、协议、端口号、某些协议头部的参数。此外，用户也用一些条件工具和串联运算符创建出更加复杂的表达式。用户可以将不同的表达式组合起来，让软件显示的数据包范围更加精确。在数据包列表面板中显示的所有数据包都可以用数据包中包含的字段进行过滤。

```
[not] Expression [and|or] [not] Expression
```

经常要用到各种运算符

| 运算符 | 说明      |
| ------ | --------- |
| ==     | 等于      |
| !=     | 不等于    |
| >      | 大于      |
| <      | 小于      |
| >=     | 大于等于  |
| <=     | 小于等于  |
| 与     | and , &&  |
| 或     | or , \|\| |
| 非     | ! , not   |

#### 配置方法

1. 借助于过滤器窗口

    ![filter_window](figure/filter_window.png)

2. 借助于工具条的输入栏

    ![filter_tool](figure/filter_tool.png)

3. 将数据包某个属性值指定为过滤条件

    ![filter_select](figure/filter_select.png)

!!! note
​    复杂的过滤命令可以直接通过第三种方式得到过滤语法

### 信息统计

#### Protocol History(协议分级)

这个窗口现实的是捕捉文件包含的所有协议的树状分支

![pro_his](figure/pro_his.png)

包含的字段

| 名称          | 含义                                           |
| ------------- | ---------------------------------------------- |
| Protocol：    | 协议名称                                       |
| % Packets：   | 含有该协议的包数目在捕捉文件所有包所占的比例   |
| Packets：     | 含有该协议的包的数目                           |
| Bytes：       | 含有该协议的字节数                             |
| Mbit/s：      | 抓包时间内的协议带宽                           |
| End Packets： | 该协议中的包的数目（作为文件中的最高协议层）   |
| End Bytes：   | 该协议中的字节数（作为文件中的最高协议层）     |
| End Mbit/s：  | 抓包时间内的协议带宽（作为文件中的最高协议层） |

这一功能可以为分析数据包的主要方向提供依据

#### Conversation(对话)

发生于一特定端点的IP间的所有流量.

![Conversation](figure/conversation.png)

!!! note
​    - 查看收发大量数据流的IP地址。如果是你知道的服务器（你记得服务器的地址或地址范围），那问题就解决了；但也有可能只是某台设备正在扫描网络，或仅是一台产生过多数据的PC。
​    - 查看扫描模式（scan pattern）。这可能是一次正常的扫描，如SNMP软件发送ping报文以查找网络，但通常扫描都不是好事情

#### EndPoints(端点)

这一工具列出了Wireshark发现的所有endpoints上的统计信息

![points](figure/points.png)

#### HTTP

- Packet Counter

    ![pac_count](figure/pac_count.png)


**参考**

- http://blog.jobbole.com/73482/
- http://www.vuln.cn/2103

### 信息统计 进阶版

根据总体信息迅速把握流量包总体特征,搞清楚 **做什么?**

TODO

## 常见协议

### HTTP/HTTPs

主要集中在流量中附件或是总体分析上,搞明白流量在做什么之后,基本可以定位到寻找flag的位置

#### HTTP

**例题**

<a href="file\hack.pcap">江苏省领航杯-2017:hack</a>

总体观察可以得出:

- `HTTP`为主
- `102.168.173.134`为主
- 不存在附件

![linghang_hack](figure/linghang_hack.png)

从这张图,基本可以判断初这是一个在`sql注入-盲注时产生的流量包`

到此为止,基本可以判断flag的方向,提取出所有的url后,用`python`辅助即可得到flag

- 提取url: `tshark -r hack.pcap -T fields  -e http.request.full_uri|tr -s '\n'|grep flag > log`

- 得到盲注结果

```python
import re

with open('log') as f:
    tmp = f.read()
    flag = ''
    data = re.findall(r'=(\d*)%23',tmp)
    data = [int(i) for i in data]
    for i,num in enumerate(data):
        try:
            if num > data[i+1]:
                flag += chr(num)
        except Exception:
            pass
    print flag
```


#### HTTPS

`HTTPs = HTTP + SSL / TLS`.服务端和客户端的信息传输都会通过TLS进行加密，所以传输的数据都是加密后的数据

- [wireshark分析HTTPs](http://www.freebuf.com/articles/system/37900.html)

**例题**:  
- [hack-dat-kiwi-ctf-2015:ssl-sniff-2](https://github.com/ctfs/write-ups-2015/tree/master/hack-dat-kiwi-ctf-2015/forensics/ssl-sniff-2)


打开流量包发现是SSL加密过的数据,导入题目提供的`server.key.insecure`,即可解密

```xml
GET /key.html HTTP/1.1
Host: localhost

HTTP/1.1 200 OK
Date: Fri, 20 Nov 2015 14:16:24 GMT
Server: Apache/2.4.7 (Ubuntu)
Last-Modified: Fri, 20 Nov 2015 14:15:54 GMT
ETag: "1c-524f98378d4e1"
Accept-Ranges: bytes
Content-Length: 28
Content-Type: text/html

The key is 39u7v25n1jxkl123
```

### FTP


### DNS

DNS通常为UDP协议,报文格式

```sh
+-------------------------------+
| 报文头                         |
+-------------------------------+
| 问题 (向服务器提出的查询部分)    |
+-------------------------------+
| 回答 (服务器回复的资源记录)      |
+-------------------------------+
| 授权 (权威的资源记录)           |
+-------------------------------+
| 格外的 (格外的资源记录)         |
+-------------------------------+
```

查询包只有头部和问题两个部分，DNS收到查询包后，根据查询到的信息追加回答信息、授权机构、额外资源记录，并且修改了包头的相关标识再返回给客户端。

每个question部分

```
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                                               |
 /                     QNAME                     /
 /                                               /
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                     QTYPE                     |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                     QCLASS                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

- QNAME：为查询的域名，是可变长的，编码格式为：将域名用.号划分为多个部分，每个部分前面加上一个字节表示该部分的长度，最后加一个0字节表示结束
- QTYPE：占16位，表示查询类型，共有16种，常用值有：1（A记录，请求主机IP地址）、2（NS，请求授权DNS服务器）、5（CNAME别名查询）



**例题**

- [BSides San Francisco CTF 2017 : dnscap-500](https://github.com/ctfs/write-ups-2017/tree/master/bsidessf-ctf-2017/forensics/dnscap-500)

- Step:

    - wireshark 打开发现全部为DNS协议,查询名为大量字符串`([\w\.]+)\.skullseclabs\.org`

    - `tshark -r dnscap.pcap -T fields -e dns.qry.name > hex`提取后，python转码

```python
import re


find = ""

with open('hex','rb') as f:
    for i in f:
        text = re.findall(r'([\w\.]+)\.skull',i)
        if text:
            find += text[0].replace('.','')
print find
```

- 发现几条关键信息

```
Welcome to dnscap! The flag is below, have fun!!
Welcome to dnscap! The flag is below, have fun!!
!command (sirvimes)
...
IHDR
gAMA
bKGD
        pHYs
IHDR
gAMA
bKGD
        pHYs
tIME
IDATx
...
2017-02-01T21:04:00-08:00
IEND
console (sirvimes)
console (sirvimes)
Good luck! That was dnscat2 traffic on a flaky connection with lots of re-transmits. Seriously,
Good luck! That was dnscat2 traffic on a flaky connection with lots of re-transmits. Seriously, d[
good luck. :)+
```
flag确实包含在其中,但是有大量重复信息,一是应为`question`在dns协议中查询和反馈时都会用到,` -Y "ip.src == 192.168.43.91"`进行过滤后发现还是有不少重复部分
```
%2A}
%2A}
%2A}q
%2A}x
%2A}
IHDR
gAMA
bKGD
        pHYs
tIME
IDATx
HBBH
CxRH!
C1%t
ceyF
i4ZI32
rP@1
ceyF
i4ZI32
rP@1
ceyF
i4ZI32
rP@1
ceyF
i4ZI32
rP@1
```

- 根据发现的`dnscat`找到 https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md 这里介绍了`dnscat`协议的相关信息,这是一种通过DNS传递数据的变种协议,题目文件中应该未使用加密,所以直接看这里的数据块信息

```
MESSAGE_TYPE_MSG: [0x01]
(uint16_t) packet_id
(uint8_t) message_type [0x01]
(uint16_t) session_id
(uint16_t) seq
(uint16_t) ack
(byte[]) data
```

- 在`qry.name`中去除其余字段,只留下`data`快,从而合并数据,再从16进制中检索`89504e.....6082`提取`png`,得到flag

```python
import re


find = []

with open('hex','rb') as f:
    for i in f:
        text = re.findall(r'([\w\.]+)\.skull',i)
        if text:
            tmp =  text[0].replace('.','')
            find.append(tmp[18:])
last = []

for i in find:
    if i not in last:
        last.append(i)


print  ''.join(last)
```

*flag*

![dnscat_flag](figure/dnscat_flag.png)



**相关题目**

- [IceCTF-2016:Search](https://mrpnkt.github.io/2016/icectf-2016-search/)
- [EIS-2017:DNS 101](https://github.com/susers/Writeups/blob/master/2017/EIS/Misc/DNS%20101/Write-up.md)

**参考**

- https://github.com/lisijie/homepage/blob/master/posts/tech/dns%E5%8D%8F%E8%AE%AE%E8%A7%A3%E6%9E%90.md
- https://xpnsec.tumblr.com/post/157479786806/bsidessf-ctf-dnscap-walkthrough

### WIFI

> 802.11是现今无线局域网通用的标准,常见认证方式
> - 不启用安全‍‍
> - WEP‍‍
> - WPA/WPA2-PSK（预共享密钥）‍‍
> - PA/WPA2 802.1X （radius认证）

#### WPA-PSK

认证大致过程如下图

![wpa-psk](figure/wpa-psk.png)

其中四次握手过程

![eapol](figure/eapol.png)

1. 4次握手开始于验证器(AP)，它产生一个随机的值(ANonce)发送给请求者
2. 请求者也产生了它自己的随机SNonce，然后用这两个Nonces以及PMK生成了PTK。请求者回复消息2给验证器,还有一个MIC（message integrity code，消息验证码）作为PMK的验证
3. 它先要验证请求者在消息2中发来的MIC等信息，验证成功后，如果需要就生成GTK。然后发送消息3
4. 请求者收到消息3，验证MIC，安装密钥，发送消息4，一个确认信息。验证器收到消息4，验证MIC，安装相同的密钥

**例题**  

- 实验吧: http://ctf5.shiyanbar.com/misc/shipin.cap

从大量的`Deauth` 攻击基本可以判断是一个破解wifi时的流量攻击

同时也成功发现了握手包信息

![shiyanba-wpa](figure/shiyanba-wpa.png)

接下来跑密码

- linux: aircrack套件
- windows: wifipr,速度比esaw快,GTX850能将近10w\s  :)

得到密码`88888888`在wireshark中`Edit -> Preferences -> Protocols -> IEEE802.11 -> Edit`以`key:SSID`形式填入即可解密wifi包看到明文流量

> KCARCK相关: https://www.krackattacks.com/

**参考**

- http://www.freebuf.com/articles/wireless/58342.html
- http://blog.csdn.net/keekjkj/article/details/46753883

### USB

**USB详述**: [http://www.usb.org/developers/hidpage/Hut1_12v2.pdf](http://www.usb.org/developers/hidpage/Hut1_12v2.pdf)


- 鼠标协议

鼠标移动时表现为连续性，与键盘击键的离散性不一样，不过实际上鼠标动作所产生的数据包也是离散的，毕竟计算机表现的连续性信息都是由大量离散信息构成的

![mouse](figure/mouse.png)

每一个数据包的数据区有四个字节，第一个字节代表按键，当取0x00时，代表没有按键、为0x01时，代表按左键，为0x02时，代表当前按键为右键。第二个字节可以看成是一个signed byte类型，其最高位为符号位，当这个值为正时，代表鼠标水平右移多少像素，为负时，代表水平左移多少像素。第三个字节与第二字节类似，代表垂直上下移动的偏移。

得到这些点的信息后,即可恢复出鼠标移动轨迹

- Tools
    - [UsbMiceDataHacker](https://github.com/WangYihang/UsbMiceDataHacker)

- 键盘协议

键盘数据包的数据长度为8个字节，击键信息集中在第3个字节

![keyboard](figure/keyboard.png)

根据data值与具体键位的对应关系

![keyboard_pro](figure/keyboard_pro.png)

可从数据包恢复出键盘的案件信息

- Tools
    - [UsbKeyboardDataHacker](https://github.com/WangYihang/UsbKeyboardDataHacker)

**参考**
- https://www.anquanke.com/post/id/85218

### 例题

> `Xman`三期夏令营排位赛练习题：`AutoKey`
>
> WP：https://www.cnblogs.com/ECJTUACM-873284962/p/9473808.html

问题描述：

![task_AutoKey](./figure/task_AutoKey.png)

这道题是我参加 `Xman` 三期夏令营选拔赛出的一道题，我们如何对其进行分析？

#### 流量包是如何捕获的？

首先我们从上面的数据包分析可以知道，这是个 `USB` 的流量包，我们可以先尝试分析一下 `USB` 的数据包是如何捕获的。

在开始前，我们先介绍一些 `USB` 的基础知识。 `USB` 有不同的规格，以下是使用 `USB` 的三种方式：

```shell
l USB UART
l USB HID
l USB Memory
```

`UART` 或者 `Universal Asynchronous Receiver/Transmitter` 。这种方式下，设备只是简单的将 `USB` 用于接受和发射数据，除此之外就再没有其他通讯功能了。

`HID` 是人性化的接口。这一类通讯适用于交互式，有这种功能的设备有：键盘，鼠标，游戏手柄和数字显示设备。

最后是 `USB Memory` ，或者说是数据存储。 `External HDD` ， `thumb drive/flash drive` 等都是这一类的。

其中使用的最广的不是 `USB HID` 就是 `USB Memory` 了。

每一个 `USB` 设备（尤其是 `HID` 或者 `Memory` ）都有一个供应商 `ID（Vendor ID）` 和产品识别码`（Product Id）` 。 `Vendor ID` 是用来标记哪个厂商生产了这个 `USB` 设备。 `Product ID` 用来标记不同的产品，他并不是一个特殊的数字，当然最好不同。如下图：

![Product-ID](./figure/Product-ID.png)

上图是我在虚拟机环境下连接在我电脑上的 `USB` 设备列表，通过 `lsusb` 查看命令。

例如说，我在 `VMware` 下有一个无线鼠标。它是属于 `HID` 设备。这个设备正常的运行，并且通过`lsusb` 这个命令查看所有 `USB` 设备，现在大家能找出哪一条是这个鼠标吗？？没有错，就是第四个，就是下面这条：

```shell
Bus 002 Device 002: ID 0e0f:0003 VMware, Inc. Virtual Mouse
```

其中，`ID 0e0f:0003` 就是 `Vendor-Product ID` 对， `Vendor ID` 的值是 `0e0f` ，并且 `Product ID` 的值是 `0003` 。 `Bus 002 Device 002` 代表 `usb` 设备正常连接，这点需要记下来。

我们用 `root` 权限运行 `Wireshark` 捕获 `USB` 数据流。但是通常来说我们不建议这么做。我们需要给用户足够的权限来获取 `Linux` 中的 `usb` 数据流。我们可以用 `udev` 来达到我们的目的。我们需要创建一个用户组 `usbmon` ，然后把我们的账户添加到这个组中。

```shell
addgroup usbmon
gpasswd -a $USER usbmon
echo 'SUBSYSTEM=="usbmon", GROUP="usbmon", MODE="640"' > /etc/udev/rules.d/99-usbmon.rules
```

接下来，我们需要 `usbmon` 内核模块。如果该模块没有被加载，我们可以通过以下命令加载该模块：

```shell
modprobe usbmon
```

打开 `wireshark` ，你会看到 `usbmonX` 其中 `X` 代表数字。下图是我们本次的结果（我使用的是`root `）：

![usbmon0](./figure/usbmon0.png)

如果接口处于活跃状态或者有数据流经过的时候， `wireshark` 的界面就会把它以波形图的方式显示出来。那么，我们该选那个呢？没有错，就是我刚刚让大家记下来的，这个X的数字就是对应这 `USB Bus` 。在本文中是 `usbmon0` 。打开他就可以观察数据包了。

![analysis-usbmon0](./figure/analysis-usbmon0.png)

通过这些，我们可以了解到 `usb` 设备与主机之间的通信过程和工作原理，我们可以来对流量包进行分析了。

#### 如何去分析一个USB流量包

根据前面的知识铺垫，我们大致对 `USB` 流量包的抓取有了一个轮廓了，下面我们介绍一下如何分析一个 `USB` 流量包。

`USB` 协议的细节方面参考 `wireshark` 的 `wiki` ：<https://wiki.wireshark.org/USB>

我们先拿 `GitHub` 上一个简单的例子开始讲起：

![example-usbpcap](./figure/example-usbpcap.png)

我们分析可以知道， `USB` 协议的数据部分在 `Leftover Capture Data` 域之中，在 `Mac` 和 `Linux` 下可以用 `tshark` 命令可以将 `leftover capture data` 单独提取出来，命令如下：

```shell
tshark -r example.pcap -T fields -e usb.capdata //如果想导入usbdata.txt文件中，后面加上参数：>usbdata.txt
```

`Windows` 下装了 `wireshark` 的环境下，在 `wireshark`目录下有个 `tshark.exe` ，比如我的在 `D:\Program Files\Wireshark\tshark.exe`

![Windows-tshark](./figure/Windows-tshark.png)

调用 `cmd` ，定位到当前目录下，输入如下命令即可：

```
tshark.exe -r example.pcap -T fields -e usb.capdata //如果想导入usbdata.txt文件中，后面加上参数：>usbdata.txt
```

有关 `tshark` 命令的详细使用参考 `wireshark` 官方文档：<https://www.wireshark.org/docs/man-pages/tshark.html>

运行命令并查看 `usbdata.txt` 发现数据包长度为八个字节

![usbdata](./figure/usbdata.png)

关于 `USB` 的特点应用我找了一张图，很清楚的反应了这个问题：

![usb-feature](./figure/usb-feature.png)

这里我们只关注 `USB` 流量中的键盘流量和鼠标流量。

键盘数据包的数据长度为 `8` 个字节，击键信息集中在第 `3` 个字节，每次 `key stroke` 都会产生一个 `keyboard event usb packet` 。

鼠标数据包的数据长度为 `4` 个字节，第一个字节代表按键，当取 `0x00` 时，代表没有按键、为0x01时，代表按左键，为 `0x02` 时，代表当前按键为右键。第二个字节可以看成是一个 `signed byte` 类型，其最高位为符号位，当这个值为正时，代表鼠标水平右移多少像素，为负时，代表水平左移多少像素。第三个字节与第二字节类似，代表垂直上下移动的偏移。

我翻阅了大量的 `USB` 协议的文档，在这里我们可以找到这个值与具体键位的对应关系：<http://www.usb.org/developers/hidpage/Hut1_12v2.pdf>

`usb keyboard` 的映射表 根据这个映射表将第三个字节取出来，对应对照表得到解码：

![keyboard_pro](./figure/keyboard_pro.png)

我们写出如下脚本：

```python
mappings = { 0x04:"A",  0x05:"B",  0x06:"C", 0x07:"D", 0x08:"E", 0x09:"F", 0x0A:"G",  0x0B:"H", 0x0C:"I",  0x0D:"J", 0x0E:"K", 0x0F:"L", 0x10:"M", 0x11:"N",0x12:"O",  0x13:"P", 0x14:"Q", 0x15:"R", 0x16:"S", 0x17:"T", 0x18:"U",0x19:"V", 0x1A:"W", 0x1B:"X", 0x1C:"Y", 0x1D:"Z", 0x1E:"1", 0x1F:"2", 0x20:"3", 0x21:"4", 0x22:"5",  0x23:"6", 0x24:"7", 0x25:"8", 0x26:"9", 0x27:"0", 0x28:"n", 0x2a:"[DEL]",  0X2B:"    ", 0x2C:" ",  0x2D:"-", 0x2E:"=", 0x2F:"[",  0x30:"]",  0x31:"\\", 0x32:"~", 0x33:";",  0x34:"'", 0x36:",",  0x37:"." }
nums = []
keys = open('usbdata.txt')
for line in keys:
    if line[0]!='0' or line[1]!='0' or line[3]!='0' or line[4]!='0' or line[9]!='0' or line[10]!='0' or line[12]!='0' or line[13]!='0' or line[15]!='0' or line[16]!='0' or line[18]!='0' or line[19]!='0' or line[21]!='0' or line[22]!='0':
         continue
    nums.append(int(line[6:8],16))
    # 00:00:xx:....
keys.close()
output = ""
for n in nums:
    if n == 0 :
        continue
    if n in mappings:
        output += mappings[n]
    else:
        output += '[unknown]'
print('output :n' + output)
```

结果如下：

![usb-solved](./figure/usb-solved.png)

我们把前面的整合成脚本，得：

```python
#!/usr/bin/env python

import sys
import os

DataFileName = "usb.dat"

presses = []

normalKeys = {"04":"a", "05":"b", "06":"c", "07":"d", "08":"e", "09":"f", "0a":"g", "0b":"h", "0c":"i", "0d":"j", "0e":"k", "0f":"l", "10":"m", "11":"n", "12":"o", "13":"p", "14":"q", "15":"r", "16":"s", "17":"t", "18":"u", "19":"v", "1a":"w", "1b":"x", "1c":"y", "1d":"z","1e":"1", "1f":"2", "20":"3", "21":"4", "22":"5", "23":"6","24":"7","25":"8","26":"9","27":"0","28":"<RET>","29":"<ESC>","2a":"<DEL>", "2b":"\t","2c":"<SPACE>","2d":"-","2e":"=","2f":"[","30":"]","31":"\\","32":"<NON>","33":";","34":"'","35":"<GA>","36":",","37":".","38":"/","39":"<CAP>","3a":"<F1>","3b":"<F2>", "3c":"<F3>","3d":"<F4>","3e":"<F5>","3f":"<F6>","40":"<F7>","41":"<F8>","42":"<F9>","43":"<F10>","44":"<F11>","45":"<F12>"}

shiftKeys = {"04":"A", "05":"B", "06":"C", "07":"D", "08":"E", "09":"F", "0a":"G", "0b":"H", "0c":"I", "0d":"J", "0e":"K", "0f":"L", "10":"M", "11":"N", "12":"O", "13":"P", "14":"Q", "15":"R", "16":"S", "17":"T", "18":"U", "19":"V", "1a":"W", "1b":"X", "1c":"Y", "1d":"Z","1e":"!", "1f":"@", "20":"#", "21":"$", "22":"%", "23":"^","24":"&","25":"*","26":"(","27":")","28":"<RET>","29":"<ESC>","2a":"<DEL>", "2b":"\t","2c":"<SPACE>","2d":"_","2e":"+","2f":"{","30":"}","31":"|","32":"<NON>","33":"\"","34":":","35":"<GA>","36":"<","37":">","38":"?","39":"<CAP>","3a":"<F1>","3b":"<F2>", "3c":"<F3>","3d":"<F4>","3e":"<F5>","3f":"<F6>","40":"<F7>","41":"<F8>","42":"<F9>","43":"<F10>","44":"<F11>","45":"<F12>"}

def main():
    # check argv
    if len(sys.argv) != 2:
        print "Usage : "
        print "        python UsbKeyboardHacker.py data.pcap"
        print "Tips : "
        print "        To use this python script , you must install the tshark first."
        print "        You can use `sudo apt-get install tshark` to install it"
        print "        Thank you for using."
        exit(1)

    # get argv
    pcapFilePath = sys.argv[1]
    
    # get data of pcap
    os.system("tshark -r %s -T fields -e usb.capdata > %s" % (pcapFilePath, DataFileName))

    # read data
    with open(DataFileName, "r") as f:
        for line in f:
            presses.append(line[0:-1])
    # handle
    result = ""
    for press in presses:
        Bytes = press.split(":")
        if Bytes[0] == "00":
            if Bytes[2] != "00":
                result += normalKeys[Bytes[2]]
        elif Bytes[0] == "20": # shift key is pressed.
            if Bytes[2] != "00":
                result += shiftKeys[Bytes[2]]
        else:
            print "[-] Unknow Key : %s" % (Bytes[0])
    print "[+] Found : %s" % (result)

    # clean the temp data
    os.system("rm ./%s" % (DataFileName))


if __name__ == "__main__":
    main()
```

效果如下：

![example-solved](./figure/example-solved.png)

另外贴上一份鼠标流量数据包转换脚本：

```python
nums = [] 
keys = open('usbdata.txt','r') 
posx = 0 
posy = 0 
for line in keys: 
if len(line) != 12 : 
     continue 
x = int(line[3:5],16) 
y = int(line[6:8],16) 
if x > 127 : 
    x -= 256 
if y > 127 : 
    y -= 256 
posx += x 
posy += y 
btn_flag = int(line[0:2],16)  # 1 for left , 2 for right , 0 for nothing 
if btn_flag == 1 : 
    print posx , posy 
keys.close()
```

键盘流量数据包转换脚本如下：

```python
nums=[0x66,0x30,0x39,0x65,0x35,0x34,0x63,0x31,0x62,0x61,0x64,0x32,0x78,0x33,0x38,0x6d,0x76,0x79,0x67,0x37,0x77,0x7a,0x6c,0x73,0x75,0x68,0x6b,0x69,0x6a,0x6e,0x6f,0x70]
s=''
for x in nums:
    s+=chr(x)
print s
mappings = { 0x41:"A",  0x42:"B",  0x43:"C", 0x44:"D", 0x45:"E", 0x46:"F", 0x47:"G",  0x48:"H", 0x49:"I",  0x4a:"J", 0x4b:"K", 0x4c:"L", 0x4d:"M", 0x4e:"N",0x4f:"O",  0x50:"P", 0x51:"Q", 0x52:"R", 0x53:"S", 0x54:"T", 0x55:"U",0x56:"V", 0x57:"W", 0x58:"X", 0x59:"Y", 0x5a:"Z", 0x60:"0", 0x61:"1", 0x62:"2", 0x63:"3", 0x64:"4",  0x65:"5", 0x66:"6", 0x67:"7", 0x68:"8", 0x69:"9", 0x6a:"*", 0x6b:"+",  0X6c:"separator", 0x6d:"-",  0x6e:".", 0x6f:"/" }
output = ""
for n in nums:
    if n == 0 :
        continue
    if n in mappings:
        output += mappings[n]
    else:
        output += '[unknown]'
print 'output :\n' + output
```

那么对于 `xman` 三期夏令营排位赛的这道题，我们可以模仿尝试如上这个例子：

首先我们通过 `tshark` 将 `usb.capdata` 全部导出：

```shell
tshark -r task_AutoKey.pcapng -T fields -e usb.capdata //如果想导入usbdata.txt文件中，后面加上参数：>usbdata.txt
```

结果如下：

![tshark-task_AutoKey](./figure/tshark-task_AutoKey.png)

我们用上面的 `python` 脚本将第三个字节取出来，对应对照表得到解码：

```python
mappings = { 0x04:"A",  0x05:"B",  0x06:"C", 0x07:"D", 0x08:"E", 0x09:"F", 0x0A:"G",  0x0B:"H", 0x0C:"I",  0x0D:"J", 0x0E:"K", 0x0F:"L", 0x10:"M", 0x11:"N",0x12:"O",  0x13:"P", 0x14:"Q", 0x15:"R", 0x16:"S", 0x17:"T", 0x18:"U",0x19:"V", 0x1A:"W", 0x1B:"X", 0x1C:"Y", 0x1D:"Z", 0x1E:"1", 0x1F:"2", 0x20:"3", 0x21:"4", 0x22:"5",  0x23:"6", 0x24:"7", 0x25:"8", 0x26:"9", 0x27:"0", 0x28:"n", 0x2a:"[DEL]",  0X2B:"    ", 0x2C:" ",  0x2D:"-", 0x2E:"=", 0x2F:"[",  0x30:"]",  0x31:"\\", 0x32:"~", 0x33:";",  0x34:"'", 0x36:",",  0x37:"." }
nums = []
keys = open('usbdata.txt')
for line in keys:
    if line[0]!='0' or line[1]!='0' or line[3]!='0' or line[4]!='0' or line[9]!='0' or line[10]!='0' or line[12]!='0' or line[13]!='0' or line[15]!='0' or line[16]!='0' or line[18]!='0' or line[19]!='0' or line[21]!='0' or line[22]!='0':
         continue
    nums.append(int(line[6:8],16))
    # 00:00:xx:....
keys.close()
output = ""
for n in nums:
    if n == 0 :
        continue
    if n in mappings:
        output += mappings[n]
    else:
        output += '[unknown]'
print('output :n' + output)
```

运行结果如下：

![task_AutoKey-solved](./figure/task_AutoKey-solved.png)

```shell
output :n[unknown]A[unknown]UTOKEY''.DECIPHER'[unknown]MPLRVFFCZEYOUJFJKYBXGZVDGQAURKXZOLKOLVTUFBLRNJESQITWAHXNSIJXPNMPLSHCJBTYHZEALOGVIAAISSPLFHLFSWFEHJNCRWHTINSMAMBVEXO[DEL]PZE[DEL]IZ'
```

我们可以看出这是自动密匙解码，现在的问题是在我们不知道密钥的情况下应该如何解码呢？

我找到了如下这篇关于如何爆破密匙：<http://www.practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-autokey-cipher/>

爆破脚本如下：

```python
from ngram_score import ngram_score
from pycipher import Autokey
import re
from itertools import permutations

qgram = ngram_score('quadgrams.txt')
trigram = ngram_score('trigrams.txt')

ctext = 'MPLRVFFCZEYOUJFJKYBXGZVDGQAURKXZOLKOLVTUFBLRNJESQITWAHXNSIJXPNMPLSHCJBTYHZEALOGVIAAISSPLFHLFSWFEHJNCRWHTINSMAMBVEXPZIZ'

ctext = re.sub(r'[^A-Z]','',ctext.upper())
# keep a list of the N best things we have seen, discard anything else

class nbest(object):
    def __init__(self,N=1000):
        self.store = []
        self.N = N

    def add(self,item):
        self.store.append(item)
        self.store.sort(reverse=True)
        self.store = self.store[:self.N]

    def __getitem__(self,k):
        return self.store[k]

    def __len__(self):
        return len(self.store)
        
#init
N=100
for KLEN in range(3,20):
    rec = nbest(N)
    for i in permutations('ABCDEFGHIJKLMNOPQRSTUVWXYZ',3):
        key = ''.join(i) + 'A'*(KLEN-len(i))
        pt = Autokey(key).decipher(ctext)
        score = 0
        for j in range(0,len(ctext),KLEN):
            score += trigram.score(pt[j:j+3])
        rec.add((score,''.join(i),pt[:30]))

    next_rec = nbest(N)
    for i in range(0,KLEN-3):
        for k in xrange(N):
            for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                key = rec[k][1] + c
                fullkey = key + 'A'*(KLEN-len(key))
                pt = Autokey(fullkey).decipher(ctext)
                score = 0
                for j in range(0,len(ctext),KLEN):
                    score += qgram.score(pt[j:j+len(key)])
                next_rec.add((score,key,pt[:30]))
        rec = next_rec
        next_rec = nbest(N)
    bestkey = rec[0][1]
    pt = Autokey(bestkey).decipher(ctext)
    bestscore = qgram.score(pt)
    for i in range(N):
        pt = Autokey(rec[i][1]).decipher(ctext)
        score = qgram.score(pt)
        if score > bestscore:
            bestkey = rec[i][1]
            bestscore = score       
    print bestscore,'autokey, klen',KLEN,':"'+bestkey+'",',Autokey(bestkey).decipher(ctext)
```

跑出来的结果如下：

![usbpwn](./figure/usbpwn.png)

我们看到了 `flag` 的字样，整理可得如下：

```shell
-674.914569565 autokey, klen 8 :"FLAGHERE", HELLOBOYSANDGIRLSYOUARESOSMARTTHATYOUCANFINDTHEFLAGTHATIHIDEINTHEKEYBOARDPACKAGEFLAGISJHAWLZKEWXHNCDHSLWBAQJTUQZDXZQPF
```

我们把字段进行分割看：

```shell
HELLO
BOYS
AND
GIRLS
YOU
ARE
SO
SMART
THAT
YOU
CAN
FIND
THE
FLAG
THAT
IH
IDE
IN
THE
KEY
BOARD
PACKAGE
FLAG
IS
JHAWLZKEWXHNCDHSLWBAQJTUQZDXZQPF
```

最后的 `flag` 就是 `flag{JHAWLZKEWXHNCDHSLWBAQJTUQZDXZQPF}` 

### 参考文献

- https://www.cnblogs.com/ECJTUACM-873284962/p/9473808.html
- https://blog.csdn.net/songze_lee/article/details/77658094
- https://wiki.wireshark.org/USB
- http://www.usb.org/developers/hidpage/Hut1_12v2.pdf
- https://www.wireshark.org/docs/man-pages/tshark.html
- http://www.practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-autokey-cipher/
- https://hackfun.org/2017/02/22/CTF%E4%B8%AD%E9%82%A3%E4%BA%9B%E8%84%91%E6%B4%9E%E5%A4%A7%E5%BC%80%E7%9A%84%E7%BC%96%E7%A0%81%E5%92%8C%E5%8A%A0%E5%AF%86/