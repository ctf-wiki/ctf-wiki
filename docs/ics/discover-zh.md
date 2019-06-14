[EN](./discover.md) | [ZH](./discover-zh.md)
> 本栏目内容，ICS CTF竞赛内容来自于作者自身打比赛经验，如果不对之处，请各位老师批评指正


## 工控设备发现

工控设备发现是工控比赛的前提，目前针对工控设备扫描中，在Nmap、Metasploit、Censes集成了大量的工具，用于挖掘当前在线PLC、DCS等ICS设备。


## 工控扫描脚本


### 基于工控端口的信息扫描脚本


在大量IP中如何发现工控设备,除了工控特殊端口意外，大量端口都是正常服务，例如ftp、ssh、telnet、smtp、ntp等正常网络服务。下面列表列举了当前可以利用开源工控扫描脚本。


|端口|协议/设备|来源|
|:-----|:------|:------|
|102(TCP)|siemens s7|nmap --script s7-info.nse -p 102 [host] <br>nmap -sP --script      s71200-enumerate-old.nse -p 102 [host]|
|502(TCP)|modbus|nmap --script modicon-info -p 502 [host]|
|2404(TCP)|IEC 60870-5-104|nmap -Pn -n -d --script iec-identify.nse  --script-args='iec-identify.timeout=500' -p 2404 [host]|
|20000(TCP)|DNP3|nmap -sT --script dnp3-enumerate.nse -p 20000 [host] <br>nmap --script dnp3-info -p 20000 [host]|
|44818(TCP)|Ethernet/IP|nmap --script enip-enumerate -sU  -p 44818 [host]|
|47808(UDP)|BACnet|nmap --script BACnet-discover-enumerate.nse -sU  -p 47808 [host]|
|1911(TCP)|Tridium Nixagara Fo|nmap --script fox-info.nse -p 1911 [host]|
|789(TCP)|Crimson V3|nmap --scripts cr3-fingerprint.nse -p 789 [host]|
|9600(TCP)|OMRON FINS|nmap --script ormontcp-info -p 9600 [host]|
|1962 (TCP)|PCWorx|nmap --script pcworx-info -p 1962 [host]|
|20547(TCP)|ProConOs|nmap --script proconos-info -p 20547 [host]|
|5007(TCP)|Melsec-Q|nmap -script melsecq-discover -sT -p 5007 [host]|
|5006|Melsec-Q|nmap -script melsecq-discover-udp.nse -sU -p 5006 [host]|
|956(TCP)|CSPV4|Unknown|
|4840(TCP)|OPCUA|Unknown|
|18245(TCP)|GE SRTP|Unknown|
|1200(TCP)|Codesys|nmap –script codesys-v2-discover.nse [host]|
|10001|atg|nmap --script atg-info -p 10001 [host]|
|2222|cspv4|nmap --script cspv4-info -p 2222 [host]|
|1911|fox|nmap --script fox-info.nse -p 1911 [host]|
|4800|moxa|nmap -sU --script moxa-enum -p 4800 [host]|
|137|siemens wincc|sudo nmap -sU --script Siemens-WINCC.nse -p137 [host]|
|445|stuxnet|nmap --script stuxnet-detect -p 445 [host]|

上述脚本并未完全整列了当前能够使用脚本信息，未完待续中......

### 基于工控组态软件的组件扫描方法

各工控厂商往往自带组态软件，组态软件时连接当前内网内设备时可自主发现目标PLC设备

|端口|协议/设备|连接方法|
|:-----|:------|:------|
|102(TCP)|siemens s7|西门子软件Step7 自带扫描当前网段PLC设备功能|
|502(TCP)|modbus|施耐德SoMachine Basic 连接PLC设备自带扫描内网网段功能|


## 工控扫描与发现引擎

### Shodan 引擎

*Shodan是一款网络空间搜索引擎，主要搜索的是存在于互联网中的设备，服务器、摄像头、工控设备、智能家居等，并且可以识别出其版本，位置，端口，服务等信息。Shodan于2013年增加了针对工控协议的探测，用户可以直接使用工控协议的端口直接检索该协议的所有数据，用户也可以使用特征Dork直接搜索对应设备数据。*

### Zoomeye 引擎

*ZoomEye是知道创宇打造的面向网络空间的搜索引擎，ZoomEye于2015年3月上线了工控专题(ics.zoomeye.org)，ZoomEye支持12种工控协议的数据检索，使用者也可以使用工控协议的端口和特征Dork关键字发现暴露在互联网的工控软硬件，对于工控协议类型的数据，ZoomEye启用了保护策略，一般用户无法直接查看。*

### FOFA 引擎

*FOFA是白帽汇推出的一款网络空间资产搜索引擎。它能够帮助用户迅速进行网络资产匹配、加快后续工作进程。例如进行漏洞影响范围分析、应用分布统计、应用流行度排名统计等*

### Diting 全网引擎

*谛听(ditecting)网络空间工控设备搜索引擎，取谛听辨识万物之意，意在搜寻暴露在互联网上的工业控制系统联网设备， 帮助安全厂家维护工控系统安全、循迹恶意企图人士。*

### Censys 全网引擎

*Censys是一款搜索引擎，它允许计算机科学家了解组成互联网的设备和网络。Censys由因特网范围扫描驱动，它使得研究人员能够找到特定的主机，并能够针将设备、网站和证书的配置和部署信息创建到一个总体报告中。*

各类漏洞引擎内容不同，采取配置、部署节点等存在较大的差异，目前针对工控这块的搜索引擎以shodan和ditecting更为专业，但是从针对端口来看，各个引擎宣称的公布检索方式不尽相同。

### 各搜索引擎对比

未完待续.....











