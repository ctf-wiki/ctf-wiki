# ICS_CTF 發現

> 本欄目內容，ICS CTF競賽內容來自於作者自身打比賽經驗，如果不對之處，請各位老師批評指正


## 工控設備發現

工控設備發現是工控比賽的前提，目前針對工控設備掃描中，在Nmap、Metasploit、Censes集成了大量的工具，用於挖掘當前在線PLC、DCS等ICS設備。


## 工控掃描腳本


### 基於工控端口的信息掃描腳本


在大量IP中如何發現工控設備,除了工控特殊端口意外，大量端口都是正常服務，例如ftp、ssh、telnet、smtp、ntp等正常網絡服務。下面列表列舉了當前可以利用開源工控掃描腳本。


|端口|協議/設備|來源|
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

上述腳本並未完全整列了當前能夠使用腳本信息，未完待續中......

### 基於工控組態軟件的組件掃描方法

各工控廠商往往自帶組態軟件，組態軟件時連接當前內網內設備時可自主發現目標PLC設備

|端口|協議/設備|連接方法|
|:-----|:------|:------|
|102(TCP)|siemens s7|西門子軟件Step7 自帶掃描當前網段PLC設備功能|
|502(TCP)|modbus|施耐德SoMachine Basic 連接PLC設備自帶掃描內網網段功能|


## 工控掃描與發現引擎

### Shodan 引擎

*Shodan是一款網絡空間搜索引擎，主要搜索的是存在於互聯網中的設備，服務器、攝像頭、工控設備、智能家居等，並且可以識別出其版本，位置，端口，服務等信息。Shodan於2013年增加了針對工控協議的探測，用戶可以直接使用工控協議的端口直接檢索該協議的所有數據，用戶也可以使用特徵Dork直接搜索對應設備數據。*

### Zoomeye 引擎

*ZoomEye是知道創宇打造的面向網絡空間的搜索引擎，ZoomEye於2015年3月上線了工控專題(ics.zoomeye.org)，ZoomEye支持12種工控協議的數據檢索，使用者也可以使用工控協議的端口和特徵Dork關鍵字發現暴露在互聯網的工控軟硬件，對於工控協議類型的數據，ZoomEye啓用了保護策略，一般用戶無法直接查看。*

### FOFA 引擎

*FOFA是白帽匯推出的一款網絡空間資產搜索引擎。它能夠幫助用戶迅速進行網絡資產匹配、加快後續工作進程。例如進行漏洞影響範圍分析、應用分佈統計、應用流行度排名統計等*

### Diting 全網引擎

*諦聽(ditecting)網絡空間工控設備搜索引擎，取諦聽辨識萬物之意，意在搜尋暴露在互聯網上的工業控制系統聯網設備， 幫助安全廠家維護工控系統安全、循跡惡意企圖人士。*

### Censys 全網引擎

*Censys是一款搜索引擎，它允許計算機科學家瞭解組成互聯網的設備和網絡。Censys由因特網範圍掃描驅動，它使得研究人員能夠找到特定的主機，並能夠針將設備、網站和證書的配置和部署信息創建到一個總體報告中。*

各類漏洞引擎內容不同，採取配置、部署節點等存在較大的差異，目前針對工控這塊的搜索引擎以shodan和ditecting更爲專業，但是從針對端口來看，各個引擎宣稱的公佈檢索方式不盡相同。

### 各搜索引擎對比

未完待續.....











