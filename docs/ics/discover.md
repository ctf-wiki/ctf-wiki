[EN](./discover.md) | [ZH](./discover-zh.md)
&gt; The content of this column, the content of the ICS CTF competition comes from the author&#39;s own experience in playing the game. If it is not right, please criticize and correct the teacher.




## Industrial equipment discovery


Industrial control equipment discovery is the premise of industrial control competition. At present, in the industrial control equipment scanning, a large number of tools are integrated in Nmap, Metasploit and Censes to mine current online PLC, DCS and other ICS equipment.




## Industrial Control Scan Script




### Information scanning script based on industrial control port




How to find industrial control equipment in a large number of IP, in addition to industrial control special port accidents, a large number of ports are normal services, such as ftp, ssh, telnet, smtp, ntp and other normal network services. The following list lists the current open source industrial control scan scripts.




|Port|Protocol/Device|Source|
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

| 137 | siemens wincc | sudo nmap -sU --script Siemens-WINCC.nse -p137 [host] |
|445|stuxnet|nmap --script stuxnet-detect -p 445 [host]|



The above script does not completely list the current use of script information, which is not yet to be continued...


### Component scanning method based on industrial control configuration software


Each industrial control manufacturer often comes with configuration software. When configuring the software, it can independently discover the target PLC device when connecting the devices in the current intranet.


|Port|Protocol/Device|Connection Method|
|:-----|:------|:------|

|102(TCP)|siemens s7|Siemens Software Step7 comes with scanning the current network segment PLC device function|
|502(TCP)|modbus|Schneider SoMachine Basic Connect PLC device with scanning intranet segment function|




## Industrial Control Scanning and Discovery Engine


### Shodan 擎


*Shodan is a cyberspace search engine that searches for devices, servers, cameras, industrial control devices, smart homes, etc. that exist on the Internet and can identify their version, location, port, service and other information. In 2013, Shodan added detection for industrial control protocols. Users can directly retrieve all data of the protocol using the port of the industrial control protocol. Users can also use the feature Dork to directly search for corresponding device data. *


### Zoomeye Engine


*ZoomEye is a search engine for cyberspace created by Chuangyu. ZoomEye launched the industrial control project (ics.zoomeye.org) in March 2015. ZoomEye supports data retrieval for 12 industrial control protocols. Users can also use the industrial control protocol. Ports and Features The Dork keyword finds industrial hardware and software exposed to the Internet. For industrial control protocol type data, ZoomEye enables a protection policy that cannot be viewed directly by normal users. *


### FOFA Engine


*FOFA is a cyberspace asset search engine launched by White Hat. It can help users quickly match network assets and speed up the follow-up work process. For example, vulnerability analysis scope analysis, application distribution statistics, application popularity ranking statistics, etc.*


### Diting Full Net Engine


*Ditecting cyberspace industrial control equipment search engine, to listen to the meaning of all things, is intended to search for industrial control system networking equipment exposed on the Internet, to help security manufacturers maintain industrial control system security, follow the malicious intentions. *


### Censys Full Network Engine


*Censys is a search engine that allows computer scientists to understand the devices and networks that make up the Internet. Driven by Internet-wide scanning, Censys enables researchers to find specific hosts and create configuration and deployment information for devices, websites, and certificates into a single overall report. *


The types of vulnerability engines are different, and there are big differences in configuration and deployment nodes. Currently, the search engine for industrial control is more professional with shodan and ditecting, but from the perspective of ports, each engine claims that the retrieval method is not Do the same.


### Comparison of various search engines


To be continued.....





















