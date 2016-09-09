# MISC

MISC 杂项是入门 CTF 竞赛的绝佳入口，对开拓思维、培养兴趣有极大作用。

## 1 信息搜集技术

### 1.1 网络信息搜索技巧

* 公开渠道

* Google hacking

* 科学上网


### 1.2 地图和街景搜索

#### 1.2.1 物理世界中的地理位置查询

* 国外：Google map \/ earth \/ street view

* 国内：百度地图 腾讯地图 街景


#### 1.2.2 网络世界到物理世界

* ip2location

* geoip 纯真数据库


### 1.3 图片搜索


## 2 编码分析

### 2.1 通信领域常见编码

* 电话拨号编码

* Morse 编码

* 曼彻斯特、格雷


### 2.2 计算机领域常见编码

* 二进制01

* Hex

* ASCII

* base64

* Huffman Code 无损压缩编码，01串显示

* 条形码

  * 宽度不等的多个黑条和空白，按照一定的编码规则排列，用以表达一组信息的图形标识符

  * 国际标准

  * EAN-13 商品标准，13 位数字

  * Code-39: 39 字符

  * Code-128: 128 字符


* 二维码

  * 用某种特定几何图形按一定规律在平面分步的黑白相间的图形记录数据符号信息

  * 堆叠式 \/ 行排式二维码：Code 16k、Code 49、PDF417

  * 矩阵式二维码：QR CODE


  ![](http://7xry4x.com1.z0.glb.clouddn.com/16-8-13/73480917.jpg)

  ![](http://7xry4x.com1.z0.glb.clouddn.com/16-8-13/82191737.jpg)

  * QR-compatible Reed-solomon libary for python



## 3 取证分析

### 3.1 取证分析-取证对象

* 文件file

* 硬盘disk

* 网络数据包pcap

* 内存dump

* 系统镜像image


### 3.2 取证分析——文件

#### 3.2.1 文件格式分析常用命令和工具

* 基本命令 file identify strings

* winhex ue

* binwalk


#### 3.2.2 需要了解常见文件特征串

* [http:\/\/en.wikipedia.org\/wiki\/List\_of\_file\_signatures](http://en.wikipedia.org/wiki/List_of_file_signatures)

* 特别是 JPEG、PNG、GIF、BMP 等图片文件，ZIP、 RAR、TAR、7z 等压缩文件，mp3、wma、avi 等音视频文件


### 3.3 取证分析——磁盘

#### 3.3.1 磁盘分区格式

* Windows: fat12 fat16 fat32 ntfs

* Linux: ext2 ext3 ext4

* 删除文件--目录表中文件名第一字节e5


### 3.3.2 文件恢复和取证工具

* easyrecovery medanalyze ftk

### 3.4 取证分析——网络数据包

* WireShark

* 流量统计和会话列表

* 善用过滤规则，找出关注的网络流量记录

* 流重组：Follow TCP Stream

* 常见网络通信协议的理解

  * IP \/ TCP

  * UDP \/ HTTP

  * DNS


* 提取流中的文件数据


### 3.5 取证分析——内存

* Volatility 工具

* 解析内存结构

* 分析进程，内存数据


### 3.6 image镜像取证

* binwalk

## 4 隐写分析

### 4.1 隐写术

隐写载体

* 文本

* 图片

* 音频

* 视频


隐写方法和工具

* RSD、LSB、DCT

* [https:\/\/en.wikipedia.org\/wiki\/Steganography\_tools](https://en.wikipedia.org/wiki/Steganography_tools)


### 4.2 隐写分析

#### 4.2.1 识别隐写

* 统计分析

* Noise floor consistency analysis


#### 4.2.2 隐写识别工具

* stegdetect

* stegsecret

* gfe stealth


#### 4.2.3 隐写分析

[http:\/\/www.garykessler.net\/library\/fsc\_stego.html](http://www.garykessler.net/library/fsc_stego.html)

