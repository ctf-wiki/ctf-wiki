# Forensic Analysis 取证分析

## 取证对象

- 文件 file
- 硬盘 disk
- 网络数据包 pcap
- 内存 dump
- 系统镜像 image

## 文件取证

### 文件格式分析常用命令和工具

- 基本命令 `file, identify, strings`：文件类型探测、字符串检测
- WinHex UltraEdit：查看十六进制数据
- Binwalk：分析文件头

### 需要了解常见文件特征串

- [http://en.wikipedia.org/wiki/List_of_file_signatures](http://en.wikipedia.org/wiki/List_of_file_signatures)
- JPEG、PNG、GIF、BMP 等图片文件，ZIP、 RAR、TAR、7z 等压缩文件，mp3、wma、avi 等音视频文件

### 音频分析

* Audacity 查看时域、频域波形
* [在线拨号音探测](http://dialabc.com/sound/detect/)

## 磁盘取证

### 磁盘分区格式

- Windows: FAT12 -> FAT16 -> FAT32 -> NTFS

- Linux: EXT2 -> EXT3 -> EXT4

- FAT 主磁盘结构

  ![FAT 主磁盘结构](http://7xry4x.com1.z0.glb.clouddn.com/16-9-9/47521458.jpg)

- 删除文件：目录表中文件名第一字节e5

### 文件恢复和取证工具

- EasyRecovery 
- MedAnalyze
- FTK

## 网络数据包取证

- WireShark
- 流量统计和会话列表
- 善用过滤规则，找出关注的网络流量记录
- 流重组：Follow TCP Stream
- 常见网络通信协议的理解
  - IP / TCP
  - UDP / HTTP
  - DNS
- 提取流中的文件数据

## 内存取证

- Volatility 工具
- 解析 Windows / Linux / Mac OS X 内存结构
- 分析进程，内存数据
- 根据题目提示寻找线索和思路， 提取分析指定进程的特定内存数据

## 镜像取证

- Binwalk
- 根据题目提示提取镜像中需关注的文件
- 分析提取文件中的应用层数据