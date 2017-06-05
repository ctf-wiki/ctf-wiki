# 磁盘&内存

# 工具

- EasyRecovery 
- MedAnalyze
- FTK
- Elcomsoft Forensic Disk Decryptor
- Volatility 

# 磁盘

## 介绍

常见的磁盘分区格式有以下几种

- Windows: FAT12 -> FAT16 -> FAT32 -> NTFS

- Linux: EXT2 -> EXT3 -> EXT4

- FAT 主磁盘结构

  ![FAT 主磁盘结构](/misc/disk/figure/forensic-filesys.jpg)

- 删除文件：目录表中文件名第一字节 e5

## vmdk

### 介绍

vmdk文件它本质上是物理硬盘的虚拟版，也会存在跟物理硬盘的分区和扇区中类似的填充区域，我们可以利用这些填充区域来把我们需要隐藏的数据隐藏到里面去，这样可以避免隐藏的文件增加了vmdk文件的大小(如直接附加到文件后端)，也可以避免由于vmdk文件大小的改变所带来的可能导致的虚拟机错误。而且vmdk文件一般比较大，适合用于隐藏大文件。

# 内存

- 解析 Windows / Linux / Mac OS X 内存结构
- 分析进程，内存数据
- 根据题目提示寻找线索和思路，提取分析指定进程的特定内存数据

# 题目

- jarvisoj misc 取证2

# 参考

- http://wooyun.jozxing.cc/static/drops/tips-12614.html