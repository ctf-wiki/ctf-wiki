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
- JPEG、PNG、GIF、BMP 等图片文件，ZIP、RAR、TAR、7 z 等压缩文件，mp3、wma、avi 等音视频文件

## 镜像取证

- Binwalk
- 根据题目提示提取镜像中需关注的文件
- 分析提取文件中的应用层数据