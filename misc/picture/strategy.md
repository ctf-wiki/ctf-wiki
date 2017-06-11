# 基本策略

下面的是一般对于图片类型挑战的基本策略，呈递进方式。

- 图片属性获取

  - `file`：文件基本属性；
  - `strings`：简单字符串；
    - **Jarvis OJ - Basic - veryeasy**

- 图片基本信息

  基本信息包括时间、地点（经纬度、地区）、人物、风景、文件属性等。可通过 Google 搜索原图、查看图片自身信息（Exif）等方法获取。

- 图片文件格式

  有时候给的文件可能本身有问题，需要我们根据文件本身的格式进行修补，可利用 010 Editor 等十六进制编辑器。

- 图片是否存在 padding

  注意文件尾信息。

  - 例题
    - tail.jpg
    - zip.jpg

- 图片隐藏信息判断

  - `binwalk`、`foremost`、`stegdetect`、`outguess`、`OurSecret`、`Jphide`等；
  - 秘钥可能是文件名、题目重点词、风景、人物等。