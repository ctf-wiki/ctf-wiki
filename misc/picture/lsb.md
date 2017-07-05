## 原理

对于无损压缩图片来说，每一种颜色用八位来表示，LSB 隐写就是修改了像素中最低的一个比特位，而这样的修改对于人眼来说是看不出来的，所以借助这样的策略就可以隐写信息。常见的无损压缩图片有

- PNG 图片
- BMP 图片

下面的方式展示了如何隐写 A。

![lsb隐写](/misc/picture/figure/lsb-intro.png)

![](/misc/picture/figure/lsb-fora.png)

!> 注意：LSB 无法对 JPG 图片进行隐写，因为 JPG 图片是有损压缩的。

## 基本思路

利用 Stegsolve 打开图片之后依次打开一点一点点击，关注每一个通道的最低位，即 plane 0，看是否有异常

- 数据提取目录下依次选择 Red、Green、Blue 三个通道的最低位，然后勾选右侧的 LSB First。
- 保存为 bin 文件

## 题目

- lsb.png
- HCTF 2016 - 教练，我想打 CTF