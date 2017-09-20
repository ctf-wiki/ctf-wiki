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

## HCTF 2016 - 教练，我想打 CTF

给一张PNG图片，找出隐藏其中的flag。
- 工具 : Stegsolve。
- 流程 : 在Stegsolve中打开该PNG文件，点击下方的按钮选择不同的模式，发现channel 0有比较异常的变化，结合LSB的隐藏数据的原理。直接在Stegsolve中选择Analyse中的Data Extraction,按照下图的方式配置(实验发现MSB和LSB效果一样)，可以看到文件的开头是PK，得知这是一个zip文件,保存为bin文件。解压得到的压缩文件，用任意软件(记事本，IDA)发现解压出来的文件开头是ELF。在Linux下运行得到：hctf{dd0gf4c3tok3yb0ard4g41n~~~}。

![conf](/misc/picture/figure/lsb-example2.PNG)
