# 环境搭建
这篇主要介绍一下怎么搭建运行和调试 arm binary 的环境(基于 qemu, 方法同样也适用于 mips 的 binary), 使用了 jarvis OJ typo(arm)/add(mips) 两道题目的 binary 进行演示

## 主机信息：
以一台新装的 deepin 虚拟机(基于 debian)为例，详细信息如下：
![](http://ww1.sinaimg.cn/large/006AWYXBly1fq5av617a5j30lq0bu78m.jpg)

## 预备环境安装：
- 安装 git，gdb 和 gdb-multiarch，同时安装 binfmt 用来识别文件类型

```bash
$ sudo apt-get update
$ sudo apt-get install git gdb gdb-multiarch
$ sudo apt-get install "binfmt*"
```

- 安装 gdb 的插件 pwndbg（或者 gef 等 gdb plugin）
```bash
$ git clone https://github.com/pwndbg/pwndbg
$ cd pwndbg
$ ./setup.sh
```
装好之后如图：
![](http://ww1.sinaimg.cn/large/006AWYXBly1fq5c1vzla8j30nb04t75m.jpg)

- 安装pwntools，不必要，但绝对是写exp的神器
  ```bash
  $ sudo pip install pwntools
  ```

## 安装qemu：
我们对版本的要求不是很严格, 直接通过 apt 等包管理安装即可
```bash
$ sudo apt-get install qemu-user
```
通过 qemu 模拟 arm/mips 环境，进而进行运行和调试

## 安装共享库：
此时已经可以运行静态链接的 arm/mips binary 了，如下图：
![](http://ww1.sinaimg.cn/large/006AWYXBly1fq5crjvp5dj31400p0ngj.jpg)
但还不能运行动态链接的 binary，如下图：
![](http://ww1.sinaimg.cn/large/006AWYXBly1fq5csjo38rj313o05i779.jpg)
这就需要我们安装对应架构的共享库，可以通过如下命令搜索：
```bash
$ apt-cache search "libc6" | grep ARCH
```
![](http://ww1.sinaimg.cn/large/006AWYXBly1fq5cudid7gj30xy0h7trd.jpg)
我们只需安装类似 **libc6-ARCH-cross** 形式的即可

## 运行：
- 静态链接的 binary 直接运行即可，会自动调用对应架构的 qemu；
- 动态链接的 bianry 需要用对应的 qemu 同时指定共享库路径，如下图32位的动态链接 mips binary
![](http://ww1.sinaimg.cn/large/006AWYXBly1fq5d1guaxvj313m03bq55.jpg)
使用 -L 指定共享库路径：
```bash
$ qemu-mipsel -L /usr/mipsel-linux-gnu/ ./add
```
![](http://ww1.sinaimg.cn/large/006AWYXBly1fq5d3xxmfqj30z50c4ahc.jpg)

## 调试：
可以使用 qemu 的 -g 指定端口
```bash
$ qemu-mipsel -g 1234 -L /usr/mipsel-linux-gnu/ ./add
```
然后使用 gdb-multiarch 进行调试，先指定架构，然后使用 remote 功能

```bash
pwndbg> set architecture mips (但大多数情况下这一步可以省略, 似乎 pwndbg 能自动识别架构)
pwndbg> target remote localhost:1234
```
![](http://ww1.sinaimg.cn/large/006AWYXBly1fq5dbufgrjj31400p013o.jpg)
这样我们就能进行调试了
![](http://ww1.sinaimg.cn/large/006AWYXBly1fq5de5c26aj31400p046h.jpg)

## 效果图：
![](http://ww1.sinaimg.cn/large/006AWYXBly1fq5de5c26aj31400p046h.jpg)
![](http://ww1.sinaimg.cn/large/006AWYXBly1fq5dg64kb8j31400p0tgd.jpg)

## more：
同样，如果想要运行或者调试其他架构的 binary，只需安装其他架构的 qemu 和共享库即可

## reference：
https://docs.pwntools.com/en/stable/qemu.html
https://reverseengineering.stackexchange.com/questions/8829/cross-debugging-for-arm-mips-elf-with-qemu-toolchain

