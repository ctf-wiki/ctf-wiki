"SFX"法利用了Ollydbg自带的OEP寻找功能, 可以选择直接让程序停在OD找到的OEP处, 此时壳的解压过程已经完毕, 可以直接dump程序.

## 要点

1. 设置OD, 忽略所有异常, 也就是说异常选项卡里面都打上勾
2. 切换到SFX选项卡, 选择"字节模式跟踪实际入口(速度非常慢)", 确定
3. 重载程序(如果跳出是否"压缩代码?"选择"否", OD直接到达OEP)

## 示例

示例程序可以点击此处下载: [6_sfx.zip](https://github.com/ctf-wiki/ctf-challenges/blob/master/reverse/unpack/example/6_sfx.zip)

首先我们在菜单`选项->调试设置->异常标签页`中勾选所有忽略异常.

![sfx_01.png](./figure/sfx_01.png)

然后切换到`SFX`标签页, 点选"字节方式跟踪真正入口处(速度非常慢)"

![sfx_02.png](./figure/sfx_02.png)

重载程序，程序已经停在了代码入口点, 并且也不需要对OEP进行重新分析.

![sfx_03.png](./figure/sfx_03.png)
