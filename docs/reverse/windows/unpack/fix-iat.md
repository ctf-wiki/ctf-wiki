## 原理

在找到程序OEP后, 我们需要将程序dump出来, 并重建`IAT`. `IAT`全名是`Import Address Table`, 表项指向函数实际地址.

## 示例

比如如下, 我们找到了OEP, 到达了程序的真正入口点. 我们这时就需要将程序dump出来. 我们右键, 选择`"用OllyDump脱壳调试进程"`(不过你也可以使用`LoadPE`来dump出来):

![right_click.jpg](./figure/fix_iat/right_click.jpg)

弹出一个窗口, 看一下地址是否正确, 主要就是看看`入口点地址`有没有选对. 然后取消勾选`重建输入表`.

![dump.png](./figure/fix_iat/dump.png)

将dump出的文件命名, 我这里是命名为`dump.exe`啦. 我们尝试来运行一下`dump.exe`, 可以发现程序无法正常运行, 对于一些简单的壳, 你dump出来发现无法正常运行, 如果你确实找到了正确的OEP并用`IDA`反编译查看结果良好, 那么你的第一想法就应该是程序的`IAT`出现了问题. 你就需要重建`IAT`.

我们需要使用`ImportREC`来帮助修复输入表.

打开`ImportREC`, 选择一个正在运行的进程`原版.exe`(`原版.exe`是我在OD中正在调试的进程, OD中的`EIP`正处在`OEP`位置, 在用`Ollydump`之后不要关闭这个进程哦.). `ImportREC`修复输入表入口点需要知道`OEP`, 也就是要在窗口右侧中间的`OEP`输入框中进行输入

![importrec.png](./figure/fix_iat/importrec.png)

我们所知, 在Ollydbg里我们知道程序目前在的入口点是`0049C25C`, 而镜像基址是`00400000`

因此我们这里需要填写`OEP`是`0009C25C`

我们修改`ImportREC`中的`OEP`为`0009C25C`然后点击`AutoSearch`后, 弹出提示框"发现可能是原IAT地址"

![auto_search.png](./figure/fix_iat/auto_search.png)

我们点击`"Get Imports"`按钮便可以重建`IAT`. 左侧会显示`IAT`中各导入函数的地址以及是否有效. 显然在图中可以看到`ImportREC`找到了内存中`IAT`的位置并检测出各个函数都是有效的.

![get_imports.png](./figure/fix_iat/get_imports.png)

我们点击`Fix Dump`, 然后打开先前使用`OllyDump`插件转储出来的文件，也就是`dump.exe`文件。

那么`ImportREC`就会帮助恢复导入表，并生成`dump_.exe`文件. `dump_.exe`可以正常运行
