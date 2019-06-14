code object
===

> 在我们导入 python 脚本时在目录下会生成个一个相应的 pyc 文件，是pythoncodeobj的持久化储存形式,加速下一次的装载。


## 文件结构

pyc文件由三大部分组成

- 最开始4个字节是一个Maigc int, 标识此pyc的版本信息

- 接下来四个字节还是个int,是pyc产生的时间

- 序列化的 PyCodeObject,结构参照[include/code.h](https://github.com/python/cpython/blob/master/Include/code.h),序列化方法[python/marshal](https://github.com/python/cpython/blob/master/Python/marshal.c)

**pyc完整的文件解析可以参照**

- [Python程序的执行原理](http://python.jobbole.com/84599/)
- [PYC文件格式分析](http://kdr2.com/tech/python/pyc-format.html)


**关于co_code**

一串二进制流,代表着指令序列,具体定义在[include/opcode.h](https://github.com/python/cpython/blob/fc7df0e664198cb05cafd972f190a18ca422989c/Include/opcode.h)中,也可以参照[python opcodes](http://unpyc.sourceforge.net/Opcodes.html)。

由

- 指令(opcode),分为有参数和无参数两种,以 https://github.com/python/cpython/blob/fc7df0e664198cb05cafd972f190a18ca422989c/Include/opcode.h#L69 划分

- 参数(oparg)

python3.6 以上参数永远占1字节,如果指令不带参数的话则以`0x00`代替,在运行过程中被解释器忽略,也是**Stegosaurus**技术原理;而低于python3.5的版本中指令不带参数的话却没有`0x00`填充


### 例题

**[Hackover CTF 2016 : img-enc](https://github.com/ctfs/write-ups-2016/tree/master/hackover-ctf-2016/forensics/img-enc)**

首先尝试pycdc反编译失败

```python
# Source Generated with Decompyle++
# File: imgenc.pyc (Python 2.7)

import sys
import numpy as np
from scipy.misc import imread, imsave

def doit(input_file, output_file, f):
Unsupported opcode: STOP_CODE
    img = imread(input_file, flatten = True)
    img /= 255
    size = img.shape[0]
# WARNING: Decompyle incomplete
```

注意到是python2.7,也就是说指令序列共占1字节或3字节(有参数无参数)

使用pcads得到

```xml
imgenc.pyc (Python 2.7)
...
                67      STOP_CODE               
                68      STOP_CODE               
                69      BINARY_DIVIDE           
                70      JUMP_IF_TRUE_OR_POP     5
                73      LOAD_CONST              3: 0
                76      LOAD_CONST              3: 0
                79      BINARY_DIVIDE       
```

定位到出错的地方,观察发现 `LOAD_CONST LOAD_CONST BINARY_DIVIDE STORE_FAST opcodes (64 03 00 64 03 00 15 7d 05 00)`被破坏了,根据上下文线索修复后

```xml
00000120  64 04 00 6b 00 00 72 ce  00 64 03 00 64 03 00 15  |d..k..r..d..d...|
00000130  7d 05 00 64 03 00 64 03  00 15 7d 05 00 64 03 00  |}..d..d...}..d..|
00000140  64 03 00 15 7d 05 00 64  03 00 64 03 00 15 7d 05  |d...}..d..d...}.|
00000150  00 64 03 00 64 03 00 15  7d 05 00 64 03 00 64 03  |.d..d...}..d..d.|
00000160  00 15 7d 05 00 64 03 00  64 03 00 15 7d 05 00 64  |..}..d..d...}..d|
00000170  03 00 64 03 00 15 7d 05  00 64 03 00 64 03 00 15  |..d...}..d..d...|
00000180  7d 05 00 64 03 00 64 03  00 15 7d 05 00 64 03 00  |}..d..d...}..d..|
00000190  64 03 00 15 7d 05 00 64  03 00 64 03 00 15 7d 05  |d...}..d..d...}.|
000001a0  00 64 03 00 64 03 00 15  7d 05 00 64 03 00 64 03  |.d..d...}..d..d.|
000001b0  00 15 7d 05 00 64 03 00  64 03 00 15 7d 05 00 6e  |..}..d..d...}..n|
```

接下来根据修复好的python源代码得到flag即可


**延伸**:

- 题目: [0ctf-2017:py](https://github.com/ctfs/write-ups-2017/tree/master/0ctf-quals-2017/reverse/py-137)
- writeup: [记一次手撸CPython bytecode](http://0x48.pw/2017/03/20/0x2f/)


## Tools


### [pycdc](https://github.com/zrax/pycdc)

> 将python字节码转换为可读的python 源代码,包含了反汇编(pycads)和反编译(pycdc)两种工具


### [Stegosaurus](https://bitbucket.org/jherron/stegosaurus/src)

> 允许我们在Python字节码文件（pyc或pyo）中嵌入任意Payload。由于编码密度较低，因此我们嵌入Payload的过程既不会改变源代码的运行行为，也不会改变源文件的文件大小

原理是在python的字节码文件中,利用冗余空间,将完整的payload代码分散隐藏到这些零零碎碎的空间中.

**Ref**: [一种用于在Python字节码中嵌入Payload的隐写工具 – Stegosaurus](http://www.freebuf.com/sectool/129357.html)

**Challenges**: [WHCTF-2017:Py-Py-Py](https://www.xctf.org.cn/library/details/whctf-writeup/)