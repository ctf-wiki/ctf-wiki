[EN](./pyc.md) | [ZH](./pyc-zh.md)
code object

===



&gt; When we import the python script, we will generate a corresponding pyc file in the directory, which is a persistent storage form of pythoncodeobj to speed up the next load.




## File Structure


Pyc file consists of three major parts


- The first 4 bytes is a Maigg int, which identifies the version information of this pyc.


- The next four bytes are still an int, which is the time that pyc is generated.


- Serialized PyCodeObject, structure reference [include/code.h] (https://github.com/python/cpython/blob/master/Include/code.h), serialization method [python/marshal](https: //github.com/python/cpython/blob/master/Python/marshal.c)


**pyc full file parsing can refer to **


- [How the Python program is executed] (http://python.jobbole.com/84599/)
- [PYC File Format Analysis] (http://kdr2.com/tech/python/pyc-format.html)




**About co_code**


A string of binary streams, representing the sequence of instructions, specifically defined in [include/opcode.h] (https://github.com/python/cpython/blob/fc7df0e664198cb05cafd972f190a18ca422989c/Include/opcode.h), or refer to [python Opcodes] (http://unpyc.sourceforge.net/Opcodes.html).


by


- The directive (opcode) is divided into parameters and no parameters, which are divided into https://github.com/python/cpython/blob/fc7df0e664198cb05cafd972f190a18ca422989c/Include/opcode.h#L69


- parameter (oparg)


The above parameters of python3.6 always occupy 1 byte. If the instruction has no parameters, it is replaced by `0x00`, which is ignored by the interpreter during the running process. It is also the technical principle of **Stegosaurus**; the version is lower than python3.5. The middle instruction has no arguments but no `0x00` padding.




### Example


**[Hackover CTF 2016 : img-enc](https://github.com/ctfs/write-ups-2016/tree/master/hackover-ctf-2016/forensics/img-enc)**



First try pycdc decompile failed


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



Note that it is python2.7, which means that the instruction sequence occupies 1 byte or 3 bytes (with parameters without parameters)


Get it with pcads


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



Positioned to the error, observed that `LOAD_CONST LOAD_CONST BINARY_DIVIDE STORE_FAST opcodes (64 03 00 64 03 00 15 7d 05 00)` was destroyed, after repairing according to context clues


```xml

00000120 64 04 00 6b 00 00 72 00 00 03 03 00 64 03 00 15 | d..k..r..d..d ... |
00000130 7d 05 00 64 03 00 64 03 00 15 7d 05 00 64 03 00 |} .. d..d ...} .. d .. |
00000140 64 03 00 15 7d 05 00 64 03 00 64 03 00 15 7d 05 | d ...} .. d..d ...}.
00 000101 00 00 64 03 00 64 03 00 15 7d 05 00 64 03 00 64 03 | .d..d ...} .. d..d. |
00000160 00 15 7d 05 00 64 03 00 64 03 00 15 7d 05 00 64 | ..} .. d..d ...} .. d |
00000170 03 00 64 03 00 15 7d 05 00 64 03 00 64 03 00 15 | ..d ...} .. d..d ... |
00000180 7d 05 00 64 03 00 64 03 00 15 7d 05 00 64 03 00 |} .. d..d ...} .. d .. |
00000190 64 03 00 15 7d 05 00 64 03 00 64 03 00 15 7d 05 | d ...} .. d..d ...}.
000001a0  00 64 03 00 64 03 00 15  7d 05 00 64 03 00 64 03  |.d..d...}..d..d.|

000001b0 00 15 7d 05 00 64 03 00 64 03 00 15 7d 05 00 6e | ..} .. d..d ...} .. n |
```



Then get the flag according to the fixed python source code.




**extend**:


- 题目: [0ctf-2017:py](https://github.com/ctfs/write-ups-2017/tree/master/0ctf-quals-2017/reverse/py-137)

- writeup: [Remember a CPython bytecode] (http://0x48.pw/2017/03/20/0x2f/)




## Tools





### [pycdc](https://github.com/zrax/pycdc)



&gt; Convert python bytecode to readable python source code, including disassembly (pycads) and decompilation (pycdc)




### [Stegosaurus](https://bitbucket.org/jherron/stegosaurus/src)



&gt; Allows us to embed any Payload in a Python bytecode file (pyc or pyo). Due to the low coding density, the process of embedding Payload does not change the running behavior of the source code, nor does it change the file size of the source file.


The principle is to use the redundant space in the python bytecode file to hide the complete payload code into these fragmented spaces.


**Ref**: [A steganographic tool for embedding Payload in Python bytecode – Stegosaurus] (http://www.freebuf.com/sectool/129357.html)


**Challenges**: [WHCTF-2017:Py-Py-Py](https://www.xctf.org.cn/library/details/whctf-writeup/)