[EN](./introduction.md) | [ZH](./introduction-zh.md)
# Unicorn Engine Introduction


## What is the Unicorn Engine?


Unicorn is a lightweight, multi-platform, multi-architecture CPU simulator framework. We can better focus on CPU operation and ignore machine differences. Imagine we can apply it to these scenarios: for example, we simply need Simulate code execution instead of requiring a real CPU to do those operations, or want to analyze malicious code more securely, detect virus signatures, or want to verify the meaning of certain code in the reverse process. Using the CPU simulator can Good to help us provide convenience.


Its highlights (which are also attributed to Unicorn&#39;s development based on [qemu] (http://www.qemu.org)) are:


* Support multiple architectures: Arm, Arm64 (Armv8), M68K, Mips, Sparc, &amp; X86 (include X86_64).
* Native support for Windows and *nix systems (confirmed to include Mac OSX, Linux, *BSD &amp; Solaris)
* API with platform independence and simplicity and ease of use
* Excellent performance with JIT compilation technology


You can learn more about the technical details of the Unicorn engine at [Black Hat USA 2015] (http://www.unicorn-engine.org/BHUSA2015-unicorn.pdf). Github Project Homepage: [unicorn](https:// Github.com/unicorn-engine/unicorn)


Although it is unusual, it can&#39;t simulate the entire program or system, nor does it support system calls. You need to manually map memory and write data in, then you can start the simulation from the specified address.


## Application scenario


When can I use the Unicorn engine?


* You can call some interesting functions in malware without creating a harmful process.
* for CTF competition
* for fuzz testing
* Plugin for gdb plugin, based on code emulation
* Simulate execution of some obfuscated code


## how to install


The easiest way to install Unicorn is to use pip installation. Just run the following command from the command line (this is the installation method for users who like to use python. For those who want to use C, you need to go to the official website to view the document. Compile the source package):


``` shell

pip install unicorn

```



But if you want to compile locally with source code, you need to download the source package from the [Download] (http://www.unicorn-engine.org/download/) page, and then follow these commands:


* *nix platform users


``` shell

$ cd bindings/python

$ sudo make install

```



* Windows platform users


``` shell

cd bindings/python

python setup.py install

```



For Windows, after executing the above command, you need to copy all the dll files of the `Windows core engine` on the [Download] (http://www.unicorn-engine.org/download/) page to `C:\locationtopython \Lib\site-packages\unicorn` location.


## Quick guide to using unicorn


We&#39;ll show you how to use python to call unicorn&#39;s api and how easy it is to emulate binary code. Of course, the api used here is only a small part, but it&#39;s enough for getting started.


``` python

 1 from __future__ import print_function

 2 from unicorn import *

 3 from unicorn.x86_const import *

 4 

 5 # code to be emulated

 6 X86_CODE32 = b"\x41\x4a" # INC ecx; DEC edx

 7 

 8 # memory address where emulation starts

 9 ADDRESS = 0x1000000

10 

11 print("Emulate i386 code")

12 try:

13     # Initialize emulator in X86-32bit mode

14 mu = Uc (UC_ARCH_X86, UC_MODE_32)
15 

16     # map 2MB memory for this emulation

17 mu.mem_map (ADDRESS, 2 * 1024 * 1024)
18 

19     # write machine code to be emulated to memory

20     mu.mem_write(ADDRESS, X86_CODE32)

21 

22     # initialize machine registers

23     mu.reg_write(UC_X86_REG_ECX, 0x1234)

24     mu.reg_write(UC_X86_REG_EDX, 0x7890)

25 

26     # emulate code in infinite time & unlimited instructions

27     mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))

28 

29     # now print out some registers

30     print("Emulation done. Below is the CPU context")

31 

32     r_ecx = mu.reg_read(UC_X86_REG_ECX)

33     r_edx = mu.reg_read(UC_X86_REG_EDX)

34 print (&quot;&gt;&gt;&gt; ECX = 0x% x&quot;% r_ecx)
35     print(">>> EDX = 0x%x" %r_edx)

36 

37 except UcError as e:

38     print("ERROR: %s" % e)

```



The results are as follows:


``` shell

$ python test1.py 

Emulate i386 code

Emulation done. Below is the CPU context

&gt;&gt;&gt; ECX = 0x1235
>>> EDX = 0x788f

```



The comments in the sample are very intuitive, but we still explain each line of code:


* Line number 2~3: Import the `unicorn` module before using Unicorn. Some x86 register constants are used in the example, so you need to import the `unicorn.x86_const` module.


* Line number 6: This is the binary machine code we need to simulate. Using hexadecimal representation, the assembly instructions are: &quot;INC ecx&quot; and &quot;DEC edx&quot;.


* Line number 9: We will simulate the virtual address where the above instructions are executed.


* Line number 14: Initialize Unicorn with the `Uc` class, which accepts 2 parameters: hardware architecture and hardware bits (mode). In the example we need to simulate 32-bit code that executes the x86 architecture, I
We use the variable `mu` to accept the return value.


* Line number 17: Use the `mem_map` method to map 2MB for the memory space that is executed according to the address declared at line number 9. All CPU operations in the process should only access this memory area. The mapped memory has a default Read, write and execute permissions.


* Line number 20: Write the code that needs to be simulated to the memory we just mapped. The `mem_write` method accepts 2 parameters: the memory address to be written and the code to be written to memory.


* Line number 23~24: Set the values of the `ECX` and `EDX` registers using the `reg_write` method.


* Line number 27: Start the simulation execution using the `emu_start` method. The API accepts 4 parameters: To simulate the code address of execution, simulate the memory address where execution is stopped (here
The last byte of `X86_CODE32`, simulates the execution time and the number of instructions that need to be executed. If we ignore the last two parameters as in the example, Unicorn will default to simulate execution with infinite time and infinite number of instructions. Code.

* Line number 32~35: Print out the values of the `ECX` and `EDX` registers. We use the function `reg_read` to read the value of the register.




To see more python examples, look at the code in the folder [bindings/python] (https://github.com/unicorn-engine/unicorn/tree/master/bindings/python). The C example is You can view the code under the [sample](https://github.com/unicorn-engine/unicorn/tree/master/samples) folder.




## Reference link


* [Unicorn Official Site](http://www.unicorn-engine.org/)

* [Quick tutorial on programming with Unicorn - with C & Python.](http://www.unicorn-engine.org/docs/)