[EN](./last-exception.md) | [ZH](./last-exception-zh.md)
The principle of the last exception method is that the program may trigger countless exceptions during self-extraction or self-decryption. If you can locate the last program exception, it may be close to the automatic shelling completion position. Now the last An exception method shelling can take advantage of Ollydbg&#39;s exception counter plugin, first record the number of exceptions, then reload, automatically stop at the last exception.


## 要点


1. Click on &#39;Options -&gt; Debug Options -&gt; Exceptions`, remove all the √ inside! Press `CTRL+F2` to reload the program.
2. The start program is a jump, here we press `SHIFT+F9`, until the program runs, write down the number of times to start from `SHIFT+F9` to the program `m`!
3. `CTRL+F2` reload the program, press `SHIFT+F9` (the number of times this time is the program running times `m-1` times)
4. In the lower right corner of the OD we see a &quot;`SE handle`&quot;, then we press `CTRL+G` and enter the address before the `SE handle&#39;!
5. Press F2 to break the point! Then press `SHIFT+F9` to the breakpoint, F8 single step tracking


##example


The sample program can be downloaded here: [5_last_exception.zip](https://github.com/ctf-wiki/ctf-challenges/blob/master/reverse/unpack/example/5_last_exception.zip)


OD loader, uncheck all ignore exceptions in the menu `Options -&gt; Debug Settings -&gt; Exceptions tab` and then reload the program.


![exception_01.png](./figure/exception_01.png)



We press `Shift+F9`, the number of times the record is pressed, the program runs normally. What we want to get is the number of times the second to last press is pressed. In this example


* `shift+F9` once, to the position of `0040CCD2`
* `shift+F9` twice, the program runs normally


Then we reload the program, just press 1 (`2-1=1`) `Shift+F9`, go to the position of `0040CCD2`, observe the stack window, there is a `SE handler: 0040CCD7`


![exception_02.png](./figure/exception_02.png)



In the CPU window (assembly instruction), press `Ctrl+G`, enter `0040CCD7`, then press F2 here. That is, set a breakpoint at `0040CCD7`, then press `Shift+F9` to run. Trigger a breakpoint.


![exception_03.png](./figure/exception_03.png)



After triggering the breakpoint, step through the tracking. Down are some loops and jumps, we use F4 to skip the loop. Finally arrive at the following position


![exception_04.png](./figure/exception_04.png)



Obviously in the final `mov ebp, 0041010CC; jmp ebp` is in the jump to OEP, we jump past as shown below:


![exception_05.png](./figure/exception_05.png)



Obviously, we were lucky enough to come to OEP.