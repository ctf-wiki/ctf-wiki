# Unicorn Engine

## 什麼是Unicorn引擎

Unicorn是一個輕量級, 多平臺, 多架構的CPU模擬器框架. 我們可以更好地關注CPU操作, 忽略機器設備的差異. 想象一下, 我們可以將其應用於這些情景: 比如我們單純只是需要模擬代碼的執行而非需要一個真的CPU去完成那些操作, 又或者想要更安全地分析惡意代碼, 檢測病毒特徵, 或者想要在逆向過程中驗證某些代碼的含義. 使用CPU模擬器可以很好地幫助我們提供便捷.

它的亮點(這也歸功於Unicorn是基於[qemu](http://www.qemu.org)而開發的)有:

* 支持多種架構: Arm, Arm64 (Armv8), M68K, Mips, Sparc, & X86 (include X86_64).
* 對Windows和*nix系統(已確認包含Mac OSX, Linux, *BSD & Solaris)的原生支持
* 具有平臺獨立且簡潔易於使用的API
* 使用JIT編譯技術, 性能表現優異

你可以在[Black Hat USA 2015](http://www.unicorn-engine.org/BHUSA2015-unicorn.pdf)獲悉有關Unicorn引擎的更多技術細節. Github項目主頁: [unicorn](https://github.com/unicorn-engine/unicorn)

儘管它不同尋常, 但它無法模擬整個程序或系統, 也不支持系統調用. 你需要手動映射內存並寫入數據進去, 隨後你才能從指定地址開始模擬. 

## 應用的情景

什麼時候能夠用到Unicorn引擎呢? 

* 你可以調用惡意軟件中一些有趣的函數, 而不用創建一個有害的進程.
* 用於CTF競賽
* 用於模糊測試
* 用於gdb插件, 基於代碼模擬執行的插件
* 模擬執行一些混淆代碼

## 如何安裝

安裝Unicorn最簡單的方式就是使用pip安裝, 只要在命令行中運行以下命令即可(這是適合於喜愛用python的用戶的安裝方法, 對於那些想要使用C的用戶, 則需要去官網查看文檔編譯源碼包):

``` shell
pip install unicorn
```

但如果你想用源代碼進行本地編譯的話, 你需要在[下載](http://www.unicorn-engine.org/download/)頁面中下載源代碼包, 然後可以按照以下命令執行:

* *nix 平臺用戶

``` shell
$ cd bindings/python
$ sudo make install
```

* Windows平臺用戶

``` shell
cd bindings/python
python setup.py install
```

對於Windows, 在執行完上述命令後, 還需要將[下載](http://www.unicorn-engine.org/download/)頁面的`Windows core engine`的所有dll文件複製到`C:\locationtopython\Lib\site-packages\unicorn`位置處. 

## 使用unicorn的快速指南

我們將會展示如何使用python調用unicorn的api以及它是如何輕易地模擬二進制代碼. 當然這裏用的api僅是一小部分, 但對於入門已經足夠了.

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
14     mu = Uc(UC_ARCH_X86, UC_MODE_32)
15 
16     # map 2MB memory for this emulation
17     mu.mem_map(ADDRESS, 2 * 1024 * 1024)
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
34     print(">>> ECX = 0x%x" %r_ecx)
35     print(">>> EDX = 0x%x" %r_edx)
36 
37 except UcError as e:
38     print("ERROR: %s" % e)
```

運行結果如下:

``` shell
$ python test1.py 
Emulate i386 code
Emulation done. Below is the CPU context
>>> ECX = 0x1235
>>> EDX = 0x788f
```

樣例裏的註釋已經非常直觀, 但我們還是對每一行代碼做出解釋:

* 行號2~3: 在使用Unicorn前導入`unicorn`模塊. 樣例中使用了一些x86寄存器常量, 所以也需要導入`unicorn.x86_const`模塊

* 行號6: 這是我們需要模擬的二進制機器碼, 使用十六進製表示, 代表的彙編指令是: "INC ecx" 和 "DEC edx".

* 行號9: 我們將模擬執行上述指令的所在虛擬地址

* 行號14: 使用`Uc`類初始化Unicorn, 該類接受2個參數: 硬件架構和硬件位數(模式). 在樣例中我們需要模擬執行x86架構的32位代碼, 我
們使用變量`mu`來接受返回值.

* 行號17: 使用`mem_map `方法根據在行號9處聲明的地址, 映射2MB用於模擬執行的內存空間. 所有進程中的CPU操作都應該只訪問該內存區域. 映射的內存具有默認的讀,寫和執行權限.

* 行號20: 將需要模擬執行的代碼寫入我們剛剛映射的內存中. `mem_write`方法接受2個參數: 要寫入的內存地址和需要寫入內存的代碼.

* 行號23~24: 使用`reg_write`方法設置`ECX`和`EDX`寄存器的值

* 行號27: 使用`emu_start`方法開始模擬執行, 該API接受4個參數: 要模擬執行的代碼地址, 模擬執行停止的內存地址(這裏是
`X86_CODE32`的最後1字節處), 模擬執行的時間和需要執行的指令數目. 如果我們像樣例一樣忽略後兩個參數, Unicorn將會默認以無窮時間和無窮指令數目的條件來模擬執行代碼. 

* 行號32~35: 打印輸出`ECX`和`EDX`寄存器的值. 我們使用函數`reg_read`來讀取寄存器的值.


要想查看更多的python示例, 可以查看文件夾[bindings/python](https://github.com/unicorn-engine/unicorn/tree/master/bindings/python)下的代碼. 而C的示例則可以查看[sample](https://github.com/unicorn-engine/unicorn/tree/master/samples)文件夾下的代碼. 


## 參考鏈接

* [Unicorn Official Site](http://www.unicorn-engine.org/)
* [Quick tutorial on programming with Unicorn - with C & Python.](http://www.unicorn-engine.org/docs/)