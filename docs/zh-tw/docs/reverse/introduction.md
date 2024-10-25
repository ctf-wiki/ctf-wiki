# 軟件逆向工程簡介

## 定義

> Reverse engineering, also called back engineering, is the process by which a man-made object is deconstructed to reveal its designs, architecture, or to extract knowledge from the object;       ------  from [wikipedia](https://en.wikipedia.org/wiki/Reverse_engineering)

軟件代碼逆向主要指對軟件的結構，流程，算法，代碼等進行逆向拆解和分析。

## 應用領域

主要應用於軟件維護，軟件破解，漏洞挖掘，惡意代碼分析。

## CTF競賽中的逆向

> 涉及 Windows、Linux、Android 平臺的多種編程技術，要求利用常用工具對源代碼及二進制文件進行逆向分析，掌握 Android 移動應用APK文件的逆向分析，掌握加解密、內核編程、算法、反調試和代碼混淆技術。
> ------ 《全國大學生信息安全競賽參賽指南》

### 要求

-   熟悉如操作系統，彙編語言，加解密等相關知識
-   具有豐富的多種高級語言的編程經驗
-   熟悉多種編譯器的編譯原理
-   較強的程序理解和逆向分析能力

## 常規逆向流程

1.  使用`strings/file/binwalk/IDA`等靜態分析工具收集信息，並根據這些靜態信息進行`google/github`搜索
2.  研究程序的保護方法，如代碼混淆，保護殼及反調試等技術，並設法破除或繞過保護
3.  反彙編目標軟件，快速定位到關鍵代碼進行分析
4.  結合動態調試，驗證自己的初期猜想，在分析的過程中理清程序功能
5.  針對程序功能，寫出對應腳本，求解出flag

### 定位關鍵代碼tips

1. 分析控制流

    控制流可以參見IDA生成的控制流程圖（CFG），沿着分支循環和函數調用，逐塊地閱讀反彙編代碼進行分析。

2. 利用數據、代碼交叉引用

    比如輸出的提示字符串，可以通過數據交叉引用找到對應的調用位置，進而找出關鍵代碼。代碼交叉引用比如圖形界面程序獲取用戶輸入，就可以使用對應的windowsAPI函數，我們就可以通過這些API函數調用位置找到關鍵代碼。

### 逆向tips

1. 編碼風格

    每個程序員的編碼風格都有所不同，熟悉開發設計模式的同學能更迅速地分析出函數模塊功能

2. 集中原則

    程序員開發程序時，往往習慣將功能相關的代碼或是數據寫在同一個地方，而在反彙編代碼中也能顯示出這一情況，因此在分析時可以查看關鍵代碼附近的函數和數據。

3. 代碼複用

    代碼複用情況非常普遍，而最大的源代碼倉庫Github則是最主要的來源。在分析時可以找一些特徵（如字符串，代碼風格等）在Github搜索，可能會發現類似的代碼，並據此恢復出分析時缺失的符號信息等。

4. 七分逆向三分猜

    合理的猜測往往能事半功倍，遇到可疑函數卻看不清裏面的邏輯，不妨根據其中的蛛絲馬跡猜測其功能，並依據猜測繼續向下分析，在不斷的猜測驗證中，或許能幫助你更加接近代碼的真相。

5. 區分代碼

    拿到反彙編代碼，必須能區分哪些代碼是人爲編寫的，而哪些是編譯器自動附加的代碼。人爲編寫的代碼中，又有哪些是庫函數代碼，哪些纔是出題人自己寫的代碼，出題人的代碼又經過編譯器怎樣的優化？我們無須花費時間在出題人以外的代碼上，這很重要。如果當你分析半天還在庫函數裏亂轉，那不僅體驗極差，也沒有絲毫效果。

6. 耐心

    無論如何，給予足夠的時間，總是能將一個程序分析地透徹。但是也不應該過早地放棄分析。相信自己肯定能在抽繭剝絲的過程中突破問題。

### 動態分析

動態分析的目的在於定位關鍵代碼後，在程序運行的過程中，藉由輸出信息（寄存器，內存變化，程序輸出）等來驗證自己的推斷或是理解程序功能

主要方法有：調試，符號執行，污點分析

### 算法和數據結構識別

-   常用算法識別

如`Tea/XTea/XXTea/IDEA/RC4/RC5/RC6/AES/DES/IDEA/MD5/SHA256/SHA1`等加密算法，大數加減乘除、最短路等傳統算法

-   常用數據結構識別

如圖、樹、哈希表等高級數據結構在彙編代碼中的識別。


### 代碼混淆

比如使用`OLLVM`，`movfuscator`，`花指令`，`虛擬化`及`SMC`等工具技術對代碼進行混淆，使得程序分析十分困難。

那麼對應的也有反混淆技術，最主要的目的就是復原控制流。比如`模擬執行`和`符號執行`

### 保護殼

保護殼類型有許多，簡單的壓縮殼可以歸類爲如下幾種

-   unpack -> execute

    直接將程序代碼全部解壓到內存中再繼續執行程序代碼

-   unpack -> execute -> unpack -> execute ...

    解壓部分代碼，再邊解壓邊執行

-   unpack -> [decoder | encoded code] -> decode -> execute

    程序代碼有過編碼，在解壓後再運行函數將真正的程序代碼解碼執行

對於脫殼也有相關的方法，比如`單步調試法`，`ESP定律`等等

### 反調試

反調試意在通過檢測調試器等方法避免程序被調試分析。比如使用一些API函數如`IsDebuggerPresent`檢測調試器，使用`SEH異常處理`，時間差檢測等方法。也可以通過覆寫調試端口、自調試等方法進行保護。

## 非常規逆向思路

非常規逆向題設計的題目範圍非常之廣，可以是任意架構的任意格式文件。

-   lua/python/java/lua-jit/haskell/applescript/js/solidity/webassembly/etc..
-   firmware/raw bin/etc..
-   chip8/avr/clemency/risc-v/etc.

但是逆向工程的方法學裏不懼怕這些未知的平臺格式，遇到這樣的非常規題，我們也有一些基本的流程可以通用

### 前期準備

-   閱讀文檔。快速學習平臺語言的方法就是去閱讀官方文檔。
-   官方工具。官方提供或建議的工具必然是最合適的工具
-   教程。在逆向方面，也許有許多前輩寫出了專門針對該平臺語言的逆向教程，因此也可以快速吸收這其中的知識。

### 找工具

主要找`文件解析工具`、`反彙編器`、`調試器`和`反編譯器`。其中`反彙編器`是必需的，`調試器`也包含有相應的反彙編功能，而對於`反編譯器`則要自求多福了，得之我幸失之我命。

找工具總結起來就是：Google大法好。合理利用Google搜索語法，進行關鍵字搜索可以幫助你更快更好地找到合適工具。
