# Android 動態調試

## Android 調試基本原理

一般來說，Android 根據如下的順序來判斷一個應用是否可以被調試

1.  檢測 boot.img 中的 ro.debuggable 是否爲1，爲 1 的話，手機中的任何應用均可以調試。
2.  否則，檢測對應應用中 AndroidManifest.xml 中 \<application\>  元素中是否包含了android:debuggable="true"，如果有的話，纔會開啓調試支持。

自然，我們也就有兩種方法來使得一個應用可以被調試

1.  將一個 apk 文件解包，在 \<application\> 元素中添加 android:debuggable="true"，然後重打包，簽名。
2.  修改 boot.img 中的 ro.debuggable 爲 1。

一般來說，因爲前者需要我們每次都需要修改應用，比較麻煩，我們更傾向於後者，。

對於後者來說，我們需要 root 手機，並刷入相關的鏡像。（**！！找一篇合適的文章！！**）

此外，由 Andoird AVD 生成的模擬器默認情況下 ro.debuggable 被設置爲1。

`ro.debuggable` 的值可以根據如下命令來查詢

```shell
adb shell getprop ro.debuggable
```

## 基本調試工具

### DDMS

DDMS（Dalvik Debug Monitor Service）是Dalvik虛擬機調試監控服務，可以監視Android程序在運行過程中的狀態以及結果，可以大大加快我們的程序分析效率。這是一款由Android SDK提供的工具，其中有設備截屏，查看運行的線程信息、文件瀏覽、Logcat、Method Profiling、廣播狀態信息、模擬電話呼叫、接收SMS等功能。該工具一般位於Android SDK的tools目錄下，其中ddms.bat就是用來啓動DDMS的。DDMS中比較重要的功能主要是

- 文件瀏覽，我們可以觀察並分析程序在執行過程中對文件的生成，修改，刪除操作。
- Logcat，可以輸出軟件的一些調試信息。
- Method Profiling，可以跟蹤程序的執行流程。

### IDEA/Android Studio

安裝 smaliidea 插件，動態調試smali。

### IDA Pro

吾愛破解。

