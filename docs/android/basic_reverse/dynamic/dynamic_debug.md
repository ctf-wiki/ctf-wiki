# Android 动态调试

## Android 调试基本原理

一般来说，Android 根据如下的顺序来判断一个应用是否可以被调试

1.  检测 boot.img 中的 ro.debuggable 是否为1，为 1 的话，手机中的任何应用均可以调试。
2.  否则，检测对应应用中 AndroidManifest.xml 中 \<application\>  元素中是否包含了android:debuggable="true"，如果有的话，才会开启调试支持。

自然，我们也就有两种方法来使得一个应用可以被调试

1.  将一个 apk 文件解包，在 \<application\> 元素中添加 android:debuggable="true"，然后重打包，签名。
2.  修改 boot.img 中的 ro.debuggable 为 1。

一般来说，因为前者需要我们每次都需要修改应用，比较麻烦，我们更倾向于后者，。

对于后者来说，我们需要 root 手机，并刷入相关的镜像。（**！！找一篇合适的文章！！**）

此外，由 Andoird AVD 生成的模拟器默认情况下 ro.debuggable 被设置为1。

`ro.debuggable` 的值可以根据如下命令来查询

```shell
adb shell getprop ro.debuggable
```

## 基本调试工具

### DDMS

DDMS（Dalvik Debug Monitor Service）是Dalvik虚拟机调试监控服务，可以监视Android程序在运行过程中的状态以及结果，可以大大加快我们的程序分析效率。这是一款由Android SDK提供的工具，其中有设备截屏，查看运行的线程信息、文件浏览、Logcat、Method Profiling、广播状态信息、模拟电话呼叫、接收SMS等功能。该工具一般位于Android SDK的tools目录下，其中ddms.bat就是用来启动DDMS的。DDMS中比较重要的功能主要是

- 文件浏览，我们可以观察并分析程序在执行过程中对文件的生成，修改，删除操作。
- Logcat，可以输出软件的一些调试信息。
- Method Profiling，可以跟踪程序的执行流程。

### IDEA/Android Studio

安装 smaliidea 插件，动态调试smali。

### IDA Pro

吾爱破解。

