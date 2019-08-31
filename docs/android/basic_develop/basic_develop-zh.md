[EN](./basic_develop.md) | [ZH](./basic_develop-zh.md)
# Android 开发基础

在做 Android 安全之前，我们应该尽可能地了解 Android 开发的基本流程。

## 基础知识

依次阅读以下书籍，由浅入深地了解 Android 基本开发知识

- 第一行代码，阅读完前七章即可
- JNI/NDK 开发，目前尚未找到一本相关合适的指南。
- Android 编程权威指南（可选）
- Android 高级进阶（可选）

在学习的过程中，个人觉得需要着重了解 Android 开发中如下知识

- Android 系统架构
- 基本源文件架构
- 基本开发方式与代码编写惯例，了解常见代码的意思。
- 了解 xml 等一些配置资源的文件格式。

**一定要搭好基本的 Android 开发环境！！！！！**

- java
- ddms
- ndk
- sdk，多安装几个版本的 sdk，5.0-8.0

## Apk 打包流程

当编写完 App 相关的代码后，我们的最后一步就是将 App 中所有使用到的资源文件进行打包，打包流程如下图（<u>http://androidsrc.net/android-app-build-overview/</u>）所示：

![](./figure/android_app_build.png)

具体的操作如下

1. 使用 aapt( The Android Asset Packing Tool ) 对资源文件进行打包，生成 R.java 文件。
2. 如果项目中使用到了 AIDL（Android Interface Definition Language）提供的服务，则需要使用 AIDL 工具解析 AIDL 接口文件生成相应的 Java 代码。
3. 使用 javac 将 R.java 和 AIDL 文件编译为 .class 文件。
4. 使用 dx 工具将 class 和第三方的 library 转换为 dex 文件。
5. 利用 apkbuilder 将第一步编译后的资源、第四步生成的 .dex 文件，以及一些其它资源打包到 APK 文件中。
6. 这一部主要是对 APK 进行签名。可以分为两种情况，如果我们是要发布 App，那就采用 RealeaseKeystore  签名；反之，我们如果只是想要对 App 进行调试，那就使用 debug.keystore 签名。
7. 在发布正式版之前，我们需要将 APK 包中资源文件距离文件的起始偏移修改为 4 字节的整数倍数，这样，在之后运行 App 的时候，速度会比较快。

## Apk 文件结构

APK 文件也是一种 ZIP 文件。因此，我们可以使用解压 zip 的工具来对其进行解压。一个典型的 APK 文件的结构如下图所示。其中，关于每一部分的介绍如下

![](./figure/apk_structure.png)


- AndroidManifest.xml

    - 该文件主要用于声明应用程序的名称，组件，权限等基本信息。

- class.dex
    - 该文件是 dalvik 虚拟机对应的可执行文件，包含应用程序的可执行代码。
- resource.arsc
    - 该文件主要是应用程序编译后的二进制资源以及资源位置与资源 id 之间的映射关系，如字符串。
- assets
    - 该文件夹一般用于包含应用程序的原始资源文件，例如字体和音乐文件。程序在运行的时候，可以通过API 获取这些信息。
- lib/
    - lib目录下主要用于存储通过 JNI（Java Native Interface）机制使用的本地库文件，并且会按照其支持的架构，分别创建对应的子目录。
- res/
    - 该目录主要包含了 Android 应用引用的资源，并且会按照资源类型进行存储，如图片，动画，菜单等。主要还有一个 value 文件夹，包含了各类属性资源
- colors.xml-->颜色资源
- dimens.xml--->尺寸资源
- strings--->字符串资源
- styles.xml-->样式资源
- META-INF/
    - 类似于 JAR 文件，APK 文件中也包含了 META-INF 目录，用于存放代码签名等文件，以便于用来确保 APK 文件不会被人随意修改。
