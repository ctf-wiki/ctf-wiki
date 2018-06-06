# Android 应用运行机制简述

本部分主要关注 Android 中 Java 层代码与 Native 层代码的基本运行原理。

一般而言，在启动一个 App 时，Android 会首先执行 Application 类（AndroidManifest.xml 文件中注明）的创建工作，然后再开始执行 Main Activity，继而根据各种各样的逻辑执行相关代码。

注：本部分的内容可能存在以下问题

- 简略
- 理解不到位

如果发现可以补充的地方，欢迎随时及时补充。当然，本部分内容也会随着时间不断更新。