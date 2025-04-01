# Chromium

## 概述

[Chromium](https://www.chromium.org/Home/) 是 [The Chromium Projects](https://www.chromium.org/chromium-projects/) 下属的开源浏览器项目，其使用包括 BSD 3-clause 在内的多重许可证，主要编写语言是 C++ ，源代码可以从 [https://chromium.googlesource.com/chromium/src/+/HEAD/docs/get_the_code.md](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/get_the_code.md) 获取。

[Google Chrome](https://www.google.com/chrome/) 则是 Google 基于 Chromium 开发的浏览器，Google 的开发者在其中加入了属于 Google 的专有代码（Google 账户、标签同步、媒体解码器等功能），使其成为 Google 的专有项目。

目前世界上绝大部分仍在活跃的浏览器都基于 Chromium 进行开发（以 chromium 作为内核），包括放弃了自有浏览器内核的 [Microsoft Edge](https://www.microsoft.com/en-us/edge/) ， 仅有 [Firefox](https://www.mozilla.org/en-US/firefox/new/) 与 [Safari](https://www.apple.com/safari/) 仍在坚持使用其他的内核。

![](https://s2.loli.net/2025/03/08/3u7rOs6j4gQJzRa.png)

——但事实上浏览器并不是这么三言两语就能概括掉的东西，Chromium 本身是一个完整的浏览器项目，其渲染引擎是 [Blink](https://www.chromium.org/blink/)，这也是微软主要依赖于 Chromium 的东西（因为他自有的那套衍生自 IE 时代的 Trident 引擎的 EdgeHTML 引擎实在是差点意思），相对应的 Safari 的渲染引擎是 [开源的 WebKit](https://webkit.org/)、Firefox 的渲染引擎是 [开源的 Gecko](https://firefox-source-docs.mozilla.org/overview/gecko.html) ，但在此之外的 JavaScript 引擎微软使用的是自研的 [开源的 Chakra](https://github.com/chakra-core/ChakraCore) （ ~~啊我草二次元怎么这么多~~ ）而非 Chromium 的 [V8](https://v8.dev/) ，相应地 Safari 的 JS 引擎是自己的 [Nitro]() 、Firefox 的 JS 引擎是自研的 [开源的 SpiderMonkey](https://spidermonkey.dev/) ......

> 这也是为什么当我们提到自研的浏览器时通常仅认为只有 4 个的缘故，其他的各自基于 chromium 套皮贴牌的所谓“自研”浏览器，一没自己的排版引擎二没自己的JS引擎三没自己的网络栈...总而言之硬核部分全都不是自研的，那这是否就有点

那浏览器又是如何工作的？可能有的人会想“不就是拿到一个 HTML 文件解析一下然后在屏幕上画出来嘛”—— **仅** 放在渲染引擎上来说，似乎确实可以就这样概况？渲染引擎吃掉服务器发来的的 HTML、CSS、JS 文件等，进行解析后交给 GPU 在屏幕上画出来：

![](https://s2.loli.net/2025/03/08/6ObUMxFAh5Tkvw1.png)

稍微一展开是这个样子（HTTP Client 就是浏览器）：

![](https://s2.loli.net/2025/03/08/OLtXs5rTjk2i7pG.png)

HTML 解析出来是表示内容的 DOM Tree，CSS 解析出来是表示布局 CSSOM Tree，合起来是包含具体渲染信息的 Render Tree，再加上 JS Engine 进行动态的内容调整和各种幕后工作，现代浏览器的雏形好像就这么形成了：

![](https://s2.loli.net/2025/03/08/6agfHueKnjmJCB1.png)

不过虽然看起来哪怕是初学编译原理的本科生都能用递归下降手搓一个简易的解析引擎，但实际上要实现现代 Web 标准再加上足够高的性能，背后的工作量远比绝大部分人想象中的要多得多，无论是浏览器背后的网络协议栈还是内存管理和多进程架构或是渲染引擎和 JS 引擎的实现细节单独拿一小块出来都能单独写上好多篇论文，理论上应该没有一个开发者能够独立地把所有部分讲清楚，而且本文的重点也不在整个浏览器如何工作，所以这里也不会深入展开：）

![](https://s2.loli.net/2025/03/08/AxTcI3XVnUyZ68l.png)

## Chromium Render Process

Chromium 的运行架构大体如下图所示（这些进程间的通信通常通过 [Mojo](https://chromium.googlesource.com/chromium/src/+/lkgr/mojo/README.md) 这一 IPC Engine 完成）：

![为什么这么卡通？因为笔者没有找到其他更合适的图...](https://s2.loli.net/2025/03/08/63bwqkTr1WAXm5g.png)

Browser Process 负责网络请求处理、存储管理、UI 等（上图的左中右三个线程），当完成网络请求内容的接收之后，其会将页面数据传递给 Render Process 进行渲染：

![](https://s2.loli.net/2025/03/08/wj6VW8IsRpQlG4Y.png)

Render Process 首先对 HTML、CSS、JavaScript 内容进行解析，前文我们已经讲到 HTML 的解析最后会产生 DOM Tree，而 JavaScript 便在此时 **阻塞 HTML 的解析并优先被解析与运行** ——这是因为 JS 代码可能会改变文档内容（例如使用 `document.write()` ）。

> 如果你的 HTML 内嵌的 JS 代码不使用 `document.write()` ，可以为 `<script>` 标签使用  [async](https://developer.mozilla.org/docs/Web/HTML/Element/script#attr-async) 或 [defer](https://developer.mozilla.org/docs/Web/HTML/Element/script#attr-defer) 特性，从而异步运行 JS 以不阻塞解析过程

![](https://s2.loli.net/2025/03/08/hcvo3XOuCgVNs1k.png)

> 待施工。

## Reference

https://arttnba3.cn

[What Are Rendering Engines: An In-Depth Guide](https://www.lambdatest.com/learning-hub/rendering-engines)

[RenderingNG deep-dive: BlinkNG](https://developer.chrome.com/docs/chromium/blinkng)

[How Does the Browser Render HTML?](https://component-odyssey.com/tips/02-how-does-the-browser-render-html)

[Browser's Rendering Pipeline](https://www.figma.com/community/file/1327562660128482813/browsers-rendering-pipeline)

[Inside look at modern web browser (part 1) ](https://developer.chrome.com/blog/inside-browser-part1)

[JavaScript engine fundamentals: Shapes and Inline Caches](https://mathiasbynens.be/notes/shapes-ics)

[Winty's blog - 现代浏览器架构漫谈](https://github.com/LuckyWinty/blog/blob/master/markdown/Q%26A/%E7%8E%B0%E4%BB%A3%E6%B5%8F%E8%A7%88%E5%99%A8%E6%9E%B6%E6%9E%84%E6%BC%AB%E8%B0%88.md)

[Firing up the Ignition interpreter](https://v8.dev/blog/ignition-interpreter)

[Digging into the TurboFan JIT](https://v8.dev/blog/turbofan-jit)

[Ignition: Jump-starting an Interpreter for V8](https://docs.google.com/presentation/d/1HgDDXBYqCJNasBKBDf9szap1j4q4wnSHhOYpaNy5mHU/edit#slide=id.g1357e6d1a4_0_58)

[Ignition: An Interpreter for V8](https://docs.google.com/presentation/d/1OqjVqRhtwlKeKfvMdX6HaCIu9wpZsrzqpIVIwQSuiXQ/edit#slide=id.g1357e6d1a4_0_58)

[Deoptimization in V8](https://docs.google.com/presentation/d/1Z6oCocRASCfTqGq1GCo1jbULDGS-w-nzxkbVF7Up0u0/htmlpresent) 

[A New Crankshaft for V8](https://blog.chromium.org/2010/12/new-crankshaft-for-v8.html)

[TurboFan](https://v8.dev/docs/turbofan)

[Sea of Nodes](https://darksi.de/d.sea-of-nodes/)

[TurboFan: A new code generation architecture for V8](https://docs.google.com/presentation/d/1_eLlVzcj94_G4r9j9d_Lj5HRKFnq6jgpuPJtnmIBs88/edit#slide=id.g2134da681e_0_125)
