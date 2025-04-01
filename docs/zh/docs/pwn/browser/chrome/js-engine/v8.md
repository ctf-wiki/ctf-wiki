# V8 Engine Intro

Chromium 使用的 JS 引擎叫 [V8](https://v8.dev/) ，这是一个 Google 开发的开源的使用 C++ 编写的 JavaScript 与 WebAssembly 引擎，其实现了 [ECMAScript](https://tc39.es/ecma262/) 与 [WebAssembly](https://webassembly.github.io/spec/core/) ，且能在 X64、IA-32、ARM 架构的 Windows、macOS、Linux 系统上运行。

V8 本质上可以算是一个 JavaScript 虚拟机，其发展历程为：

- 在最初（2008 年）通过一个 JIT compiler 对 JS 代码进行 **全量即时编译** 的方式运行，生成的代码称为 `Baseline Code` 
- 2010 年时引入了名为 [Crankshaft](https://blog.chromium.org/2010/12/new-crankshaft-for-v8.html) 的新的 JIT compiler，其 **基于全量代码生成的结果进行优化** ，有着类型反馈与 deoptimization 的功能，相应地我们将优化后的代码称为 `Optimized Code`
- 2015 年引入了名为 [TurboFan](https://v8.dev/docs/turbofan) 的新的 JIT compiler， _用于取代 Crankshaft_ ，也是现在 V8 所主力使用的 JIT compiler，有着类型分析、[sea of node](https://darksi.de/d.sea-of-nodes/) 等高级功能
- 2016 年引入了名为 [Ignition](https://v8.dev/blog/ignition-interpreter) 的 **JS 解释器** ，也是现在 V8 最主要的运行 JS 代码的方式
- 2017 年编译管线大改，**仅留下了精简的 Ignition + TurboFan 的结构** ，并沿用至今

V8 本身可以作为一个单独的 C++ 项目来看待，且能很方便地被整合到其他 C++ 应用当中，目前 V8 Engine已经能支持九种不同的指令集架构，且被广泛用于 Nodejs 与 Chrome 等大型项目中。

## 架构 & 编译管线

V8 Engine 的顶层架构设计如下图所示：

![](https://s2.loli.net/2025/03/09/Jx1al6Qbemqhuig.png)

- 读入 JavaScript 源码后，Parser 首先会将其解析成 AST 这样的中间表示
- 中间表示会交给名为 [Ignition Interpreter](https://v8.dev/blog/ignition-interpreter) 的解释器进行翻译，生成简洁的字节码（大小仅为基准机器码的 25～50%）
- JavaScript 是一门解释型语言，因此完成字节码翻译后会由 Ignition 进行解释执行
- 对于高频执行的或是处于其他原因被认为需要优化的代码，Ignition Interpreter 会将翻译后的字节码交由 [TurboFan Compiler](https://v8.dev/docs/turbofan) 进行即时编译（Just-In-Time Compilation）： **直接在内存中生成对应的机器码** 

此外，V8 Engine 当中还有一个特殊的设计叫 [Deoptimization](https://docs.google.com/presentation/d/1Z6oCocRASCfTqGq1GCo1jbULDGS-w-nzxkbVF7Up0u0/htmlpresent) ：将 TurboFan 生成的机器码 _反向翻译回字节码，重新交回 Ignition 解释执行_ ，这通常出现于以下两种场景：

- Eager Deoptimization：在类似  JIT code 执行出错（例如动态检查未通过）的情况下会出现，此时会立即放弃执行 JIT code，调用 deoptimizer 翻译回 bytecode，再交由 interpreter 解释执行
- Lazy Deoptimization：例如某个全局变量发生了改变，依赖该变量的代码会被认为需要 deoptimization，但只会先进行 patch，在执行到对应代码时再调用 deoptimizer

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