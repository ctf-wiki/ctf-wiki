# Ignition Interpreter

[Ignition Interpreter](https://v8.dev/blog/ignition-interpreter) 是 V8 当中的 JS 解释器，其将 Parser 前端生成的抽象语法树首先翻译为字节码，之后再解释执行字节码，工作管线如下图所示：

![](https://s2.loli.net/2025/03/09/D2ibKIsxh1zPZVF.png)

- 首先将 Parser 生成的抽象语法树翻译成基本的字节码，Ignition 的虚拟机被设计为最常见的的寄存器机（register machine，字节码中输入和输出显式地指定为寄存器操作数）
- 接下来字节码会经过一系列的中间优化阶段
    - 首先是针对字节码所使用的寄存器的优化，例如减少不必要的寄存器间的拷贝等
    - 接下来是针对指令序列的优化，即将指令序列替换为等价的更优指令，这包括删除无用操作、等价操作简化等
    - 最后是常规的死代码消除阶段，例如移除不会被执行的代码和不会用到的变量等
- 完成优化后 Ignition Interpreter 对字节码进行解释执行

>  需要注意的是这一系列工作都在后台由 Script Streamer Thread 并行运行，从而减少前台主线程的压力。

## Ignition Bytecodes

Ignition Bytecode 为定长指令集，背后对应的机器架构被设计为最常见的的寄存器机，完整的 bytecode 列表如下图所属：

![](https://s2.loli.net/2025/03/11/Nm7DB84FzYrZJL2.png)

例如以下是一个 JS 代码翻译为 Ignition Bytecode 的例子（初始状态）：

![](https://s2.loli.net/2025/03/11/gnlRaNOybFAYmVT.png)

## Why Interpret？

事实上， **在 Ignition 出现前，JS 被直接翻译成未优化的机器码** ，必要时再由 TurboFan 等进行优化（在不开启 Ignition 的情况下，V8 仍旧是这么工作的），Ignition Interpreter 的出现改变了 V8 的核心执行逻辑， **那么为什么要使用解释执行？** 

这主要出于以下考虑：

- Ignition 字节码占用的内存空间更小（基准机器码的 25～50%）
- Ignition 字节码的翻译更快（反正比翻译成机器码快 ）
- Ignition 字节码的复杂度更低，从而能简化编译管线

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