# V8 Design History

这一节给大家大概了解一下 V8 的发展历程，仅供大家进行扩展阅读。

### 2008: Full-code Generation + Semi-optimization

此时 V8 刚刚面世，简而言之使用的是全量代码生成的方案： **所有的 JS 代码都进行 JIT 编译生成对应架构的机器码** ，再进行一小部分优化

![](https://s2.loli.net/2025/03/11/LeisDWScb2ZVUC1.png)

### 2010: Full-code Generation + Crankshaft JIT Compiler & Optimizer

修修补补两年后，V8 开发组将原有的代码优化部分拆分出来，作为一个单独的 JIT compiler，称之为 [Crankshaft](https://blog.chromium.org/2010/12/new-crankshaft-for-v8.html) ，JS 代码的编译管线也多了一个到 Crankshaft 的分支，同时 V8 也开始引入了 Deoptimization 的机制：

![](https://s2.loli.net/2025/03/11/cd1xWp8gA5wnyhD.png)

> JS 代码生成的 AST 什么时候给到原有的全量代码编译引擎？什么时候给到 Crankshaft？ 这其实主要是根据 chromium 所开启的配置选项决定，此时 chromium 的运行模式可以是先将 JS 给到原有的全量代码生成引擎再给到 Crankshaft 进行优化，也可以是直接给 Crankshaft。

### 2014: Full-code Generation + Crankshaft / TurboFan JIT Compiler & Optimizer

又过了四年，全新的名为 [TurboFan](https://v8.dev/docs/turbofan) 的 JavaScript JIT Compiler + Optimizer 横空出世，此时的编译管线变成下面这个样子，原有的管线额外分叉出指向 TurboFan 的路径，TurboFan 和 Crankshaft 并行存在：

![](https://s2.loli.net/2025/03/11/7Ptx93koOHsIi12.png)

> JS 代码生成的 AST 什么时候给到原有的全量代码编译引擎？什么时候给到 Crankshaft？什么时候给到 TurboFan？和前面一样，这同样是根据具体的配置选项决定 。

### 2016: Ignition Interpreter + Full-code Generation + Crankshaft / TurboFan JIT Compiler & Optimizer

又过了两年，名为 [Ignition](https://v8.dev/blog/ignition-interpreter) 的 JS 解释器横空出世，V8 engine **首次引入了解释执行的概念** ，原因是全量代码生成还是太耗时空间也太拖执行效率了，哪怕是有了强大的 TurboFan 的辅助也不如直接解释执行来得快，因此从这一年开始解释执行成为 V8 执行 JS 代码的主要方式：

![](https://s2.loli.net/2025/03/11/CocnM4vmT8qpXwx.png)

Ignition 此时是一个 _可选特性_ ，对于开启了 Ignition 的 V8，JS AST 会给到 Ignition 生成 bytecode 后进行解释执行，对于运行较多的 bytecode 会给到 TurboFan 进行 JIT 编译生成机器码，或是给到原有的全量代码生成 + Crankshaft 优化的路径；而未开启 Ignition 的 V8 则走的是原来的全量代码生成 + Crankshaft 优化的路径（梦回 2010 了属于是）。

> 这个时候的整个编译管线变得又大又麻了，于是新的一轮架构优化便是必有的事情——

### 2017: Ignition Interpreter + TurboFan JIT Compiler

又过了一年大家发现有了 Ignition 和 TurboFan 这两个威猛的大家伙之后， _全量代码生成的 JIT Compiler 和老旧的 Crankshaft 似乎没有什么存在的必要了， 于是这两个组件就被直接移除了_  ，**编译管线就变为简洁的 Ignition Interpreter + TurboFan JIT Compiler**，V8 团队为此激动地发了一篇名为 [Launching Ignition and TurboFan](https://v8.dev/blog/launching-ignition-and-turbofan) 的文章，解释执行也最终成为了 V8 Engine 的缺省执行 JS 代码的方式：

![](https://s2.loli.net/2025/03/11/CX81DoyTBaeV46n.png)

> 后面编译管线就基本没发生过什么变化了，开发者不语只是一味地在这两座大山上继续进行修修补补......