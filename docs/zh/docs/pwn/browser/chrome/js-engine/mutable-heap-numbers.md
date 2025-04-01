# Mutable Heap Numbers

**堆数量不可变** 机制是 2025 年 V8 团队公开的优化机制，其思路来源于于 `async-fs` 这一 JS 文件系统实现在 `Math.random` 上的运行瓶颈，例如对于下面的这样一段代码：

```javascript
let seed;
Math.random = (function() {
  return function () {
    seed = ((seed + 0x7ed55d16) + (seed << 12))  & 0xffffffff;
    seed = ((seed ^ 0xc761c23c) ^ (seed >>> 19)) & 0xffffffff;
    seed = ((seed + 0x165667b1) + (seed << 5))   & 0xffffffff;
    seed = ((seed + 0xd3a2646c) ^ (seed << 9))   & 0xffffffff;
    seed = ((seed + 0xfd7046c5) + (seed << 3))   & 0xffffffff;
    seed = ((seed ^ 0xb55a4f09) ^ (seed >>> 16)) & 0xffffffff;
    return (seed & 0xfffffff) / 0x10000000;
  };
})();
```

变量 `seed` 在每次调用 `Math.random` 时都会发生变动，从而生成一个伪随机序列，关键的一点是 `seed` 被存放在一个 `ScriptContext` 当中，该结构用以表示特定脚本内可访问值的存储位置（说人话就是 **一个 JS 脚本的上下文** ），该结构内部是一个 V8 的标记值的数组：

- ScopeInfo：上下文元数据。
- NativeContext：全局对象。
- Slot 0 ～ Slot n：其他各种各样的值。

这些 Slot 的值通常为 32 位，每个值的最低有效位用作标记，因此使用时都会将该值右移 1 位：

- 0：31 位小整数（small interger，SMI）。
- 1：31 位指针。

相应地，大于 31 位的数据都会存放在堆上，由 ScriptContext 的 Slot 存储指向这些对象的指针，例如对于简单的数值类型据而言会使用一个 `HeapNumber` 对象存放，对于复杂对象则是 `JSObject` 结构体一类的。

![](https://s2.loli.net/2025/03/11/BEhSayrC24XJ6Tq.png)

那么瓶颈就来了：

- **HeapNumber allocation**： 上面的 JS 代码中 `seed` 变量存放在一个 `HeapNumber` 对象当中，那么每次 `Math.random` 函数调用时都会进行内存分配与释放。
- **Floating-point arthmetic** ：虽然 `Math.random` 全程使用整型操作，但 `seed` 存放在一个通用的 `HeapNumber` 当中，从而导致编译器生成较慢的浮点数操作指令，以及在编译器已知这可能是一个 32 位整型的情况下仍会需要潜在的 64 位浮点到 32 位整型的转换以及精度损失检查。

如何破局？V8 团队采用了两部分优化：

- **Slot type tracking / mutable heap number slots** ：V8 团队扩展了 [script context const value tracking](https://issues.chromium.org/u/2/issues/42203515) 以包含类型信息，从而追踪一个 slot value 是一个常量、`SMI`、`HeapNumber` 还是通用标记值，并在脚本上下文中引入了`JSObjects` 的 [mutable heap number fields](https://v8.dev/blog/react-cliff#smi-heapnumber-mutableheapnumber) 概念的 **不可变堆数量** 的概念：slot value 从指向一个变化的 `HeapNumber` 变为 **持有一个 HeapNumber** ——从而消除了代码优化更新时的堆重分配。
- **Mutable heap Int32** ：V8 团队增强了 script context slot 类型以追踪一个数字值是否在 Int32 的范围内，若是则 `HeapNumber` 将其存放为一个纯 `Int32` ，若需要扩展为 `double` 则不会需要重分配 `HeapNumber` 的空间；在这种情况下，上面例子中的 `Math.random` 在编译器观察下便知道这是一个持续更新的整型值，因而将对应的 slot 标记为一个 mutable `Int32` 。

需要注意的是这样的优化引入了对 context slot 的值的代码依赖，若是 slot 的类型发生了改变（如变为字符串），则该优化会被回退，因此保证 slot 的类型稳定性至关重要（ ~~言外之意就是别老给一个 JS 变量换类型~~ ）。

最终，对于 `Math.random` 的优化结果如下：

- **No allocation / fast in-place updates** ：`seed` 的更新不需要重复分配新的堆对象。
- **Integer operations** ：编译器已知其类型为 `Int32` ，故避免了生成低效的浮点运算。

最终 `async-fs` 的基准测试速度提升了 2.5 倍 ，在 [JetStream2](https://browserbench.org/JetStream2.1/) 这一基准测试上提升了约 `1.6%` 的整体分数，还是很有效果的。