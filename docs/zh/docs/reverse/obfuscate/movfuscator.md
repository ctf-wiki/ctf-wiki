# movofuscator

## 简介

[movobfuscator](https://github.com/xoreaxeaxeax/movfuscator) 是一个通过**将常规 x86 指令替换为等价的 mov 指令**来完成代码混淆的混淆器，得益于 `mov` 指令满足图灵完备性质，所有的指令都可以通过由 `mov` 指令组成的代码片段进行等价代换，同时保持程序逻辑不变。

由于 mov 混淆的特殊性，目前暂时没有较为高效的反混淆手段，现阶段如 [demovobfuscator](https://github.com/leetonidas/demovfuscator) 等反混淆器可以完成初步的去混淆工作。

## 例题：强网拟态 2023 决赛 - movemove

> 待施工。