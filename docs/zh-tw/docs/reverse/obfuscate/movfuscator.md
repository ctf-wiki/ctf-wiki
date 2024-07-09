# movofuscator

## 簡介

[movobfuscator](https://github.com/xoreaxeaxeax/movfuscator) 是一個通過**將常規 x86 指令替換爲等價的 mov 指令**來完成代碼混淆的混淆器，得益於 `mov` 指令滿足圖靈完備性質，所有的指令都可以通過由 `mov` 指令組成的代碼片段進行等價代換，同時保持程序邏輯不變。

由於 mov 混淆的特殊性，目前暫時沒有較爲高效的反混淆手段，現階段如 [demovobfuscator](https://github.com/leetonidas/demovfuscator) 等反混淆器可以完成初步的去混淆工作。

## 例題：強網擬態 2023 決賽 - movemove

> 待施工。