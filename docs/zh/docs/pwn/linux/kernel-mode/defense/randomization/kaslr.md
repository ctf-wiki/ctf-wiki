# KASLR

## 介绍

在开启了 KASLR 的内核中，内核的代码段基地址等地址会整体偏移。

## 发展历史

TODO。

## 实现

TODO。

## 开启与关闭

如果是使用 qemu 启动的内核，我们可以在 `-append` 选项中添加 `kaslr` 来开启 KASLR。

如果是使用 qemu 启动的内核，我们可以在 `-append` 选项中添加 `nokaslr` 来关闭 KASLR。

## Attack

通过泄漏内核某个段的地址，就可以得到这个段内的所有地址。比如当我们泄漏了内核的代码段地址，就知道内核代码段的所有地址。

## 参考

- https://outflux.net/slides/2013/lss/kaslr.pdf
- https://bneuburg.github.io/volatility/kaslr/2017/04/26/KASLR1.html

