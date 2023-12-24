# 控制流平坦化

## 简介

控制流平坦化（control flow flattening）是作用于控制流图的代码混淆技术，其基本思想是重新组织函数的控制流图中的基本块关系，通过插入一个“主分发器”来控制基本块的执行流程，例如下图是正常的执行流程：

![](./images/before-flattening.png)

经过控制流平坦化处理之后便变成了这个样子，由一个“主分发器”负责控制程序执行流：

![](./images/after-flattenning.png)

通过控制流平坦化，基本块间的前后关系将被混淆，从而加大了程序逆向分析的难度。更多关于控制流平坦化的实现细节可以参考[这篇论文](http://ac.inf.elte.hu/Vol_030_2009/003.pdf).

## 利用符号执行去除控制流平坦化

> 待施工。

## Reference

[腾讯安全应急响应中心 - 利用符号执行去除控制流平坦化](https://security.tencent.com/index.php/blog/msg/112)

[OBFUSCATING C++ PROGRAMS VIA CONTROL FLOW FLATTENING](http://ac.inf.elte.hu/Vol_030_2009/003.pdf)