# Jump Oriented Programming

## 原理

类似于 pwn 中的 ROP，EVM 中也有 JOP（Jump Oriented Programming）。JOP 的思想和 ROP 是相似的：串联起一个个小的代码片段（gadget），达成一定的目的。

涉及到JOP 的是如下三个字节码：

- 0x56 JUMP
- 0x57 JUMPI
- 0x5B JUMPDEST

在 EVM 中的无条件跳转 `JUMP` 和条件跳转 `JUMPI` 的目的地都必须是 `JUMPDEST`，这点和 ROP 可以任选返回地址不同。

另外需要注意的是，EVM 虽然使用的是变长指令，但是不允许像 ROP 那样跳到一条指令的中间。比如 64 位的 `pop r15` 是 `A_`，ROP 时直接落在第二个字节则可以当成 `pop rdi` 使用；EVM `PUSH1 0x5B` 中的 `0x5B` 则不能当作 `JUMPDEST` 使用。

通常需要用到 JOP 的合约在编写时都夹杂着内联汇编的后门，需要人工逆向识别查找两样东西：

1. 通常控制流可达、可以控制跳转地址的起点
1. `JUMPDEST` 之后实现了一些特殊功能，然后再接一个 `JUMP` 指令的各种 gadget

gadget 需要实现的功能因题目要求或考察点而异，比如要实现一个外部合约的调用，就要先按照顺序将各种偏移、gas等数据布置在栈上。在 JOP 的最后需要一个 `JUMPDEST; STOP` 作为结束的着陆点，否则一旦执行出错就会导致交易回滚。

除了以上的三个字节码，EIP-2315 还提出了 `BEGINSUB`、`RETURNSUB`、`JUMPSUB` 三个字节码。其中 `JUMPSUB` 和 `JUMP` 相似，只是跳转的目的地必须是 `BEGINSUB`；而 `RETURNSUB` 相当于 ROP 中的 `ret`，对目标地址没有限制。EIP-2315 在柏林升级前曾被列入升级列表，不久后又被移除，目前仍处于草案阶段。

## 题目

### RealWorldCTF Final 2018
- 题目名称 Acoraida Monica

### RealWorldCTF 3rd 2021
- 题目名称 Re: Montagy

!!! note
    注：题目附件相关内容可至 [ctf-challenges/blockchain](https://github.com/ctf-wiki/ctf-challenges/tree/master/blockchain) 仓库寻找。
