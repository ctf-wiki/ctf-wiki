# Jump Oriented Programming

## 原理

類似於 pwn 中的 ROP，EVM 中也有 JOP（Jump Oriented Programming）。JOP 的思想和 ROP 是相似的：串聯起一個個小的代碼片段（gadget），達成一定的目的。

涉及到JOP 的是如下三個字節碼：

- 0x56 JUMP
- 0x57 JUMPI
- 0x5B JUMPDEST

在 EVM 中的無條件跳轉 `JUMP` 和條件跳轉 `JUMPI` 的目的地都必須是 `JUMPDEST`，這點和 ROP 可以任選返回地址不同。

另外需要注意的是，EVM 雖然使用的是變長指令，但是不允許像 ROP 那樣跳到一條指令的中間。比如 64 位的 `pop r15` 是 `A_`，ROP 時直接落在第二個字節則可以當成 `pop rdi` 使用；EVM `PUSH1 0x5B` 中的 `0x5B` 則不能當作 `JUMPDEST` 使用。

通常需要用到 JOP 的合約在編寫時都夾雜着內聯彙編的後門，需要人工逆向識別查找兩樣東西：

1. 通常控制流可達、可以控制跳轉地址的起點
1. `JUMPDEST` 之後實現了一些特殊功能，然後再接一個 `JUMP` 指令的各種 gadget

gadget 需要實現的功能因題目要求或考察點而異，比如要實現一個外部合約的調用，就要先按照順序將各種偏移、gas等數據佈置在棧上。在 JOP 的最後需要一個 `JUMPDEST; STOP` 作爲結束的着陸點，否則一旦執行出錯就會導致交易回滾。

除了以上的三個字節碼，EIP-2315 還提出了 `BEGINSUB`、`RETURNSUB`、`JUMPSUB` 三個字節碼。其中 `JUMPSUB` 和 `JUMP` 相似，只是跳轉的目的地必須是 `BEGINSUB`；而 `RETURNSUB` 相當於 ROP 中的 `ret`，對目標地址沒有限制。EIP-2315 在柏林升級前曾被列入升級列表，不久後又被移除，目前仍處於草案階段。

## 題目

### RealWorldCTF Final 2018
- 題目名稱 Acoraida Monica

### RealWorldCTF 3rd 2021
- 題目名稱 Re: Montagy

!!! note
    注：題目附件相關內容可至 [ctf-challenges/blockchain](https://github.com/ctf-wiki/ctf-challenges/tree/master/blockchain) 倉庫尋找。
