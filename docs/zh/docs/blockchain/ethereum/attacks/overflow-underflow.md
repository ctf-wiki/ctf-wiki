# Integer Overflow and Underflow

## 原理 

EVM的整数有 `int` 和 `uint` 两种，对应有无符号的情况。在 `int` 或 `uint` 后可以跟随一个8的倍数，表示该整数的位数，如8位的 `uint8`。位数上限为256位，`int` 和 `uint` 分别是 `int256` 和 `uint256` 的别名，一般 `uint` 使用的更多。

在整数超出位数的上限或下限时，就会静默地进行取模操作。通常我们希望费用向上溢出变小，或者存款向下溢出变大。整数溢出漏洞可以使用 SafeMath 库来防御，当发生溢出时会回滚交易。

## 例子

以 Capture The Ether 的 Token sale 为例：

```solidity
pragma solidity ^0.4.21;

contract TokenSaleChallenge {
    mapping(address => uint256) public balanceOf;
    uint256 constant PRICE_PER_TOKEN = 1 ether;

    function TokenSaleChallenge(address _player) public payable {
        require(msg.value == 1 ether);
    }

    function isComplete() public view returns (bool) {
        return address(this).balance < 1 ether;
    }

    function buy(uint256 numTokens) public payable {
        require(msg.value == numTokens * PRICE_PER_TOKEN);

        balanceOf[msg.sender] += numTokens;
    }

    function sell(uint256 numTokens) public {
        require(balanceOf[msg.sender] >= numTokens);

        balanceOf[msg.sender] -= numTokens;
        msg.sender.transfer(numTokens * PRICE_PER_TOKEN);
    }
}
```

在本题中，购买单个代币需要支付 1 ether，即 `msg.value == numTokens * PRICE_PER_TOKEN`。在EVM中，货币以 wei 为单位，1 ether 实际上是 $10 ^ { 18 }$ wei，即 0xde0b6b3a7640000 wei。如果让这里的 `numTokens` 大一些，乘积就可能溢出。例如我们购买 $2 ^ { 256 } // 10 ^ { 18 } + 1$ 个代币，乘上 $10 ^ { 18 }$ 后就发生了溢出，最终花费仅约 0.4 ether 就买到了大量代币。然后我们将买到的代币部分卖出，即可完成题目要求。

整数下溢的一个例子是减法操作。假设有一个合约实现了如下功能：

```solidity
contract Bank {
    mapping(address => uint256) public balanceOf;
    ...
    function withdraw(uint256 amount) public {
        require(balanceOf[msg.sender] - amount >= 0);
        balanceOf[msg.sender] -= amount;
        msg.sender.send.value(amount)();
    }
}
```

乍看之下没有问题，实际上 require 一行，`balanceOf[msg.sender]-amount` 的结果作为无符号整数，永远是大于等于 0 的，导致我们可以任意取款。正确的写法是 `require(balanceOf[msg.sender] >= amount)`。

整数下溢的另一个例子与重入攻击有关，如将持有数为 1 的物品卖出两次，或者将 1 ether 存款取出两次，导致结果为负数，储存为 uint 则为巨大的正数。

## 题目

绝大部分重入攻击的题目都涉及到向下溢出，可参照重入攻击的部分。不涉及重入攻击的相对较少，可以参考以下题目。

### ByteCTF 2019
- 题目名称 hf
- 题目名称 bet

!!! note
    注：题目附件相关内容可至 [ctf-challenges/blockchain](https://github.com/ctf-wiki/ctf-challenges/tree/master/blockchain) 仓库寻找。
