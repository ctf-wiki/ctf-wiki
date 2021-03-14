# Randomness

本节讨论以太坊中的随机数问题。由于所有以太坊节点在验证交易时，需要计算出相同的结果以达成共识，因此 EVM 本身无法实现真随机数的功能。至于伪随机数，其熵源也是只能是确定值。下面讨论各种随机数的安全性，并介绍回滚攻击。

## 使用区块变量的伪随机数

EVM 有五个字节码可以获取当前区块的变量，包括 coinbase、timestamp、number、difficulty、gaslimit。这些变量对矿工来说，都是已知或者可操控的，因此在私有链部署的题目中，可以作为恶意的矿工控制随机数的结果。在公开的链如 Ropsten 上，这个方法就不太可行，但我们也可以编写攻击合约，在攻击合约中获取到相同的区块变量值，进一步用相同的算法得到随机数值。

### 题目
0ctf 2018 ZeroLottery

## 使用 Blockhash 的伪随机数

Blockhash 是一个特殊的区块变量，EVM 只能获取到当前区块之前的 256 个区块的 blockhash （**不含当前区块**），对于这 256 个之外的区块返回 0。使用 blockhash 可能存在几种问题。

1. 误用，如 `block.blockhash(block.number)` 恒为零。
2. 使用过去区块的有效 blockhash ，可以编写攻击合约获取相同值。
3. 将猜数字和开奖的交易分开在两个不同区块中，并且使用猜数字时还不知道的某个区块的 blockhash 作为熵源，则可以等待 256 个区块后再进行开奖，消除 blockhash 的不确定性。

### 题目
Capture The Ether - Predict the block hash、Guess the new number

## 使用私有变量的伪随机数

合约使用外界未知的私有变量参与随机数生成。虽然变量是私有的，无法通过另一合约访问，但是变量储存进 storage 之后仍然是公开的。我们可以使用区块链浏览器（如 etherscan）观察 storage 变动情况，或者计算变量储存的位置并使用 Web3 的 api 获得私有变量值，然后计算得到随机数。

## 外部参与的随机数

随机数由其他服务端生成。为了确保公平，服务端会先将随机数或者其种子的哈希写入合约中，然后待用户操作之后再公布哈希对应的明文值。由于明文空间有 256 位，这样的随机数生成方法相对安全。但是在明文揭露时，我们可以在状态为 pending 的交易中找到明文数据，并以更高的gas抢在之前完成交易确认。

## 回滚攻击

在某些情况下，获取随机数可能过于困难或繁琐，这时可以考虑使用回滚攻击。回滚攻击的概念很简单，输了就“耍赖”，通过抛出异常使整个交易回滚不作数。

### 例子

这里以 0ctf 2018 ZeroLottery 为例，部分关键代码如下。其中 `n` 为随机数，并且省略了其生成方式。

```solidity
contract ZeroLottery {
    ...
    mapping (address => uint256) public balanceOf;
    ...
    function bet(uint guess) public payable {
        require(msg.value > 1 ether);
        require(balanceOf[msg.sender] > 0);

        uint n = ...;

        if (guess != n) {
            balanceOf[msg.sender] = 0;
            // charge 0.5 ether for failure
            msg.sender.transfer(msg.value - 0.5 ether);
            return;
        }

        // charge 1 ether for success
        msg.sender.transfer(msg.value - 1 ether);
        balanceOf[msg.sender] = balanceOf[msg.sender] + 100;
    }
    ...
}
```

可以观察到题目合约在我们猜对或猜错时收费不同，分别为 1 ether 或 0.5 ether ，我们猜数时多给的钱会转账还给我们。结合智能合约收到转账时会调用 fallback 函数的知识点，假设每次使用 2 ether 去猜数，如果 fallback 函数收到 1.5 ether 就回滚。我们可以固定一个数字一直猜，只有猜对的交易才会被确认。

```solidity
function guess() public {
    task.bet.value(2 ether)(1);
}
function () public payable {
    require(msg.value != 1.5 ether);
}
```

并不是所有题目都涉及转账操作，但是通常都会有一个变量象征着正确次数等，ZeroLottery 中就有 `balanceOf[msg.sender]` 在猜对时会增加，猜错时清零，也可以通过它判断是否猜对。

```solidity
function guess() public {
    task.bet.value(2 ether)(1);
    require(task.balanceOf(this));
}
```

回滚攻击需要发送大量的交易来“碰运气”，因此建议在一个函数中连续猜同一个数字多次，以减少总交易数量。实际上，因为题目合约的 `bet` 函数自带了 `balanceOf` 非零的检查，如果我们连猜多次，失败了也会自动回滚。
