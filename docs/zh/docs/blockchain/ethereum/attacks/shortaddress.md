# Short Address Attack

## 原理

短地址攻击，利用 EVM 在参数长度不够时自动在右方补 0 的特性，通过去除钱包地址末位的 0，达到将转账金额左移放大的效果。

## 例子

```solidity
pragma solidity ^0.4.10;

contract Coin {
    address owner;
    mapping (address => uint256) public balances;

    modifier OwnerOnly() { require(msg.sender == owner); _; }

    function ICoin() { owner = msg.sender; }
    function approve(address _to, uint256 _amount) OwnerOnly { balances[_to] += _amount; }
    function transfer(address _to, uint256 _amount) {
        require(balances[msg.sender] > _amount);
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
    }
}
```

具体代币功能的合约 Coin，当 A 账户向 B 账户转代币时调用 `transfer()` 函数，例如 A 账户（0x14723a09acff6d2a60dcdf7aa4aff308fddc160c）向 B 账户（0x4b0897b0513fdc7c541b6d9d7e929c4e5364d2db）转 8 个 Coin，`msg.data` 数据为：

```
0xa9059cbb  -> bytes4(keccak256("transfer(address,uint256)")) 函数签名
0000000000000000000000004b0897b0513fdc7c541b6d9d7e929c4e5364d2db  -> B 账户地址（前补 0 补齐 32 字节）
0000000000000000000000000000000000000000000000000000000000000008  -> 0x8（前补 0 补齐 32 字节）
```

那么短地址攻击是怎么做的呢，攻击者找到一个末尾是 `00` 账户地址，假设为 0x4b0897b0513fdc7c541b6d9d7e929c4e5364d200，那么正常情况下整个调用的 `msg.data` 应该为：

```
0xa9059cbb  -> bytes4(keccak256("transfer(address,uint256)")) 函数签名
0000000000000000000000004b0897b0513fdc7c541b6d9d7e929c4e5364d200  -> B 账户地址（注意末尾 00）
0000000000000000000000000000000000000000000000000000000000000008  -> 0x8（前补 0 补齐 32 字节）
```

但是如果我们将 B 地址的 `00` 吃掉，不进行传递，也就是说我们少传递 1 个字节变成 4+31+32：

```
0xa9059cbb  -> bytes4(keccak256("transfer(address,uint256)")) 函数签名
0000000000000000000000004b0897b0513fdc7c541b6d9d7e929c4e5364d2  -> B 地址（31 字节）
0000000000000000000000000000000000000000000000000000000000000008  -> 0x8（前补 0 补齐 32 字节）
```

当上面数据进入 EVM 进行处理时，对参数进行编码对齐后补 `00` 变为：

```
0xa9059cbb
0000000000000000000000004b0897b0513fdc7c541b6d9d7e929c4e5364d200
0000000000000000000000000000000000000000000000000000000000000800
```

也就是说，恶意构造的 `msg.data` 通过 EVM 解析补 0 操作，导致原本 0x8 = 8 变为了 0x800 = 2048

上述 EVM 对畸形字节的 `msg.data` 进行补位操作的行为其实就是短地址攻击的原理

## 题目

这个目前没有题目，基本已经被修复。不过可以复现成功，但是不能通过 Remix 复现，因为客户端会检查地址长度；也不能通过 sendTransaction()，因为 `web3` 中也加了保护。

但是，可以使用 **geth** 搭建私链，使用 sendRawTransaction() 发送交易复现，可自行尝试。

!!! note
    注：目前主要依靠客户端主动检查地址长度来避免该问题，另外 `web3` 层面也增加了参数格式校验。虽然 EVM 层仍然可以复现，但是在实际应用场景中基本没有问题。