# Integer Overflow and Underflow

## 原理 

EVM的整數有 `int` 和 `uint` 兩種，對應有無符號的情況。在 `int` 或 `uint` 後可以跟隨一個8的倍數，表示該整數的位數，如8位的 `uint8`。位數上限爲256位，`int` 和 `uint` 分別是 `int256` 和 `uint256` 的別名，一般 `uint` 使用的更多。

在整數超出位數的上限或下限時，就會靜默地進行取模操作。通常我們希望費用向上溢出變小，或者存款向下溢出變大。整數溢出漏洞可以使用 SafeMath 庫來防禦，當發生溢出時會回滾交易。

## 例子

以 Capture The Ether 的 Token sale 爲例：

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

在本題中，購買單個代幣需要支付 1 ether，即 `msg.value == numTokens * PRICE_PER_TOKEN`。在EVM中，貨幣以 wei 爲單位，1 ether 實際上是 $10 ^ { 18 }$ wei，即 0xde0b6b3a7640000 wei。如果讓這裏的 `numTokens` 大一些，乘積就可能溢出。例如我們購買 $2 ^ { 256 } // 10 ^ { 18 } + 1$ 個代幣，乘上 $10 ^ { 18 }$ 後就發生了溢出，最終花費僅約 0.4 ether 就買到了大量代幣。然後我們將買到的代幣部分賣出，即可完成題目要求。

整數下溢的一個例子是減法操作。假設有一個合約實現瞭如下功能：

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

乍看之下沒有問題，實際上 require 一行，`balanceOf[msg.sender]-amount` 的結果作爲無符號整數，永遠是大於等於 0 的，導致我們可以任意取款。正確的寫法是 `require(balanceOf[msg.sender] >= amount)`。

整數下溢的另一個例子與重入攻擊有關，如將持有數爲 1 的物品賣出兩次，或者將 1 ether 存款取出兩次，導致結果爲負數，儲存爲 uint 則爲巨大的正數。

## 題目

絕大部分重入攻擊的題目都涉及到向下溢出，可參照重入攻擊的部分。不涉及重入攻擊的相對較少，可以參考以下題目。

### ByteCTF 2019
- 題目名稱 hf
- 題目名稱 bet

!!! note
    注：題目附件相關內容可至 [ctf-challenges/blockchain](https://github.com/ctf-wiki/ctf-challenges/tree/master/blockchain) 倉庫尋找。
