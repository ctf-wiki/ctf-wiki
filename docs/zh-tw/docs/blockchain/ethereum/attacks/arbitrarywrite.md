# Arbitrary Writing

## 原理

動態數組的任意 Storage 存儲寫漏洞，根據 [官方文檔](https://docs.soliditylang.org/en/v0.8.1/internals/layout_in_storage.html#) 介紹，可總結如下

- EVM 中，有三個地方可以存儲變量，分別是 Memory、Stack 和 Storage。Memory 和 Stack 是在執行期間臨時生成的存儲空間，主要負責運行時的數據存儲，Storage 是永久存在於區塊鏈中的變量。
    + Memory: 內存，生命週期僅爲整個方法執行期間，函數調用後回收，因爲僅保存臨時變量，故 GAS 開銷很小
    + Storage: 永久儲存在區塊鏈中，由於會永久保存合約狀態變量，故 GAS 開銷也最大
    + Stack: 存放部分局部值類型變量，幾乎免費使用的內存，但有數量限制

- EVM 對每一個智能合約維護了一個巨大的 **key-value** 的存儲結構，用於持久化存儲數據，我們稱這片區域爲 Storage。除了 map 映射變量和變長數組以外的所有類型變量，在 Storage 中是依次連續從 slot 0 開始排列的，一共有 2^256 個 slot，每個 slot 可以存儲 32 字節的數據。Storage 存儲結構是在合約創建的時候就確定好的，它取決於合約所聲明狀態變量，但是內容可以通過 Transaction 改變。
- Storage 變量大致分爲 4 種類型：定長變量、結構體、map 映射變量和變長數組。如果多個變量佔用的大小小於 32 字節，按照緊密打包原則，會盡可能打包到單個 slot 中，具體規則如下：
    + 在 slot 中，是按照低位對齊存儲的，即大端序
    + 基本類型變量存儲時僅存儲它們實際所需的字節數
    + 如果基本類型變量不能放入某個 slot 餘下的空間，它將被放入下一個 slot
    + map 和變長數組總是使用一個全新的 slot，並佔用整個 slot，但對於其內部的每個變量，還是要遵從上面的規則

### slot 計算規則

首先我們分析一下各種對象結構在 EVM 中的存儲和訪問情況

#### 定長變量和結構體

Solidity 中的定長定量在定義的時候，其長度就已經被限制住了。比如定長整型（uint、uint8），地址常量（address），定長字節數組（bytes1-32）等，這類的變量在 Storage 中是儘可能打包成 32 字節的塊順序存儲的。

Solidity 的結構體並沒有特殊的存儲模型，在 Storage 中的存儲可以按照定長變量規則分析。

#### Map 映射變量

在 Solidity 中，並不存儲 map 的鍵，只存儲鍵對應的值，值是通過鍵的 hash 索引來找到的。用 $slotM$ 表示 map 聲明的 slot 位置，用 $key$ 表示鍵，用 $value$ 表示 $key$ 對應的值，用 $slotV$ 表示 $value$ 的存儲位置，則

- $slotV = keccak256(key|slotM)$

- $value = sload(slotV)$

#### 變長數組

用 $slotA$ 表示變長數組聲明的位置，用 $length$ 表示變長數組的長度，用 $slotV$ 表示變長數組數據存儲的位置，用 $value$ 表示變長數組某個數據的值，用 $index$ 表示 $value$ 對應的索引下標，則

- $length = sload(slotA)$

- $slotV = keccak256(slotA) + index$

- $value = sload(slotV)$

變長數組在編譯期間無法知道數組的長度，沒辦法提前預留存儲空間，所以 Solidity 就用 $slotA$ 位置存儲了變長數組的長度

!!! note
    注：變長數組具體數據存放在 keccak256 哈希計算之後的一片連續存儲區域，這一點與 Map 映射變量不同。

### 漏洞介紹

在以太坊 EVM 的設計思路中，所有的 Storage 變量共用一片大小爲 2^256*32 字節的存儲空間，沒有各自的存儲區域劃分。

Storage 空間即使很大也是有限大小，當變長數組長度很大時，考慮極端情況，如果長度達到 2^256，則可對任意 Storage 變量進行讀寫操作，這是非常可怕的。

## 例子

### Source

```solidity
pragma solidity ^0.4.24;

contract ArrayTest  {

    address public owner;
    bool public contact;
    bytes32[] public codex;
    
    constructor() public {
        owner = msg.sender;
    }

    function record(bytes32 _content) public {
        codex.push(_content);
    }

    function retract() public {
        codex.length--;
    }

    function revise(uint i, bytes32 _content) public {
        codex[i] = _content;
    }
}
```

這裏攻擊者如何才能成爲 owner 呢？其中 owner 最初爲 0x73048cec9010e92c298b016966bde1cc47299df5

### Analyse

- 數組 codex 的 slot 爲 1 ，同時這也是存儲數組 length 的地方，而 codex 的實際內容存儲在 keccak256(bytes32(1)) 開始的位置

!!! info
    Keccak256 是緊密打包的，意思是說參數不會補位，多個參數也會直接連接在一起，所以要用 keccak256(bytes32(1))

- 這樣我們就知道了 codex 實際的存儲的 slot ，可以將動態數組內變量的存儲位計算方法概括爲: array[index] == sload(keccak256(slot(array)) + index). 

- 因爲總共有 2^256 個 slot ，要修改 slot 0 ，假設 codex 實際所在 slot x ，(對於本題來說，數組的 slot是 1 , x=keccak256(bytes32(1))) ，那麼當我們修改 codex[y]，(y=2^256-x+0) 時就能修改 slot 0 ，從而修改 owner
    - 計算 codex 位置爲 slot 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6
    - 所以 y = 2^256 - 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6 + 0
    - 即 y = 35707666377435648211887908874984608119992236509074197713628505308453184860938

- 可以看到 y 很大，我們要修改 codex[y] ，那就要滿足 y < codex.length ，而這個時候 codex.length =0 ，但是我們可以通過 retract() 使 length 下溢，然後就可以操縱 codex[y] 了
- 由上面已經計算出 codex[35707666377435648211887908874984608119992236509074197713628505308453184860938] 對應的存儲位就是 slot 0 ，而 slot 0 中同時存儲了 contact 和 owner ，我們只需將 owner 換成 attacker 即可，假設 attacker 地址是 0x88d3052d12527f1fbe3a6e1444ea72c4ddb396c2，則如下所示

```
contract.revise('35707666377435648211887908874984608119992236509074197713628505308453184860938','0x00000000000000000000000088d3052d12527f1fbe3a6e1444ea72c4ddb396c2')
```

## 題目

### XCTF_final 2019
- 題目名稱 Happy_DOuble_Eleven

### Balsn 2019
- 題目名稱 Bank

### 第一屆釣魚城杯 2020
- 題目名稱 StrictMathematician

### RCTF 2020
- 題目名稱 roiscoin

!!! note
    注：題目附件相關內容可至 [ctf-challenges/blockchain](https://github.com/ctf-wiki/ctf-challenges/tree/master/blockchain) 倉庫尋找。
