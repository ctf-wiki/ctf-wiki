# Short Address Attack

## 原理

短地址攻擊，利用 EVM 在參數長度不夠時自動在右方補 0 的特性，通過去除錢包地址末位的 0，達到將轉賬金額左移放大的效果。

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

具體代幣功能的合約 Coin，當 A 賬戶向 B 賬戶轉代幣時調用 `transfer()` 函數，例如 A 賬戶（0x14723a09acff6d2a60dcdf7aa4aff308fddc160c）向 B 賬戶（0x4b0897b0513fdc7c541b6d9d7e929c4e5364d2db）轉 8 個 Coin，`msg.data` 數據爲：

```
0xa9059cbb  -> bytes4(keccak256("transfer(address,uint256)")) 函數簽名
0000000000000000000000004b0897b0513fdc7c541b6d9d7e929c4e5364d2db  -> B 賬戶地址（前補 0 補齊 32 字節）
0000000000000000000000000000000000000000000000000000000000000008  -> 0x8（前補 0 補齊 32 字節）
```

那麼短地址攻擊是怎麼做的呢，攻擊者找到一個末尾是 `00` 賬戶地址，假設爲 0x4b0897b0513fdc7c541b6d9d7e929c4e5364d200，那麼正常情況下整個調用的 `msg.data` 應該爲：

```
0xa9059cbb  -> bytes4(keccak256("transfer(address,uint256)")) 函數簽名
0000000000000000000000004b0897b0513fdc7c541b6d9d7e929c4e5364d200  -> B 賬戶地址（注意末尾 00）
0000000000000000000000000000000000000000000000000000000000000008  -> 0x8（前補 0 補齊 32 字節）
```

但是如果我們將 B 地址的 `00` 喫掉，不進行傳遞，也就是說我們少傳遞 1 個字節變成 4+31+32：

```
0xa9059cbb  -> bytes4(keccak256("transfer(address,uint256)")) 函數簽名
0000000000000000000000004b0897b0513fdc7c541b6d9d7e929c4e5364d2  -> B 地址（31 字節）
0000000000000000000000000000000000000000000000000000000000000008  -> 0x8（前補 0 補齊 32 字節）
```

當上面數據進入 EVM 進行處理時，對參數進行編碼對齊後補 `00` 變爲：

```
0xa9059cbb
0000000000000000000000004b0897b0513fdc7c541b6d9d7e929c4e5364d200
0000000000000000000000000000000000000000000000000000000000000800
```

也就是說，惡意構造的 `msg.data` 通過 EVM 解析補 0 操作，導致原本 0x8 = 8 變爲了 0x800 = 2048

上述 EVM 對畸形字節的 `msg.data` 進行補位操作的行爲其實就是短地址攻擊的原理

## 題目

這個目前沒有題目，基本已經被修復。不過可以復現成功，但是不能通過 Remix 復現，因爲客戶端會檢查地址長度；也不能通過 sendTransaction()，因爲 `web3` 中也加了保護。

但是，可以使用 **geth** 搭建私鏈，使用 sendRawTransaction() 發送交易復現，可自行嘗試。

!!! note
    注：目前主要依靠客戶端主動檢查地址長度來避免該問題，另外 `web3` 層面也增加了參數格式校驗。雖然 EVM 層仍然可以復現，但是在實際應用場景中基本沒有問題。