# Ethereum Basics

對智能合約一些基礎知識的介紹。

## Solidity

> Solidity is an object-oriented programming language for writing smart contracts. It is used for implementing smart contracts on various blockchain platforms, most notably, Ethereum. It was developed by Christian Reitwiessner, Alex Beregszaszi, and several former Ethereum core contributors to enable writing smart contracts on blockchain platforms such as Ethereum.  ------  from [wikipedia](https://en.wikipedia.org/wiki/Solidity)

Solidity 是一種用於編寫智能合約的高級語言，語法類似於 JavaScript。在以太坊平臺上，Solidity 編寫的智能合約可以被編譯成字節碼在以太坊虛擬機 EVM 上運行。

可參考 [官方網站](https://docs.soliditylang.org/en/latest/) 進行學習，不再展開介紹。

## MetaMask

非常好用也是用的最多的以太坊錢包，頭像是小狐狸標識，Chrome 提供了其插件，其不僅可以管理外部賬戶，而且可以便捷切換測試鏈網絡，並且可以自定義 RPC 網絡。

!!! info
    一個外部賬戶通常由私鑰文件控制，擁有私鑰的用戶就可以擁有對應地址的賬戶裏的 Ether 使用權。我們通常把管理這些數字密鑰的軟件稱爲錢包，而我們所說的備份錢包其實就是備份賬戶的私鑰文件。

## Remix

基於瀏覽器的 Solidity 編譯器和集成開發環境，提供了交互式界面，以及編譯、調用測試、發佈等一系列功能，使用十分方便。[http://remix.ethereum.org/](http://remix.ethereum.org/#optimize=false&runs=200&evmVersion=null)

## 賬戶

在以太坊中，一個重要的概念就是賬戶（Account）。

在以太坊中存在兩種類型的賬戶，分別是外部賬戶（Externally Owned Account, EOA）和合約賬戶。

### 外部賬戶

外部賬戶是由人創建的，可以存儲以太幣，是由公鑰和私鑰控制的賬戶。每個外部賬戶擁有一對公私鑰，這對密鑰用於簽署交易，它的地址由公鑰決定。外部賬戶不能包含以太坊虛擬機（EVM）代碼。

一個外部賬戶具有以下特性

- 擁有一定的 Ether
- 可以發送交易、通過私鑰控制
- 沒有相關聯的代碼

### 合約賬戶

合約賬戶是由外部賬戶創建的賬戶，包含合約代碼。合約賬戶的地址是由合約創建時合約創建者的地址，以及該地址發出的交易共同計算得出的。

一個合約賬戶具有以下特性

- 擁有一定的 Ether
- 有相關聯的代碼，代碼通過交易或者其他合約發送的調用來激活
- 當合約被執行時，只能操作合約賬戶擁有的特定存儲

!!! note
    私鑰經過一種哈希算法(橢圓曲線算法 ECDSA-secp256k1 )計算生成公鑰，計算公鑰的 Keccak-256 哈希值，然後取最後 160 位二進制（通常表現爲 40 位的 16 進制字符串）形成了地址。其中，公鑰和地址都是可以公佈的，而私鑰，你只能自己悄悄的藏起來，不要丟失，因爲你的賬戶中的資產也會跟着丟掉；不要被別人盜取，因爲賬戶中的資產也會隨着被盜取。所以，私鑰的保存非常重要。

以太坊中，這兩種賬戶統稱爲“狀態對象”（存儲狀態）。其中外部賬戶存儲以太幣餘額狀態，而合約賬戶除了餘額還有智能合約及其變量的狀態。通過交易的執行，這些狀態對象發生變化，而 Merkle 樹用於索引和驗證狀態對象的更新。一個以太坊的賬戶包含 4 個部分：

- nonce: 已執行交易總數，用來標示該賬戶發出的交易數量。
- balance: 賬持幣數量，記錄賬戶的以太幣餘額。
- storageRoot: 存儲區的哈希值，指向智能合約賬戶的存儲數據區。
- codeHash: 代碼區的哈希值，指向智能合約賬戶存儲的智能合約代碼。

兩個外部賬戶之間的交易只是一個價值轉移。但是從外部賬戶到合約賬戶的交易會激活合約賬戶的代碼，允許它執行各種操作（例如轉移 Token，寫入內部存儲，創建新的 Token ，執行一些計算，創建新的合約等）。

與外部賬戶不同，合約賬戶不能自行發起新的交易。相反，合約帳戶只能觸發交易以響應其他交易（從外部擁有的帳戶或其他合約帳戶）。

!!! note 
    注：合約賬戶和外部賬戶最大的不同就是它還存有智能合約。

## 交易

以太坊的交易主要是指一條外部賬戶發送到區塊鏈上另一賬戶的消息的簽名數據包，其主要包含發送者的簽名、接收者的地址以及發送者轉移給接收者的以太幣數量等內容。以太坊上的每一筆交易都需要支付一定的費用，用於支付交易執行所需要的計算開銷。計算開銷的費用並不是以太幣直接計算的，而是引入 Gas 作爲執行開銷的基本單位，通過 GasPrice 與以太幣進行換算的。 

GasPrice 根據市場波動調整，避免以太幣價值受市場價格的影響。交易是以太坊整體結構中的重要部分，它將以太坊的賬戶連接起來，起到價值的傳遞作用。

### 交易費用
- Gas: 衡量一筆交易所消耗的計算資源的基本單位
- Gas Price: 一單位 Gas 所需的手續費（Ether）
- Gas Limit: 交易發送者願意爲這筆交易執行所支付的最大 Gas 數量

!!! note 
    注：如果交易實際消耗的 Gas (Gas Used) 小於 Gas Limit, 那麼執行的礦工只會收取實際計算開銷（Gas Used）對應的交易手續費（Gas Used * Gas Price）；而如果 Gas Used 大於 Gas Limit，那麼礦工執行過程中會發現 Gas 已被耗盡而交易沒有執行完成，此時礦工會回滾到程序執行前到狀態，而且收取 Gas Limit 所對應的手續費（GasPrice * Gas Limit）。換句話說，**GasPrice * Gas Limit** 表示用戶願意爲一筆交易支付的最高金額。

### 交易內容
以太坊中的交易（Transaction）是指存儲一條從外部賬戶發送到區塊鏈上另一個賬戶的消息的簽名數據包，它既可以是簡單的轉賬，也可以是包含智能合約代碼的消息。一條交易包含以下內容：

- from: 交易發送者的地址，必填；
- to: 交易接收者的地址，如果爲空則意味這是一個創建智能合約的交易；
- value: 發送者要轉移給接收者的以太幣數量
- data: 存在的數據字段，如果存在，則表明該交易是一個創建或者調用智能合約的交易；
- Gas Limit: 表示交易允許消耗的最大 Gas 數量；
- GasPrice: 發送者願意支付給礦工的 Gas 單價；
- nonce: 用來區別同一賬戶發出的不同交易的標記；
- hash: 由以上信息生成的散列值（哈希值）；
- r、s、v: 交易簽名的三個部分，由發送者的私鑰對交易 hash 進行簽名生成。

以上是以太坊中交易可能包含的內容，在不同場景下，交易有三種類型。

- 轉帳交易

轉賬是最簡單的一種交易，從一個賬戶向另一個賬戶發送 Ether，發送轉賬交易時只需要指定交易的發送者、接收者、轉移的 Ether 數量即可（在客戶端發送交易時，Gas Limit、Gas Price、nonce、hash、簽名可以按照默認方式生成），如下所示

```nodejs
web3.eth.sendTransaction({
    from: "0x88D3052D12527F1FbE3a6E1444EA72c4DdB396c2",
    to: "0x75e65F3C1BB334ab927168Bd49F5C44fbB4D480f",
    value: 1000
})
```

- 創建合約的交易

創建合約是指將合約部署到區塊鏈上，這也是通過交易來完成的。創建合約時，to 字段是一個空字符串，data 字段是合約編譯後的二進制代碼，在之後合約被調用時，該代碼的執行結果將作爲合約代碼，如下所示

```
web3.eth.sendTransaction({
    from: "0x88D3052D12527F1FbE3a6E1444EA72c4DdB396c2",
    data: "contract binary code"
})
```

- 執行合約的交易

該交易中，to 字段是要調用的智能合約的地址，通過 data 字段指定要調用的方法以及向該方法傳入參數，如下所示

```
web3.eth.sendTransaction({
    from: "0x88D3052D12527F1FbE3a6E1444EA72c4DdB396c2",
    to: "0x75e65F3C1BB334ab927168Bd49F5C44fbB4D480f",
    data: "hash of the invoked method signature and encoded parameters"
})
```

!!! info
    根據 to、data 字段內容也可以反過來判斷是什麼類型的交易，然後可以繼續分析。

## Interact with Contracts

- 直接通過 Remix 交互
- Remix 不能夠做到自動化，所以便有開發人員做了一些工作
    - Python 的 web3.py 庫
    - Nodejs 的 web3.js 庫
    - [Infura](https://infura.io/) 提供了 RPC API 供開發者調用，現支持 Ethereum、Eth2、Filecoin

使用 [Infura](https://infura.io/) 提供的 RPC API，利用 web3.py 或者 web3.js 庫與其進行自動化交互

Infura 現支持如下網絡的訪問點：

|網絡          |說明                    |URL|
|-------------|------------------------|---------------------------------------|
|Mainnet      |JSON-RPC over HTTPs     |https://mainnet.infura.io/v3/YOUR-PROJECT-ID |
|Mainnet      |JSON-RPC over websockets|wss://mainnet.infura.io/ws/v3/YOUR-PROJECT-ID|
|Ropsten      |JSON-RPC over HTTPs     |https://ropsten.infura.io/v3/YOUR-PROJECT-ID |
|Ropsten      |JSON-RPC over websockets|wss://ropsten.infura.io/ws/v3/YOUR-PROJECT-ID|
|Rinkeby      |JSON-RPC over HTTPs     |https://rinkeby.infura.io/v3/YOUR-PROJECT-ID |
|Rinkeby      |JSON-RPC over websockets|wss://rinkeby.infura.io/ws/v3/YOUR-PROJECT-ID|
|Kovan        |JSON-RPC over HTTPs     |https://kovan.infura.io/v3/YOUR-PROJECT-ID   |
|Kovan        |JSON-RPC over websockets|wss://kovan.infura.io/ws/v3/YOUR-PROJECT-ID  |
|Görli        |JSON-RPC over HTTPs     |https://goerli.infura.io/v3/YOUR-PROJECT-ID  |
|Görli        |JSON-RPC over websockets|wss://goerli.infura.io/ws/v3/YOUR-PROJECT-ID |
|Mainnet(eth2)|JSON-RPC over HTTPs     |https://YOUR-PROJECT-ID:YOUR-PROJECT-SECRET@eth2-beacon-mainnet.infura.io|
|pyrmont(eth2)|JSON-RPC over websockets|wss://YOUR-PROJECT-ID:YOUR-PROJECT-SECRET@eth2-beacon-mainnet.infura.io|
|Filecoin     |JSON-RPC over HTTPs     |https://YOUR-PROJECT-ID:YOUR-PROJECT-SECRET@filecoin.infura.io|
|Filecoin     |JSON-RPC over websockets|wss://YOUR-PROJECT-ID:YOUR-PROJECT-SECRET@filecoin.infura.io|

!!! note 
    注：使用時，請務必使用你的Infura儀表盤 中的項目 ID/Project ID 或 Project Secret 來替換以上 URL 中的 YOUR-PROJECT-ID 或 YOUR-PROJECT-SECRET

下面是使用 web3.py 和 Infura API 與智能合約進行交互調用合約函數選擇器爲 0x00774360 的函數的例子

```python
from web3 import Web3, HTTPProvider

w3 = Web3(Web3.HTTPProvider("https://rinkeby.infura.io/v3/YOUR-PROJECT-ID"))

contract_address = "0x31c883a9aa588d3f890c26c7844062d99444b5d6"
private = "your private key"
public = "0x75e65F3C1BB334ab927168Bd49F5C44fbB4D480f"

def deploy(public):
    txn = {
        'from': Web3.toChecksumAddress(public),
        'to': Web3.toChecksumAddress(contract_address),
        'gasPrice': w3.eth.gasPrice,
        'gas': 3000000,
        'nonce': w3.eth.getTransactionCount(Web3.toChecksumAddress(public)),
        'value': Web3.toWei(0, 'ether'),
        'data': '0x007743600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001a6100016100016100016100016100016100650361000161fbfbf1000000000000',
    }
    signed_txn = w3.eth.account.signTransaction(txn, private)
    txn_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction).hex()
    txn_receipt = w3.eth.waitForTransactionReceipt(txn_hash)
    print("txn_hash=", txn_hash)
    return txn_receipt

print(deploy(public))
```

## tx.origin vs msg.sender

- 這裏區分一下 tx.origin 和 msg.sender ，msg.sender 是函數的直接調用方，在用戶手動調用該函數時是發起交易的賬戶地址，但也可以是調用該函數的一個智能合約的地址。而 tx.origin 則必然是這個交易的原始發起方，無論中間有多少次合約內/跨合約函數調用，而且一定是賬戶地址而不是合約地址。
- 給定這樣一個場景如：用戶通過合約 A 調合約B，此時：
    + 對於合約 A : tx.origin 和 msg.sender 都是用戶
    + 對於合約 B : tx.origin 是用戶，msg.sender 是合約 A
