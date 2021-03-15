# Ethereum Basics

对智能合约一些基础知识的介绍。

## Solidity

> Solidity is an object-oriented programming language for writing smart contracts. It is used for implementing smart contracts on various blockchain platforms, most notably, Ethereum. It was developed by Christian Reitwiessner, Alex Beregszaszi, and several former Ethereum core contributors to enable writing smart contracts on blockchain platforms such as Ethereum.  ------  from [wikipedia](https://en.wikipedia.org/wiki/Solidity)

Solidity 是一种用于编写智能合约的高级语言，语法类似于 JavaScript。在以太坊平台上，Solidity 编写的智能合约可以被编译成字节码在以太坊虚拟机 EVM 上运行。

可参考 [官方网站](https://docs.soliditylang.org/en/latest/) 进行学习，不再展开介绍。

## MetaMask

非常好用也是用的最多的以太坊钱包，头像是小狐狸标识，Chrome 提供了其插件，其不仅可以管理外部账户，而且可以便捷切换测试链网络，并且可以自定义 RPC 网络。

!!! info
    一个外部账户通常由私钥文件控制，拥有私钥的用户就可以拥有对应地址的账户里的 Ether 使用权。我们通常把管理这些数字密钥的软件称为钱包，而我们所说的备份钱包其实就是备份账户的私钥文件。

## Remix

基于浏览器的 Solidity 编译器和集成开发环境，提供了交互式界面，以及编译、调用测试、发布等一系列功能，使用十分方便。[http://remix.ethereum.org/](http://remix.ethereum.org/#optimize=false&runs=200&evmVersion=null)

## 账户

在以太坊中，一个重要的概念就是账户（Account）。

在以太坊中存在两种类型的账户，分别是外部账户（Externally Owned Account, EOA）和合约账户。

### 外部账户

外部账户是由人创建的，可以存储以太币，是由公钥和私钥控制的账户。每个外部账户拥有一对公私钥，这对密钥用于签署交易，它的地址由公钥决定。外部账户不能包含以太坊虚拟机（EVM）代码。

一个外部账户具有以下特性

- 拥有一定的 Ether
- 可以发送交易、通过私钥控制
- 没有相关联的代码

### 合约账户

合约账户是由外部账户创建的账户，包含合约代码。合约账户的地址是由合约创建时合约创建者的地址，以及该地址发出的交易共同计算得出的。

一个合约账户具有以下特性

- 拥有一定的 Ether
- 有相关联的代码，代码通过交易或者其他合约发送的调用来激活
- 当合约被执行时，只能操作合约账户拥有的特定存储

!!! note
    私钥经过一种哈希算法(椭圆曲线算法 ECDSA-secp256k1 )计算生成公钥，计算公钥的 Keccak-256 哈希值，然后取最后 160 位二进制（通常表现为 40 位的 16 进制字符串）形成了地址。其中，公钥和地址都是可以公布的，而私钥，你只能自己悄悄的藏起来，不要丢失，因为你的账户中的资产也会跟着丢掉；不要被别人盗取，因为账户中的资产也会随着被盗取。所以，私钥的保存非常重要。

以太坊中，这两种账户统称为“状态对象”（存储状态）。其中外部账户存储以太币余额状态，而合约账户除了余额还有智能合约及其变量的状态。通过交易的执行，这些状态对象发生变化，而 Merkle 树用于索引和验证状态对象的更新。一个以太坊的账户包含 4 个部分：

- nonce: 已执行交易总数，用来标示该账户发出的交易数量。
- balance: 账持币数量，记录账户的以太币余额。
- storageRoot: 存储区的哈希值，指向智能合约账户的存储数据区。
- codeHash: 代码区的哈希值，指向智能合约账户存储的智能合约代码。

两个外部账户之间的交易只是一个价值转移。但是从外部账户到合约账户的交易会激活合约账户的代码，允许它执行各种操作（例如转移 Token，写入内部存储，创建新的 Token ，执行一些计算，创建新的合约等）。

与外部账户不同，合约账户不能自行发起新的交易。相反，合约帐户只能触发交易以响应其他交易（从外部拥有的帐户或其他合约帐户）。

!!! note 
    注：合约账户和外部账户最大的不同就是它还存有智能合约。

## 交易

以太坊的交易主要是指一条外部账户发送到区块链上另一账户的消息的签名数据包，其主要包含发送者的签名、接收者的地址以及发送者转移给接收者的以太币数量等内容。以太坊上的每一笔交易都需要支付一定的费用，用于支付交易执行所需要的计算开销。计算开销的费用并不是以太币直接计算的，而是引入 Gas 作为执行开销的基本单位，通过 GasPrice 与以太币进行换算的。 

GasPrice 根据市场波动调整，避免以太币价值受市场价格的影响。交易是以太坊整体结构中的重要部分，它将以太坊的账户连接起来，起到价值的传递作用。

### 交易费用
- Gas: 衡量一笔交易所消耗的计算资源的基本单位
- Gas Price: 一单位 Gas 所需的手续费（Ether）
- Gas Limit: 交易发送者愿意为这笔交易执行所支付的最大 Gas 数量

!!! note 
    注：如果交易实际消耗的 Gas (Gas Used) 小于 Gas Limit, 那么执行的矿工只会收取实际计算开销（Gas Used）对应的交易手续费（Gas Used * Gas Price）；而如果 Gas Used 大于 Gas Limit，那么矿工执行过程中会发现 Gas 已被耗尽而交易没有执行完成，此时矿工会回滚到程序执行前到状态，而且收取 Gas Limit 所对应的手续费（GasPrice * Gas Limit）。换句话说，**GasPrice * Gas Limit** 表示用户愿意为一笔交易支付的最高金额。

### 交易内容
以太坊中的交易（Transaction）是指存储一条从外部账户发送到区块链上另一个账户的消息的签名数据包，它既可以是简单的转账，也可以是包含智能合约代码的消息。一条交易包含以下内容：

- from: 交易发送者的地址，必填；
- to: 交易接收者的地址，如果为空则意味这是一个创建智能合约的交易；
- value: 发送者要转移给接收者的以太币数量
- data: 存在的数据字段，如果存在，则表明该交易是一个创建或者调用智能合约的交易；
- Gas Limit: 表示交易允许消耗的最大 Gas 数量；
- GasPrice: 发送者愿意支付给矿工的 Gas 单价；
- nonce: 用来区别同一账户发出的不同交易的标记；
- hash: 由以上信息生成的散列值（哈希值）；
- r、s、v: 交易签名的三个部分，由发送者的私钥对交易 hash 进行签名生成。

以上是以太坊中交易可能包含的内容，在不同场景下，交易有三种类型。

- 转帐交易

转账是最简单的一种交易，从一个账户向另一个账户发送 Ether，发送转账交易时只需要指定交易的发送者、接收者、转移的 Ether 数量即可（在客户端发送交易时，Gas Limit、Gas Price、nonce、hash、签名可以按照默认方式生成），如下所示

```nodejs
web3.eth.sendTransaction({
    from: "0x88D3052D12527F1FbE3a6E1444EA72c4DdB396c2",
    to: "0x75e65F3C1BB334ab927168Bd49F5C44fbB4D480f",
    value: 1000
})
```

- 创建合约的交易

创建合约是指将合约部署到区块链上，这也是通过交易来完成的。创建合约时，to 字段是一个空字符串，data 字段是合约编译后的二进制代码，在之后合约被调用时，该代码的执行结果将作为合约代码，如下所示

```
web3.eth.sendTransaction({
    from: "0x88D3052D12527F1FbE3a6E1444EA72c4DdB396c2",
    data: "contract binary code"
})
```

- 执行合约的交易

该交易中，to 字段是要调用的智能合约的地址，通过 data 字段指定要调用的方法以及向该方法传入参数，如下所示

```
web3.eth.sendTransaction({
    from: "0x88D3052D12527F1FbE3a6E1444EA72c4DdB396c2",
    to: "0x75e65F3C1BB334ab927168Bd49F5C44fbB4D480f",
    data: "hash of the invoked method signature and encoded parameters"
})
```

!!! info
    根据 to、data 字段内容也可以反过来判断是什么类型的交易，然后可以继续分析。

## Interact with Contracts

- 直接通过 Remix 交互
- Remix 不能够做到自动化，所以便有开发人员做了一些工作
    - Python 的 web3.py 库
    - Nodejs 的 web3.js 库
    - [Infura](https://infura.io/) 提供了 RPC API 供开发者调用，现支持 Ethereum、Eth2、Filecoin

使用 [Infura](https://infura.io/) 提供的 RPC API，利用 web3.py 或者 web3.js 库与其进行自动化交互

Infura 现支持如下网络的访问点：

|网络          |说明                    |URL|
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
    注：使用时，请务必使用你的Infura仪表盘 中的项目 ID/Project ID 或 Project Secret 来替换以上 URL 中的 YOUR-PROJECT-ID 或 YOUR-PROJECT-SECRET

下面是使用 web3.py 和 Infura API 与智能合约进行交互调用合约函数选择器为 0x00774360 的函数的例子

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

- 这里区分一下 tx.origin 和 msg.sender ，msg.sender 是函数的直接调用方，在用户手动调用该函数时是发起交易的账户地址，但也可以是调用该函数的一个智能合约的地址。而 tx.origin 则必然是这个交易的原始发起方，无论中间有多少次合约内/跨合约函数调用，而且一定是账户地址而不是合约地址。
- 给定这样一个场景如：用户通过合约 A 调合约B，此时：
    + 对于合约 A : tx.origin 和 msg.sender 都是用户
    + 对于合约 B : tx.origin 是用户，msg.sender 是合约 A
