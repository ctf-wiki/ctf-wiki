# Ethereum Overview

!!! info
    CTF 中關於區塊鏈安全的內容，目前爲止，涉及到最多的便是 Ethereum 安全。

## 定義

> Ethereum is a decentralized, open-source blockchain featuring smart contract functionality. Ether (ETH) is the native cryptocurrency of the platform. It is the second-largest cryptocurrency by market capitalization, after Bitcoin. Ethereum is the most actively used blockchain.  ------  from [wikipedia](https://en.wikipedia.org/wiki/Ethereum)

Ethereum 是區塊鏈 2.0 的代表產物，因其底層使用區塊鏈技術，所以繼承區塊鏈的各種特性，其中有一項便是 **代碼一旦上鍊，便難以篡改或更改**，所以我們需要額外關注它的安全。

智能合約 (Smart Contract) 是 Ethereum 中最爲重要的一個概念，允許在沒有第三方的情況下進行可信交易，這些交易可追蹤且不可逆轉。

## CTF 中的區塊鏈

CTF 中有關於 Ethereum Security 還是比較簡單的，主要涉及到的是 Solidity Security， 下面介紹一下需要具備的基本能力。

### 要求

- 對區塊鏈基本知識以及交易本質有所瞭解
- 熟悉並掌握 Solidity 編程語言及以太坊虛擬機 EVM 運行機制
- 熟悉各種測試鏈，包括私鏈
- 熟悉 Remix、MetaMask、web3.js、web3.py 等工具或庫的使用
- 瞭解並掌握以太坊智能合約各種漏洞及其攻擊原理
- 對底層 opcodes 理解透徹
- 較強的程序理解和逆向分析能力

!!! note
    注：以太坊智能合約大多數不公開源代碼，而是字節碼，所以需要逆向分析能力。