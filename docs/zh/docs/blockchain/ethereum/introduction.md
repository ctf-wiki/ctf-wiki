# Ethereum Overview

!!! info
    CTF 中关于区块链安全的内容，目前为止，涉及到最多的便是 Ethereum 安全。

## 定义

> Ethereum is a decentralized, open-source blockchain featuring smart contract functionality. Ether (ETH) is the native cryptocurrency of the platform. It is the second-largest cryptocurrency by market capitalization, after Bitcoin. Ethereum is the most actively used blockchain.  ------  from [wikipedia](https://en.wikipedia.org/wiki/Ethereum)

Ethereum 是区块链 2.0 的代表产物，因其底层使用区块链技术，所以继承区块链的各种特性，其中有一项便是 **代码一旦上链，便难以篡改或更改**，所以我们需要额外关注它的安全。

智能合约 (Smart Contract) 是 Ethereum 中最为重要的一个概念，允许在没有第三方的情况下进行可信交易，这些交易可追踪且不可逆转。

## CTF 中的区块链

CTF 中有关于 Ethereum Security 还是比较简单的，主要涉及到的是 Solidity Security， 下面介绍一下需要具备的基本能力。

### 要求

- 对区块链基本知识以及交易本质有所了解
- 熟悉并掌握 Solidity 编程语言及以太坊虚拟机 EVM 运行机制
- 熟悉各种测试链，包括私链
- 熟悉 Remix、MetaMask、web3.js、web3.py 等工具或库的使用
- 了解并掌握以太坊智能合约各种漏洞及其攻击原理
- 对底层 opcodes 理解透彻
- 较强的程序理解和逆向分析能力

!!! note
    注：以太坊智能合约大多数不公开源代码，而是字节码，所以需要逆向分析能力。