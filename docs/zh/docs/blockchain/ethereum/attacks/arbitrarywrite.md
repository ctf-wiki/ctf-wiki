# Arbitrary Writing

## 原理

动态数组的任意 Storage 存储写漏洞，根据 [官方文档](https://docs.soliditylang.org/en/v0.8.1/internals/layout_in_storage.html#) 介绍，可总结如下

- EVM 中，有三个地方可以存储变量，分别是 Memory、Stack 和 Storage。Memory 和 Stack 是在执行期间临时生成的存储空间，主要负责运行时的数据存储，Storage 是永久存在于区块链中的变量。
    + Memory: 内存，生命周期仅为整个方法执行期间，函数调用后回收，因为仅保存临时变量，故 GAS 开销很小
    + Storage: 永久储存在区块链中，由于会永久保存合约状态变量，故 GAS 开销也最大
    + Stack: 存放部分局部值类型变量，几乎免费使用的内存，但有数量限制

- EVM 对每一个智能合约维护了一个巨大的 **key-value** 的存储结构，用于持久化存储数据，我们称这片区域为 Storage。除了 map 映射变量和变长数组以外的所有类型变量，在 Storage 中是依次连续从 slot 0 开始排列的，一共有 2^256 个 slot，每个 slot 可以存储 32 字节的数据。Storage 存储结构是在合约创建的时候就确定好的，它取决于合约所声明状态变量，但是内容可以通过 Transaction 改变。
- Storage 变量大致分为 4 种类型：定长变量、结构体、map 映射变量和变长数组。如果多个变量占用的大小小于 32 字节，按照紧密打包原则，会尽可能打包到单个 slot 中，具体规则如下：
    + 在 slot 中，是按照低位对齐存储的，即大端序
    + 基本类型变量存储时仅存储它们实际所需的字节数
    + 如果基本类型变量不能放入某个 slot 余下的空间，它将被放入下一个 slot
    + map 和变长数组总是使用一个全新的 slot，并占用整个 slot，但对于其内部的每个变量，还是要遵从上面的规则

### slot 计算规则

首先我们分析一下各种对象结构在 EVM 中的存储和访问情况

#### 定长变量和结构体

Solidity 中的定长定量在定义的时候，其长度就已经被限制住了。比如定长整型（uint、uint8），地址常量（address），定长字节数组（bytes1-32）等，这类的变量在 Storage 中是尽可能打包成 32 字节的块顺序存储的。

Solidity 的结构体并没有特殊的存储模型，在 Storage 中的存储可以按照定长变量规则分析。

#### Map 映射变量

在 Solidity 中，并不存储 map 的键，只存储键对应的值，值是通过键的 hash 索引来找到的。用 $slotM$ 表示 map 声明的 slot 位置，用 $key$ 表示键，用 $value$ 表示 $key$ 对应的值，用 $slotV$ 表示 $value$ 的存储位置，则

- $slotV = keccak256(key|slotM)$

- $value = sload(slotV)$

#### 变长数组

用 $slotA$ 表示变长数组声明的位置，用 $length$ 表示变长数组的长度，用 $slotV$ 表示变长数组数据存储的位置，用 $value$ 表示变长数组某个数据的值，用 $index$ 表示 $value$ 对应的索引下标，则

- $length = sload(slotA)$

- $slotV = keccak256(slotA) + index$

- $value = sload(slotV)$

变长数组在编译期间无法知道数组的长度，没办法提前预留存储空间，所以 Solidity 就用 $slotA$ 位置存储了变长数组的长度

!!! note
    注：变长数组具体数据存放在 keccak256 哈希计算之后的一片连续存储区域，这一点与 Map 映射变量不同。

### 漏洞介绍

在以太坊 EVM 的设计思路中，所有的 Storage 变量共用一片大小为 2^256*32 字节的存储空间，没有各自的存储区域划分。

Storage 空间即使很大也是有限大小，当变长数组长度很大时，考虑极端情况，如果长度达到 2^256，则可对任意 Storage 变量进行读写操作，这是非常可怕的。

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

这里攻击者如何才能成为 owner 呢？其中 owner 最初为 0x73048cec9010e92c298b016966bde1cc47299df5

### Analyse

- 数组 codex 的 slot 为 1 ，同时这也是存储数组 length 的地方，而 codex 的实际内容存储在 keccak256(bytes32(1)) 开始的位置

!!! info
    Keccak256 是紧密打包的，意思是说参数不会补位，多个参数也会直接连接在一起，所以要用 keccak256(bytes32(1))

- 这样我们就知道了 codex 实际的存储的 slot ，可以将动态数组内变量的存储位计算方法概括为: array[index] == sload(keccak256(slot(array)) + index). 

- 因为总共有 2^256 个 slot ，要修改 slot 0 ，假设 codex 实际所在 slot x ，(对于本题来说，数组的 slot是 1 , x=keccak256(bytes32(1))) ，那么当我们修改 codex[y]，(y=2^256-x+0) 时就能修改 slot 0 ，从而修改 owner
    - 计算 codex 位置为 slot 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6
    - 所以 y = 2^256 - 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6 + 0
    - 即 y = 35707666377435648211887908874984608119992236509074197713628505308453184860938

- 可以看到 y 很大，我们要修改 codex[y] ，那就要满足 y < codex.length ，而这个时候 codex.length =0 ，但是我们可以通过 retract() 使 length 下溢，然后就可以操纵 codex[y] 了
- 由上面已经计算出 codex[35707666377435648211887908874984608119992236509074197713628505308453184860938] 对应的存储位就是 slot 0 ，而 slot 0 中同时存储了 contact 和 owner ，我们只需将 owner 换成 attacker 即可，假设 attacker 地址是 0x88d3052d12527f1fbe3a6e1444ea72c4ddb396c2，则如下所示

```
contract.revise('35707666377435648211887908874984608119992236509074197713628505308453184860938','0x00000000000000000000000088d3052d12527f1fbe3a6e1444ea72c4ddb396c2')
```

## 题目

### XCTF_final 2019
- 题目名称 Happy_DOuble_Eleven

### Balsn 2019
- 题目名称 Bank

### 第一届钓鱼城杯 2020
- 题目名称 StrictMathematician

### RCTF 2020
- 题目名称 roiscoin

!!! note
    注：题目附件相关内容可至 [ctf-challenges/blockchain](https://github.com/ctf-wiki/ctf-challenges/tree/master/blockchain) 仓库寻找。
