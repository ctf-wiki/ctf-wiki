# RSA 側信道攻擊

能量分析攻擊（側信道攻擊）是一種能夠從密碼設備中獲取祕密信息的密碼攻擊方法．與其
他攻擊方法不同：這種攻擊利用的是密碼設備的能量消耗特徵，而非密碼算法的數學特性．能量分析攻擊是一種非入侵式攻擊，攻擊者可以方便地購買實施攻擊所需要的設備：所以這種攻擊對智能卡之類的密碼設備的安全性造成了嚴重威脅。

能量分析攻擊是安全領域內非常重要的一個部分，我們只在這裏簡單討論下。

能量分析攻擊分爲：
- 簡單能量分析攻擊（SPA），即對能量跡進行直觀分析，肉眼看即可。
- 差分能量分析攻擊（DPA），基於能量跡之間的相關係數進行分析。

## 攻擊條件

攻擊者可獲取與加解密相關的側信道信息，例如能量消耗、運算時間、電磁輻射等等。

## 例子
這裏我們以 HITB 2017 的 Hack in the card I 作爲例子。

題目給出了公鑰文件 `publickey.pem`，密文，測量智能卡功率的電路圖，和**解密**過程中智能卡消耗的功率變化（通過在線網站給出 [trace](http://47.74.147.53:20015/index.html)）。

![Circuit diagram](./figure/circuitdiagram.png)

密文：
```
014b05e1a09668c83e13fda8be28d148568a2342aed833e0ad646bd45461da2decf9d538c2d3ab245b272873beb112586bb7b17dc4b30f0c5408d8b03cfbc8388b2bd579fb419a1cac38798da1c3da75dc9a74a90d98c8f986fd8ab8b2dc539768beb339cadc13383c62b5223a50e050cb9c6b759072962c2b2cf21b4421ca73394d9e12cfbc958fc5f6b596da368923121e55a3c6a7b12fdca127ecc0e8470463f6e04f27cd4bb3de30555b6c701f524c8c032fa51d719901e7c75cc72764ac00976ac6427a1f483779f61cee455ed319ee9071abefae4473e7c637760b4b3131f25e5eb9950dd9d37666e129640c82a4b01b8bdc1a78b007f8ec71e7bad48046
```

### 分析
由於網站只給出了一條能量跡，所以可以斷定這是 Simple channel analysis（SPA）攻擊。那麼我們可以直接通過觀察能量跡的高低電平來獲得 RSA 解密過程的密鑰 d。
RSA 可被 SPA 攻擊的理論基礎來自於 RSA 中包含的快速冪取餘算法。


快速冪算法如下

1. b 爲偶數時，$a^b \bmod c = ({a^2}^{b/2}) \bmod c$。
2. b 爲奇數時，$a^b \bmod c = ({a^2}^{b/2} \times a) \bmod c$。

相應的 C 代碼實現爲：
```c
int PowerMod(int a, int b, int c)
{
    int ans = 1;
    a = a % c;
    while(b>0) {
        if(b % 2 == 1) // 當b爲奇數時會多執行下面的指令
	        ans = (ans * a) % c;
        b = b/2;
        a = (a * a) % c;
    }
    return ans;
}
```

由於快速冪的計算過程中會逐位判斷指數的取值，並會採取不同的操作，所以可從能量跡中還原出 d 的取值（從上面可知，直接得到的值是 d 的二進製取值的**逆序**）。

**注意**：

> 有時候模乘也可能會從高位向低位進行模乘。這裏是從低位向高位模乘。

![](./figure/trace.png)

由此可給出還原 d 的腳本如下：

```python
f = open('./data.txt')
data = f.read().split(",")
print('point number:', len(data))

start_point = 225   # 開始分析的點
mid = 50            # 採樣點間隔
fence = 228         # 高低電平分界線

bin_array = []

for point_index in range(start_point, len(data), mid):
    if float(data[point_index]) > fence:
        bin_array.append(1)
    else:
        bin_array.append(0)

bin_array2 = []
flag1 = 0
flag2 = 0
for x in bin_array:
    if x:
        if flag1:
            flag2 = 1
        else:
            flag1 = 1
    else:
        if flag2:
            bin_array2.append(1)
        else:
            bin_array2.append(0)
        flag1 = 0
        flag2 = 0

# d_bin = bin_array2[::-1]
d_bin = bin_array2
d = "".join(str(x) for x in d_bin)[::-1]
print(d)
d_int = int(d,2)
print(d_int)
```
## 參考資料
1. Mangard, S., Oswald, E., Popp, T., 馮登國, 周永彬, & 劉繼業. (2010). 能量分析攻擊.
