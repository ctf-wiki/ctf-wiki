# 總結

## 古典密碼分析思路

CTF 中有關古典密碼的題目，通常是根據密文求出明文，因此採用**唯密文攻擊**居多，基本分析思路總結如下：

1. 確定密碼類型：根據題目提示、加密方式、密文字符集、密文展現形式等信息。
2. 確定攻擊方法：包括直接分析、蠻力攻擊、統計分析等方法。對於無法確定類型的特殊密碼，應根據其密碼特性選用合適的攻擊方法。
3. 確定分析工具：以在線密碼分析工具與 Python 腳本工具包爲主，以離線密碼分析工具與手工分析爲輔。

以上唯密文攻擊方法的適用場景與舉例如下：

| 攻擊方法   | 適用場景                           | 舉例                                   |
| ---------- | ---------------------------------- | -------------------------------------- |
| 直接分析法 | 由密碼類型可確定映射關係的代換密碼 | 凱撒密碼、豬圈密碼、鍵盤密碼等         |
| 蠻力攻擊法 | 密鑰空間較小的代換密碼或置換密碼   | 移位密碼、柵欄密碼等                   |
| 統計分析法 | 密鑰空間較大的代換密碼             | 簡單替換密碼、仿射密碼、維吉尼亞密碼等 |

## 實驗吧 圍在柵欄裏的愛

題目描述

> 最近一直在好奇一個問題，QWE 到底等不等於 ABC？
>
> -.- .. --.- .-.. .-- - ..-. -.-. --.- --. -. ... --- ---
>
> flag格式：CTF{xxx}

首先，根據密碼樣式判斷是摩斯電碼，解密後得到 `KIQLWTFCQGNSOO`，看着也不像 flag，題目中還有還有柵欄與 `QWE到底等不等於ABC`，兩個都試了試之後，發現是先 QWE 然後柵欄可得到結果。  

首先鍵盤 QWE 解密，試着解密得到 `IILYOAVNEBSAHR`。繼而柵欄解密得到 `ILOVESHIYANBAR`。

## 2017 SECCON Vigenere3d

程序如下

```python
# Vigenere3d.py
import sys
def _l(idx, s):
    return s[idx:] + s[:idx]
def main(p, k1, k2):
    s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}"
    t = [[_l((i+j) % len(s), s) for j in range(len(s))] for i in range(len(s))]
    i1 = 0
    i2 = 0
    c = ""
    for a in p:
        c += t[s.find(a)][s.find(k1[i1])][s.find(k2[i2])]
        i1 = (i1 + 1) % len(k1)
        i2 = (i2 + 1) % len(k2)
    return c
print main(sys.argv[1], sys.argv[2], sys.argv[2][::-1])

$ python Vigenere3d.py SECCON{**************************} **************
POR4dnyTLHBfwbxAAZhe}}ocZR3Cxcftw9
```

**解法一**：

首先，我們先來分析一下 t 的構成
$$
t[i][j]=s[i+j:]+s[:i+j] \\
t[i][k]=s[i+k:]+s[:i+k]
$$

$t[i][j][k]$ 爲 $t[i][j]$ 中的第 k 個字符，$t[i][k][j]$ 爲 $t[i][k]$ 中的第 j 個字符。無論是 $i+j+k$ 是否超過 `len(s)` 兩者都始終保持一致，即 $t[i][j][k]=t[i][k][j]$ 。

故而，其實對於相同的明文來說，可能有多個密鑰使其生成相同的密文。

然而上面分析就是單純地分析而已，，下面開始正題。

不難看出，密文的每一位只與明文的相應位相關，而且，密鑰的每一位的空間最大也就是 s 的大小，所以我們可以使用爆破來獲取密鑰。這裏根據上述命令行提示，可以知道密鑰長度爲 14，恰好明文前面7個字節已知。恢復密鑰的 exp 如下

```python
def get_key(plain, cipher):
    s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}"
    t = [[_l((i + j) % len(s), s) for j in range(len(s))]
         for i in range(len(s))]
    i1 = 0
    i2 = 0
    key = ['*'] * 14
    for i in range(len(plain)):
        for i1 in range(len(s)):
            for i2 in range(len(s)):
                if t[s.find(plain[i])][s.find(s[i1])][s.find(s[i2])] == cipher[
                        i]:
                    key[i] = s[i1]
                    key[13 - i] = s[i2]
    return ''.join(key)
```

恢復明文的腳本如下

```python
def decrypt(cipher, k1, k2):
    s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}"
    t = [[_l((i + j) % len(s), s) for j in range(len(s))]
         for i in range(len(s))]
    i1 = 0
    i2 = 0
    plain = ""
    for a in cipher:
        for i in range(len(s)):
            if t[i][s.find(k1[i1])][s.find(k2[i2])] == a:
                plain += s[i]
                break
        i1 = (i1 + 1) % len(k1)
        i2 = (i2 + 1) % len(k2)
    return plain
```

得到明文如下

```shell
➜  2017_seccon_vigenere3d git:(master) python exp.py
SECCON{Welc0me_to_SECCON_CTF_2017}
```
**解法二**

關於此題的分析：

1. 考慮到在程序正常運行下，數組訪問不會越界，我們在討論時做以下約定：$arr[index] \Leftrightarrow arr[index \% len(arr)]$
2. 關於 python 程序中定義的 `_l` 函數，發現以下等價關係：$\_l(offset, arr)[index] \Leftrightarrow arr[index + offset]$
3. 關於 python 的 main 函數中三維矩陣 t 的定義，發現以下等價關係：$t[a][b][c] \Leftrightarrow \_l(a+b, s)[c]$
4. 綜合第 2 第 3 點的觀察，有如下等價關係：$t[a][b][c] \Leftrightarrow s[a+b+c]$
5. 我們將 s 視爲一種編碼格式，即：編碼過程 s.find(x)，解碼過程 s[x]。並直接使用其編碼結果的數字替代其所代指的字符串，那麼加密過程可以用以下公式表示：
   - $e = f +  k1 +k2$
   - 其中，e 是密文，f 是明文，k1 與 k2 是通過複製方法得到、與 f 長度一樣的密鑰，**加法是向量加**。

所以我們只需要通過計算 `k1+k2` ，模擬密鑰，即可解密。關於此題的解密 python 腳本：

```python
# exp2.py
enc_str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}'
dec_dic = {k:v for v,k in enumerate(enc_str)}
encrypt = 'POR4dnyTLHBfwbxAAZhe}}ocZR3Cxcftw9'
flag_bg = 'SECCON{**************************}'

sim_key = [dec_dic[encrypt[i]]-dec_dic[flag_bg[i]] for i in range(7)] # 破解模擬密鑰
sim_key = sim_key + sim_key[::-1]

flag_ed = [dec_dic[v]-sim_key[k%14] for k,v in enumerate(encrypt)] # 模擬密鑰解密
flag_ed = ''.join([enc_str[i%len(enc_str)] for i in flag_ed]) # 解碼
print(flag_ed)
```

得到明文如下：

```bash
$ python exp2.py
SECCON{Welc0me_to_SECCON_CTF_2017}
```

## 消失的三重密碼

密文
```
of zit kggd zitkt qkt ygxk ortfzoeqs wqlatzwqssl qfr zvg ortfzoeqs yggzwqssl. fgv oy ngx vqfz zg hxz zitd of gft soft.piv dgfn lgsxzogfl qkt zitkt? zohl:hstqlt eiqfut zit ygkd gy zit fxdwtk ngx utz.zit hkgukqddtkl!
```

使用 quipquip 直接解密。
