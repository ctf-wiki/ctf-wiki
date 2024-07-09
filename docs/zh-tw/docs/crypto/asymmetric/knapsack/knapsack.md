# 揹包加密

## 揹包問題

首先，我們先來介紹一下揹包問題，假定一個揹包可以稱重 W，現在有 n 個物品，其重量分別爲 $a_1, a_2,...,a_n$ 我們想問一下裝哪些物品可以恰好使得揹包裝滿，並且每個物品只能被裝一次。這其實就是在解這樣的一個問題

$$
x_1a_1+x_2a_2+,...,+x_na_n=W
$$

其中所有的 $x_i$ 只能爲 0 和 1。顯然我們必須枚舉所有的 n 個物品的組合才能解決這個問題，而複雜度也就是 $2^n$，這也就是揹包加密的妙處所在。

在加密時，如果我們想要加密的明文爲 x，那麼我們可以將其表示爲 n 位二進制數，然後分別乘上 $a_i$ 即可得到加密結果。

但是解密的時候，該怎麼辦呢？我們確實讓其他人難以解密密文，但是我們自己也確實沒有辦法解密密文。

但是當 $a_i$ 是超遞增的話，我們就有辦法解了，所謂超遞增是指序列滿足如下條件

$$
a_i>\sum_{k=1}^{i-1}a_k
$$

即第 i 個數大於前面所有數的和。

爲什麼滿足這樣的條件就可以解密了呢？這是因爲如果加密後的結果大於 $a_n$ 的話，其前面的係數爲必須 1 的。反之，無論如何也無法使得等式成立。因此，我們可以立馬得到對應的明文。

但是，這樣又出現了一個問題，由於 $a_i$ 是公開的，如果攻擊者截獲了密文，那麼它也就很容易去破解這樣的密碼。爲了彌補這樣的問題，就出現了 Merkle–Hellman 這樣的加密算法，我們可以使用初始的揹包集作爲私鑰，變換後的揹包集作爲公鑰，再稍微改動加密過程，即可。

這裏雖然說了超遞增序列，但是卻沒有說是如何生成的。

## Merkle–Hellman

### 公私鑰生成

#### 生成私鑰

私鑰就是我們的初始的揹包集，這裏我們使用超遞增序列，怎麼生成呢？我們可以假設 $a_1=1$，那麼 $a_2$ 大於 1 即可，類似的可以依次生成後面的值。

#### 生成公鑰

在生成公鑰的過程中主要使用了模乘的運算。

首先，我們生成模乘的模數 m，這裏要確保

$$
m>\sum_{i=1}^{i=n}a_i
$$

其次，我們選擇模乘的乘數 w，作爲私鑰並且確保

$$
gcd(w,m)=1
$$

之後，我們便可以通過如下公式生成公鑰

$$
b_i \equiv w a_i \bmod m
$$

並將這個新的揹包集 $b_i$ 和 m 作爲公鑰。

### 加解密

#### 加密

假設我們要加密的明文爲 v，其每一個比特位爲 $v_i$，那麼我們加密的結果爲

$$
\sum_{i=1}^{i=n}b_iv_i \bmod m
$$

#### 解密

對於解密方，首先可以求的 w 關於 m 的逆元 $w^{-1}$。

然後我們可以將得到的密文乘以 $w^{-1}$ 即可得到明文，這是因爲

$$
\sum_{i=1}^{i=n}w^{-1}b_iv_i \bmod m=\sum_{i=1}^{i=n}a_iv_i \bmod m
$$

這裏有

$$
b_i \equiv w a_i \bmod m
$$

對於每一塊的加密的消息都是小於 m 的，所以求得結果自然也就是明文了。

### 破解

該加密體制在提出後兩年後該體制即被破譯，破譯的基本思想是我們不一定要找出正確的乘數 w（即陷門信息），只需找出任意模數 `m′` 和乘數 `w′`，只要使用 `w′` 去乘公開的揹包向量 B 時，能夠產生超遞增的揹包向量即可。

### 例子

這裏我們以 2014 年 ASIS Cyber Security Contest Quals 中的 Archaic 爲例，[題目鏈接](https://github.com/ctfs/write-ups-2014/tree/b02bcbb2737907dd0aa39c5d4df1d1e270958f54/asis-ctf-quals-2014/archaic)。

首先查看源程序

```python
secret = 'CENSORED'
msg_bit = bin(int(secret.encode('hex'), 16))[2:]
```

首先得到了 secret 的所有二進制位。

其次，利用如下函數得到 keypair，包含公鑰與私鑰。

```python
keyPair = makeKey(len(msg_bit))
```

仔細分析 makekey 函數，如下

```python
def makeKey(n):
	privKey = [random.randint(1, 4**n)]
	s = privKey[0]
	for i in range(1, n):
		privKey.append(random.randint(s + 1, 4**(n + i)))
		s += privKey[i]
	q = random.randint(privKey[n-1] + 1, 2*privKey[n-1])
	r = random.randint(1, q)
	while gmpy2.gcd(r, q) != 1:
		r = random.randint(1, q)
	pubKey = [ r*w % q for w in privKey ]
	return privKey, q, r, pubKey
```

可以看出 prikey 是一個超遞增序列，並且得到的 q 比 prikey 中所有數的和還要大，此外我們得到的 r，恰好與 q 互素，這一切都表明了該加密是一個揹包加密。

果然加密函數就是對於消息的每一位乘以對應的公鑰並求和。

```python
def encrypt(msg, pubKey):
	msg_bit = msg
	n = len(pubKey)
	cipher = 0
	i = 0
	for bit in msg_bit:
		cipher += int(bit)*pubKey[i]
		i += 1
	return bin(cipher)[2:]
```

對於破解的腳本我們直接使用 [GitHub](https://github.com/ctfs/write-ups-2014/tree/b02bcbb2737907dd0aa39c5d4df1d1e270958f54/asis-ctf-quals-2014/archaic) 上的腳本。進行一些簡單的修改。

```python
import binascii
# open the public key and strip the spaces so we have a decent array
fileKey = open("pub.Key", 'rb')
pubKey = fileKey.read().replace(' ', '').replace('L', '').strip('[]').split(',')
nbit = len(pubKey)
# open the encoded message
fileEnc = open("enc.txt", 'rb')
encoded = fileEnc.read().replace('L', '')
print "start"
# create a large matrix of 0's (dimensions are public key length +1)
A = Matrix(ZZ, nbit + 1, nbit + 1)
# fill in the identity matrix
for i in xrange(nbit):
    A[i, i] = 1
# replace the bottom row with your public key
for i in xrange(nbit):
    A[i, nbit] = pubKey[i]
# last element is the encoded message
A[nbit, nbit] = -int(encoded)

res = A.LLL()
for i in range(0, nbit + 1):
    # print solution
    M = res.row(i).list()
    flag = True
    for m in M:
        if m != 0 and m != 1:
            flag = False
            break
    if flag:
        print i, M
        M = ''.join(str(j) for j in M)
        # remove the last bit
        M = M[:-1]
        M = hex(int(M, 2))[2:-1]
		print M
```

輸出之後再解碼下

```python
295 [1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0]
415349535f3962643364356664323432323638326331393536383830366130373036316365
>>> import binascii
>>> binascii.unhexlify('415349535f3962643364356664323432323638326331393536383830366130373036316365')
'ASIS_9bd3d5fd2422682c19568806a07061ce'
```

需要注意的是，我們得到的 LLL 攻擊得到的矩陣 res 的只包含 01 值的行纔是我們想要的結果，因爲我們對於明文加密時，會將其分解爲二進制比特串。此外，我們還需要去掉對應哪一行的最後一個數字。

flag 是 `ASIS_9bd3d5fd2422682c19568806a07061ce`。

### 題目

- 2017 國賽 classic
