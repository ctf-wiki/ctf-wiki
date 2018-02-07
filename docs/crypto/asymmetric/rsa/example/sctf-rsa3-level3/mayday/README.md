# mayday (crypto 150)

這是先前跟著隊友作為亂入隊伍，去打 TW-edu CTF 2015 （台大、台科大、中央三校資安實務期末考）的小小紀錄XD

~~表示還欠了很多題目的還沒寫~~

雖然最後結束出來的成績不是很好，不過這次去亂入這個 CTF 感覺真的累積不少經驗值呢！<br>
因為是配合課程進行的關係，所以大多數題目都是應用一些經典的漏洞或是攻擊技巧，或是簡單的搭配，<br>
對我們這群弱弱來說，打起來也比較有成就感，大家比較有動力挑戰看看<br>
畢竟一般其他 CTF 的題目真的很難很難，需要很多背景知識才能玩下去XDDDD<br>

先來說明一下，按照大部分在講 RSA 的文章的慣例，一般說 <img src="http://latex2png.com/output//latex_9137fac0125df890a70326ee7d009c1b.png" height=15/> 指的是明文 (cleartext)、<img src="http://latex2png.com/output//latex_73de1ac8af38ebfcf7fc627715aeda46.png" height=12 /> 指的是密文（ciphertext）、<img src="http://latex2png.com/output//latex_735f8af029197c52c5e525e478b29e95.png" height=12 /> 指的是模數（<img src="http://latex2png.com/output//latex_323ca6f1e3bbf948172ce6d3796dc298.png" height=12 /> 兩個大質數的積，可以說成是公鑰的一部分，有時會用 <img src="http://latex2png.com/output//latex_d5b89c297bbfc4f3b7b824eb83764922.png" height=12 /> 替代），而 <img src="http://latex2png.com/output//latex_5adf2318d23fdafcf4b8231ff28815f0.png" height=12 />、<img src="http://latex2png.com/output//latex_4ed1f7a6e493e01e42932e12ca94685c.png" height=12 /> 則分別是公用指數（通常是 3, 7, 17, 65537）跟私密指數，兩者對同餘 <img src="http://i.imgur.com/vkoE8Q7.png" height=12 /> 時呈模反元素關係。

Description:
```
Here are some encrypted messages sent to Mayday.
https://www.dropbox.com/s/lwjkboz8ee8wz6l/mayday.zip?dl=0
```

題目給的 zip 解開後有 `mayday.py` 跟 `mayday.json` 兩個檔案，跟一般 crypto 題目一樣的，一個是進行加密的 code，另一個則是相關的數字/資料。

`mayday.json`:
```javascript
[{"c": 6867940996691870031530411714485906844552818193325528906319305401428815108346680759433216763381096732182463314446219239703961679396462026276373332783945618, "e": 7, "n": 24810910852704603048663349011054669655631146433543459534796438815331335687309113943583212235150241971378068933151593149818684880078674098193758773603399061},
{"c": 1117905220184329685115491669660129193823567641747584717324745389247133369892051586020708442213591696394252275224109800066498394464330197218398972106358012, "e": 7, "n": 47127839105299361033791208737798899776781255381503030381686909082155757361019104103280620540716894699133142173100175132195577832323495741588275138089635573},
{"c": 40118076943735337559537379692982070943921515348000211097599356263330760075906748374129727526740438883695094503103029124366037118931371140019302082751801200, "e": 7, "n": 43134291711046821358455351358884087777021003839470296505990450581706219379356272391794220129036895199873385802547302584174011929423801149992868607229780347},
{"c": 12649076592222649371192164869044025408231371717627780046219346377852024544337050152652676577122342534868958091714335614555475487488062150879916823763757293, "e": 7, "n": 19300838921149221007298944887478599082800229045219271606272038103970656559943914197281654158587468730541828306489197866130025079021184391333521894567512679},
{"c": 28899089935435267588235897519846120393433214114341521238696384122507316899457327055029546972333281452563984838498862225380416594907544057513529315866966881, "e": 7, "n": 30754121488827635692971849599267749375077949182550303145729325375314926401905783830931628738658879320179944880074582359287457299694791345311565979620527051},
{"c": 14086629413855672403639830676118042465846020320143823318815048070368505684208141652603596234960968703217788472960409410744177258293358579948872603962777501, "e": 7, "n": 30430477983470426195631142659668071772256641205525929891985872996115858010744648779370983539942187689192406517498678966428105726004485493523914299389645977},
{"c": 20049299207588955907155276095787913402589652379134151403340360498371893119855957833576443856534037886298731701974026748277461327934437483689818240109850533, "e": 7, "n": 35489275126536805974281635942907480463916089663069129771420548612817920902692423639961709000309976531819984030335085090156962285880892504720123765878938153}]
```

`mayday.json` 給了我們七組 RSA 的數字，各自的  不同，不過它們的 e 都是 7<br>
而由於 <img src="http://latex2png.com/output//latex_735f8af029197c52c5e525e478b29e95.png" height=12 /> 的數字非常大，我們知道也不可能因數分解來暴力破解它。

`mayday.py`:
```python
import json
from sympy import randprime

e = 7
m = int(open('flag').read().strip().encode('hex'), 16)

for i in range(7):
    p = randprime(2 ** 256, 2 ** 257)
    q = randprime(2 ** 256, 2 ** 257)
    n = p * q
    assert m < n
    c = pow(m, e, n)
    print json.dumps({'n': n, 'e': e, 'c': c})
```

有趣的是，根據 `mayday.py`，所有的明文 <img src="http://latex2png.com/output//latex_9137fac0125df890a70326ee7d009c1b.png" height=12 /> 都是一樣的，而被用了不同的公鑰（這邊指 <img src="http://latex2png.com/output//latex_735f8af029197c52c5e525e478b29e95.png" height=12 />）加密，而正剛好有 7 個明文（大於 <img src="http://latex2png.com/output//latex_5adf2318d23fdafcf4b8231ff28815f0.png" height=12 />，這樣就構成了 [Hastad's Broadcast Attack](https://en.wikipedia.org/wiki/Coppersmith%27s_Attack#H.C3.A5stad.27s_Broadcast_Attack)（RSA 廣播攻擊）的要件。

Hastad's Broadcast Attack 基本上就是[中國餘數定理 （Chinese Remainder Theorem）](https://market.cloud.edu.tw/content/senior/math/tn_t2/math05/math_magic/1/1-6.htm)（也就是數學老師說的韓信點兵、鬼谷算命題）在 RSA 密碼學上的實作，<br>

根據中國餘數定理（這裡以 <img src="http://latex2png.com/output//latex_4fe4b757e7be068210be64335367e2a3.png" height=12 /> 做舉例），只要，就可以求出 <img src="http://latex2png.com/output//latex_0b50ff01cf5051f1539b6acbd5c51b63.png" height=12 />，而因為 <img src="http://latex2png.com/output//latex_9137fac0125df890a70326ee7d009c1b.png" height=12 /> 小於每一個 <img src="http://latex2png.com/output//latex_86c4c77d50772b63f7a210c18f2ca0fd.png" height=12 />，<img src="http://latex2png.com/output//latex_fb99a39a38225c4d80e582e5048a2332.png" height=12 /> 會小於 <img src="http://latex2png.com/output//latex_b6a455b85da2e6e66bff2230f434d937.png" height=12 />，<br>
所以就可以不用管後面的模算法，直接就可以求出 ![t^3 = c'](http://latex2png.com/output//latex_0974e7ce8816396d23057025516341f5.png" height=12 />。

這邊提供了七組的 <img src="http://latex2png.com/output//latex_bfd866dd6d681fbf9ab8eec5f7343d5b.png" height=12 /> ，化成同餘式則是七組 <img src="http://latex2png.com/output//latex_07401cdb4f2a419f8697ae10a7f05410.png" height=12 /> （<img src="http://latex2png.com/output//latex_6c8bc8685c4da46e52dc9d44c1507b78.png" height=12 />），透過上面的方式就可以推出原先的 <img src="http://latex2png.com/output//latex_01d7ca40c5423d96dd1a3b3aad783d3b.png" height=12 />，<br>
再來就只要 <img src="http://latex2png.com/output//latex_5adf2318d23fdafcf4b8231ff28815f0.png" height=12 /> 的值沒有太高（這裡是7），可以快速求出其次方根，就可以解出 <img src="http://latex2png.com/output//latex_9137fac0125df890a70326ee7d009c1b.png" height=12 />。

所以我們來解這個同餘方程組吧！不重造輪子，我找了 [Rosetta Code 上的 CRT solver](http://rosettacode.org/wiki/Chinese_remainder_theorem#Python) （針對解中國餘式定理的同餘方程組的工具：

```python
import gmpy   # gmpy 是一個在 python 提供類似 GMP 的高等算術的 module，這裡用它算模反元素跟次方根
import json, binascii   # json 是 python 下的 json parsing 工具，binascii 則是用來做 binary 跟 ascii 之間轉換的工具
from functools import reduce

def chinese_remainder(n, a):   # Rosetta Code 上的 CRT Solver code，就只是把中國餘數定理 code 化而已
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * modinv(p, n_i) * p
    return int(sum % prod)
def modinv(a, m): return int(gmpy.invert(gmpy.mpz(a), gmpy.mpz(m)))   # 用 gmpy 算模反元素，回傳轉成 int 的結果


with open("mayday.json") as dfile:
    data = json.loads(dfile.read())   # 打開檔案，讀成 json
data = {k:[d.get(k) for d in data] for k in {k for d in data for k in d}}   # 從 [{c1, e1, n1}, {c2, e2, n2}] 轉成 {"c": [c1, c2], "e": [e1, e2], "n": [n1, n2]}
t_to_e = chinese_remainder(data['n'], data['c'])   # 用中國餘式定理解同餘方程組，推出原先的 t^e
t = int(gmpy.mpz(t_to_e).root(7)[0])   # 算 t^e 的 7 次方根（因為 e=7），推回原本的 t
print(binascii.unhexlify(hex(t)[2:]))   # 把結果從數字先轉成 hex 再轉成字串
...
```

Flag: `CTF{Hastad's Broadcast Attack & Chinese Remainder Theorem}`

應該是因為配合資安課程的關係，這是一題非常經典，利用 textbook RSA （純理論 RSA）的漏洞進行的題目。<br>
實際上在進行 RSA 加密應用的時候，主要是因為 padding 的技巧讓每一次的 <img src="http://latex2png.com/output//latex_9137fac0125df890a70326ee7d009c1b.png" height=12 /> 都不一樣，這樣的攻擊型態就會失效，所以這種的攻擊在實務上是很難達到什麼影響的。<br>
不過有一點值得提到的是，在這種 textbook RSA 中，可以看到這樣的數學理論實際用在密碼學上也是挺有趣的XDD
