# 题目

## 2019 强网杯 babysampling/sampling

babysampling给出了一个lfsr每经过7bit输出1bit的数据，mask未知，要求还原lfsr的初始状态。 

这里我们注意到间隔7bit的输出仍然是一个lfsr，可以通过berlekamp_massey算法获取到这个lfsr的多项式信息，那么只要将多项式中的x替换为x^7，就可以作用到原始lfsr的输出上，那么原始lfsr的多项式必然是它的一个因子，我们就可以枚举出所有因子来得到可能的mask集合，通过对degree进行筛选我们可以去掉很多不符合条件的因子，因此实际复杂度并不高。 

假如得到mask我们就可以构建线性方程组来还原lfsr的初始状态了，使用给出的sha256进行验证即可。这里加了个筛选条件是如果当前mask组合出来的矩阵rank过低，即解的自由度过高，就直接舍去这个mask，因为本地测试的rank分布都会比较接近129。

在babysampling中，最初只挑选了degree为129的因子没有出来，本地测试时发现偶尔会有degree比较小的因子，因此改了下筛选条件很快就跑出来了。 

sampling的惟一区别是从第129bit开始输出，方法类似，求解线性方程时稍作修改即可。

```
from hashlib import sha256
from itertools import product

with open('output','rb') as f:
    s=f.read()
tarh = "bdde9837d5228a9ff33c00be1daf46489b7dafdd88750827e93d0dbd56477e7c"

bs = ''.join(map(lambda x:bin(ord(x))[2:].rjust(8,'0'),s))
print len(bs)
#print bs

seq = []
F = GF(2)
for i in range(1024):
    seq.append(F(int(bs[i])))

P.<x> = PolynomialRing(F)
poly = berlekamp_massey(seq)

p7 = poly.subs(x^7)
fs = factor(p7)
#tar = 559282078126269518888830963030439834975
#tar = 404314640861877153229506089020527528203
tar=658830303166448434138558730570919555209

tmp = [0]*128
mat = [vector(GF(2),tmp)]
for i in range(128):
    tmp = [0]*128
    tmp[i] = 1
    mat.append(vector(GF(2),tmp))

def solveone(msk):
    v = map(int, bin(msk)[2:])
    if len(v)<129:
        pre = [0]*(129-len(v))
        v = pre+v
    assert len(v)==129
    mata = deepcopy(mat)
    for i in range(129, 7*128+1):
        tmp = [0]*128
        tmp = vector(GF(2),tmp)
        for j in range(129):
            if v[j]==1:
                tmp += mata[i-129+j]
        mata.append(tmp)
    equs = []
    res = []

    for i in range(128):
        res.append(seq[i])
        equs.append(mata[7*i])
    #equs = matrix(GF(2),equs)
    #res = vector(GF(2),res)

    freedom = 128-matrix(GF(2),equs).rank()
    print freedom
    if freedom>6:
        return

    for xs in product(range(2),repeat=freedom):
        equsa = deepcopy(equs)
        resa = deepcopy(res)
        for ix in range(freedom):
            equsa.append(mat[ix+1])
            resa.append(xs[ix])
        equsa = matrix(GF(2),equsa)
        resa = vector(GF(2),resa)
        try:
            X = equsa.solve_right(resa)
        except:
            continue
        assert len(X)==128
        val = int(''.join(map(str,X)),2)
        h = hex(val)[2:].strip('L').rjust(32,'0')
        flag = 'flag{'+h+'}'
        print flag
        if sha256(flag).hexdigest()==tarh:
            print '!!!!!!!!!!!!!!!!!!!!!!!'
            print flag
            exit()
        

def do_search(pos,cur):
    if pos>=len(fs):
        if cur.degree()<129 and cur.degree()>120:
            #print cur
            msk = int(''.join(map(str,vector(cur)[:-1])),2)
            print 'trying',msk
            solveone(msk)
        return
    if cur.degree()>129:
        return
    for i in range(fs[pos][1]+1):
        do_search(pos+1, cur*fs[pos][0]^i)
    
do_search(0, x^0)
```
