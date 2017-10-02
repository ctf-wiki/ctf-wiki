.. role:: math(raw)
   :format: html latex
..

原理
====

公钥与私钥的产生
----------------

1. 随机选择两个不同大质数 :math:`p` 和 :math:`q`\ ，计算
   :math:`N=p \times q`\ 。
2. 根据欧拉函数，求得
   :math:`r=\varphi (N)=\varphi (p)\varphi (q)=(p-1)(q-1)`\ 。
3. 选择一个小于 :math:`r` 的整数 :math:`e`\ ，使 :math:`e` 和 :math:`r`
   互质。并求得 :math:`e` 关于 :math:`r` 的模反元素，命名为
   :math:`d`\ （ :math:`ed\equiv 1 \pmod r`\ ）。
4. 将 :math:`p` 和 :math:`q` 的记录销毁。

此时，\ :math:`(N,e)` 是公钥，\ :math:`(N,d)` 是私钥。

消息加密
--------

首先需要将消息 :math:`m` 以一个双方约定好的格式转化为一个小于
:math:`N`\ ，且与 :math:`N` 互质的整数
:math:`n`\ 。如果消息太长，可以将消息分为几段，这也就是我们所说的块加密，后对于每一部分利用如下公式加密：

.. math::


   n^{e}\equiv c\pmod N

消息解密
--------

利用密钥 :math:`d` 进行解密。

.. math::


   c^{d}\equiv n\pmod N

正确性证明
----------

即我们要证\ :math:`n^{ed} \equiv n \bmod N`,
已知\ :math:`ed \equiv 1 \bmod \phi(N)` ，
那么\ :math:`ed=k\phi(N)+1`\ ，即需要证明

.. math::


   n^{k\phi(N)+1}  \equiv n \bmod N

 这里我们分两种情况证明

第一种情况\ :math:`gcd(n,N)=1`
，那么\ :math:`n^{\phi(N)} \equiv 1 \bmod N` ，因此原式成立。

第二种情况\ :math:`gcd(n,N)!=1`\ ，
那么n必然是p或者q的倍数，并且n小于N。我们假设

.. math::


   n=xp

 那么x必然小于q，又由于q是素数。那么

.. math::


   n^{\phi(q)} \equiv 1 \bmod q

 进而

.. math::


   n^{k\phi(N)}=n^{k(p-1)(q-1)}=(n^{\phi(q)})^{k(p-1)} \equiv 1 \bmod q

 那么\ :math:`n^{k\phi(N)+1}=n+uqn`
，进而\ :math:`n^{k\phi(N)+1}=n+uqxp=n+uxN`\ ，所以原式成立。

基本工具
========

RSAtool
-------

-  安装

``bash   git clone https://github.com/ius/rsatool.git   cd rsatool   python rsatool.py -h``

功能：

-  生成私钥

``bash   python rsatool.py -f PEM -o private.pem -p 1234567 -q 7654321``

关于更多的功能请参考readme。

RSA Converter
-------------

-  根据给定密钥对，生成 pem 文件
-  **根据 n，e，d 得出p，q**

openssl
-------

-  查看公钥文件

``bash   openssl rsa -pubin -in pubkey.pem -text -modulus``

-  解密

``bash   rsautl -decrypt -inkey private.pem -in flag.enc -out flag``

更加具体的细节请参考 ``openssl --help``\ 。

分解整数工具
------------

-  `factor.db <http://factordb.com/>`__
-  `yafu <https://sourceforge.net/projects/yafu/>`__

python 库
---------

gmpy
~~~~

常见用法

-  ``gmpy.root(a, b)``\ ，返回一个元组 ``(x, y)``\ ，其中 ``x`` 为 ``a``
   开 ``b`` 次方的值，\ ``y``\ 是判断 ``x`` 是否为整数的布尔型变量。

gmpy2
~~~~~

安装时，可能会需要自己另行安装mfpr与mpc库。

常见用法

-  ``gmpy2.iroot(a, b)``\ ， 类似于gmpy.root(a,b)

pycrypto
~~~~~~~~

-  安装

``bash   sudo pip install pycrypto``

-  使用

\`\`\`python import gmpy from Crypto.Util.number import \* from
Crypto.PublicKey import RSA from Crypto.Cipher import PKCS1\_v1\_5

msg = 'crypto here' p = getPrime(128) q = getPrime(128) n = p\*q e =
getPrime(64) pubkey = RSA.construct((long(n), long(e))) privatekey =
RSA.construct((long(n), long(e), long(d), long(p), long(q))) key =
PKCS1\_v1\_5.new(pubkey) enc = key.encrypt(msg).encode('base64') key =
PKCS1\_v1\_5.new(privatekey) msg = key.decrypt(enc.decode('base64'), e)
\`\`\`

更多的细节请参考readme。

简单练手
========

这里我们以Jarvis OJ - Basic - veryeasyRSA为例进行介绍，题目如下

    p = 3487583947589437589237958723892346254777 q =
    8767867843568934765983476584376578389

    e = 65537

    求d =

    请提交PCTF{d}

直接根据\ :math:`ed\equiv 1 \pmod r` ，其中
:math:`r=\varphi (N)=\varphi (p)\varphi (q)=(p-1)(q-1)`\ ，
可得d。exp在example/Jarvis OJ-Basic-veryeasyRSA目录下，其结果如下

.. code:: shell

    ➜  Jarvis OJ-Basic-veryeasyRSA git:(master) ✗ python exp.py       
    19178568796155560423675975774142829153827883709027717723363077606260717434369
