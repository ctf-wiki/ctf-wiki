..

分组模式
========

在分组加密中，会将明文消息划分为固定大小的块，每块分别在密钥控制下加密为等长的密文。当然并不是每个消息都会是相应大小的整数倍，所以我们可能需要进行填充。

ECB
^^^

ECB模式全称为电子密码本模式（Electronic codebook）。

加密
----

.. figure:: /crypto/symmetric/figure/ecb_encryption.png
   :alt:  ECB 加密

解密
----

.. figure:: /crypto/symmetric/figure/ecb_decryption.png
   :alt: ECB 解密

缺点
----

-  同样的明文块会被加密成相同的密文块

CBC
^^^

CBC全称为密码分组链接（Cipher-block chaining） 模式。

加密
----

.. figure:: /crypto/symmetric/figure/cbc_encryption.png
   :alt: CBC 加密

解密
----

.. figure:: /crypto/symmetric/figure/cbc_decryption.png
   :alt: CBC 解密

特点
----

-  密文块中的一位变化只会影响当前密文块和下一密文块。
-  加密过程难以并行化

攻击
----

字节反转攻击
~~~~~~~~~~~~

-  iv向量，影响第一个明文分组
-  第n个密文分组，影响第n+1个明文分组

padding oracle attack
~~~~~~~~~~~~~~~~~~~~~

PCBC
^^^^

PCBC的全称为明文密码块链接（Plaintext cipher-block
chaining）。也称为填充密码块链接（Propagating cipher-block chaining）。

加密
----

.. figure:: /crypto/symmetric/figure/pcbc_encryption.png
   :alt: PCBC 加密

解密
----

.. figure:: /crypto/symmetric/figure/pcbc_decryption.png
   :alt: PCBC 解密

特点
----

-  解密过程难以并行化
-  互换邻接的密文块不会对后面的密文块造成影响

CFB
^^^

CFB全称为密文反馈模式（Cipher feedback）。

加密
----

.. figure:: /crypto/symmetric/figure/cfb_encryption.png
   :alt: CFB 加密

解密
----

.. figure:: /crypto/symmetric/figure/cfb_decryption.png
   :alt: CFB 解密

特点
----

-  加解密均不能并行化。

攻击
----

-  HITCONCTF-Quals-2015-Simple-(Crypto-100)
-  ​

OFB
^^^

OFB全称为输出反馈模式（Output feedback）。

加密
----

.. figure:: /crypto/symmetric/figure/ofb_encryption.png
   :alt: OFB 加密

解密
----

.. figure:: /crypto/symmetric/figure/ofb_decryption.png
   :alt: OFB 解密

CTR
^^^

CTR全称为计数器模式（Counter mode）。

加密
----

.. figure:: /crypto/symmetric/figure/ctr_encryption.png
   :alt: CTR 加密

解密
----

.. figure:: /crypto/symmetric/figure/ctr_decryption.png
   :alt: CTR 解密

参考链接

-  `分组加密模式 <https://zh.wikipedia.org/wiki/%E5%88%86%E7%BB%84%E5%AF%86%E7%A0%81%E5%B7%A5%E4%BD%9C%E6%A8%A1%E5%BC%8F>`_
