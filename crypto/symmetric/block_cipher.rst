

分组模式
========

分组加密会将明文消息划分为固定大小的块，每块明文分别在密钥控制下加密为密文。当然并不是每个消息都是相应块大小的整数倍，所以我们可能需要进行填充。

常见填充规则
------------

正如我们之前所说，在分组加密中，明文的长度往往并不满足要求，需要进行 padding，而如何 padding 目前也已经有了不少的规定。

常见的 `填充规则 <https://www.di-mgt.com.au/cryptopad.html>`__ 如下。\ **需要注意的是，即使消息的长度是块大小的整数倍，仍然需要填充。**

一般来说，如果在解密之后发现 Padding 不正确，则往往会抛出异常。我们也因此可以知道 Paddig 是否正确。

Pad with bytes all of the same value as the number of padding bytes (PKCS5 padding)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

举例子如下

::

    DES INPUT BLOCK  = f  o  r  _  _  _  _  _
    (IN HEX)           66 6F 72 05 05 05 05 05
    KEY              = 01 23 45 67 89 AB CD EF
    DES OUTPUT BLOCK = FD 29 85 C9 E8 DF 41 40

Pad with 0x80 followed by zero bytes (OneAndZeroes Padding)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

举例子如下

::

    DES INPUT BLOCK  = f  o  r  _  _  _  _  _
    (IN HEX)           66 6F 72 80 00 00 00 00
    KEY              = 01 23 45 67 89 AB CD EF
    DES OUTPUT BLOCK = BE 62 5D 9F F3 C6 C8 40

这里其实就是和 md5 和 sha1 的 padding 差不多。

Pad with zeroes except make the last byte equal to the number of padding bytes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

举例子如下

::

    DES INPUT BLOCK  = f  o  r  _  _  _  _  _
    (IN HEX)           66 6f 72 00 00 00 00 05
    KEY              = 01 23 45 67 89 AB CD EF
    DES OUTPUT BLOCK = 91 19 2C 64 B5 5C 5D B8

Pad with zero (null) characters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

举例子如下

::

    DES INPUT BLOCK  = f  o  r  _  _  _  _  _
    (IN HEX)           66 6f 72 00 00 00 00 00
    KEY              = 01 23 45 67 89 AB CD EF
    DES OUTPUT BLOCK = 9E 14 FB 96 C5 FE EB 75

Pad with spaces
~~~~~~~~~~~~~~~

举例子如下

::

    DES INPUT BLOCK  = f  o  r  _  _  _  _  _
    (IN HEX)           66 6f 72 20 20 20 20 20
    KEY              = 01 23 45 67 89 AB CD EF
    DES OUTPUT BLOCK = E3 FF EC E5 21 1F 35 25

ECB
---

ECB模式全称为电子密码本模式（Electronic codebook）。

加密
~~~~

|image0|

解密
~~~~

|image1|

缺点
~~~~

-  同样的明文块会被加密成相同的密文块

CBC
---

CBC全称为密码分组链接（Cipher-block chaining） 模式。

.. 加密-1:

加密
~~~~

|image2|

.. 解密-1:

解密
~~~~

|image3|

特点
~~~~

-  密文块中的一位变化只会影响当前密文块和下一密文块。
-  加密过程难以并行化

攻击
~~~~

-  字节反转攻击

   -  IV 向量，影响第一个明文分组
   -  第 n 个密文分组，影响第 n + 1 个明文分组

-  Padding Oracle Attack，具体参见下面介绍。

PCBC
----

PCBC的全称为明文密码块链接（Plaintext cipher-block chaining）。也称为填充密码块链接（Propagating cipher-block chaining）。

.. 加密-2:

加密
~~~~

|image4|

.. 解密-2:

解密
~~~~

|image5|

.. 特点-1:

特点
~~~~

-  解密过程难以并行化
-  互换邻接的密文块不会对后面的密文块造成影响

CFB
---

CFB全称为密文反馈模式（Cipher feedback）。

.. 加密-3:

加密
~~~~

|image6|

.. 解密-3:

解密
~~~~

|image7|

.. 特点-2:

特点
~~~~

-  加解密均不能并行化。

.. 攻击-1:

攻击
~~~~

-  HITCONCTF-Quals-2015-Simple-(Crypto-100)

OFB
---

OFB全称为输出反馈模式（Output feedback）。

.. 加密-4:

加密
~~~~

|image8|

.. 解密-4:

解密
~~~~

|image9|

CTR
---

CTR全称为计数器模式（Counter mode）。

.. 加密-5:

加密
~~~~

|image10|

.. 解密-5:

解密
~~~~

|image11|

Padding Oracle Attack
---------------------

介绍
~~~~

Padding Oracle Attack 攻击一般需要满足以下几个条件

-  加密算法

   -  采用 PKCS5 Padding 的加密算法。 当然，非对称加密中 OAEP 的填充方式也有可能会受到影响。
   -  分组模式为 CBC 模式。

-  攻击者能力

   -  攻击者可以拦截上述加密算法加密的消息。
   -  攻击者可以和 padding oracle（即服务器） 进行交互：客户端向服务器端发送密文，服务器端告知客户端 padding 是否正常。

Padding Oracle Attack 攻击可以达到的效果如下

-  在不清楚 key 和 IV 的前提下解密任意给定的密文。

原理
~~~~

Padding Oracle Attack 攻击的基本原理如下

-  对于很长的消息，可以一块一块解密。
-  对于每一块消息，先解密消息的最后一个字节，然后解密倒数第二个字节，依次类推。

这里我们回顾一下 CBC 的

-  加密

.. math::


   C_i=E_K(P_i \oplus C_{i-1})\\
   C_0=IV

-  解密

.. math::


   P_{i}=D_{K}(C_{i})\oplus C_{i-1}\\ C_{0}=IV

我们主要关注于解密，这里我们并不知道 IV 和 key。这里我们假设密文块的长度为 n 个字节。

假设我们截获了密文 Y，以获取密文 Y 的最后一个字节为例子进行分析。为了获取 Y 的内容，我们首先需要伪造一块密文 F 以便于可以修改 Y 对应明文的最后一个字节。这是因为若我们构造密文 ``F|Y`` ，那么解密 Y
时具体为

.. math::


   P=D_K(Y)\oplus F

所以修改密文 :math:`F_{n}` 可以修改 Y 对应的明文的最后一个字节。下面给出获取 P 最后一个字节的过程

1. i=0，设置 F 的每个字节为\ **随机字节**\ 。
2. 设置 :math:`F_n=i \oplus 0x01`
3. 将 F|Y 发送给服务器，如果 P 的最后一个字节是 i 的话，那么最后的 padding 就是 0x01，不会出现错误。否则，只有 P 的最后 :math:`P_n \oplus i \oplus 0x01` 字节都是 :math:`P_n \oplus i \oplus 0x01`
   才不会报错。\ **而且，需要注意的是 padding 的字节只能是 0 到 n。** 因此，若想要使得在 F 随机地情况下，并且满足padding
   字节大小的约束情况下还不报错\ **概率很小**\ 。所以在服务器端不报错的情况下，我们可以认为我们确实获取了正确的字节。
4. 在出现错误的情况下，i=i+1，跳转到2。

当获取了 P 的最后一个字节后，我们可以继续获取 P 的倒数第二个字节，此时需要设置 :math:`F_n=P_n\oplus 0x02` ，同时设置 :math:`F_{n-1}=i \oplus 0x02` 去枚举 i。

所以，综上所示，Padding Oracle Attack 其实在一定程度上是一种具有很大概率成功的攻击方法。

然而，需要注意的是，往往遇到的一些现实问题并不是标准的 Padding Oracle Attack 模式，我们往往需要进行一些变形。

2017 HITCON Secret Server
~~~~~~~~~~~~~~~~~~~~~~~~~

分析
^^^^

程序中采用的加密是 AES CBC，其中采用的 padding 与 PKCS5 类似

.. code:: python

    def pad(msg):
        pad_length = 16-len(msg)%16
        return msg+chr(pad_length)*pad_length

    def unpad(msg):
        return msg[:-ord(msg[-1])]

但是，在每次 unpad 时并没有进行检测，而是直接进行 unpad。

其中，需要注意的是，每次和用户交互的函数是

-  ``send_msg`` ，接受用户的明文，使用固定的 ``2jpmLoSsOlQrqyqE`` 作为 IV，进行加密，并将加密结果输出。
-  ``recv_msg`` ，接受用户的 IV 和密文，对密文进行解密，并返回。根据返回的结果会有不同的操作

.. code:: python

                msg = recv_msg().strip()
                if msg.startswith('exit-here'):
                    exit(0)
                elif msg.startswith('get-flag'):
                    send_msg(flag)
                elif msg.startswith('get-md5'):
                    send_msg(MD5.new(msg[7:]).digest())
                elif msg.startswith('get-time'):
                    send_msg(str(time.time()))
                elif msg.startswith('get-sha1'):
                    send_msg(SHA.new(msg[8:]).digest())
                elif msg.startswith('get-sha256'):
                    send_msg(SHA256.new(msg[10:]).digest())
                elif msg.startswith('get-hmac'):
                    send_msg(HMAC.new(msg[8:]).digest())
                else:
                    send_msg('command not found')

主要漏洞
^^^^^^^^

这里我们再简单总结一下我们已有的部分

-  加密

   -  加密时的 IV 是固定的而且已知。
   -  ‘Welcome!!’ 加密后的结果。

-  解密

   -  我们可以控制 IV。

首先，既然我们知道 ``Welcome!!`` 加密后的结果，还可以 recv_msg 中的 IV，那么根据解密过程

.. math::


   P_{i}=D_{K}(C_{i})\oplus C_{i-1}\\ C_{0}=IV

如果我们将 ``Welcome!!`` 加密后的结果输入给 recv_msg，那么其得到的结果便是 ``（Welcome!!+'\x07'*7) xor iv_encrypt``\ ，如果我们\ **恰当的控制解密过程中传递的
iv**\ ，那么我们就可以控制解密后的结果。也就是说我们可以执行\ **上述所说的任意命令**\ 。从而，我们也就可以知道 ``flag`` 解密后的结果。

其次，在上面的基础之上，如果我们在任何密文 C 后面添加自定义的 IV 和 Welcome 加密后的结果，作为输入传递给 recv_msg，那么我们便可以控制解密之后的消息的最后一个字节，\ **那么由于 unpad
操作，我们便可以控制解密后的消息的长度减小 0 到 255**\ 。

利用思路
^^^^^^^^

基本利用思路如下

1. 绕过 proof of work
2. 根据执行任意命令的方式获取加密后的 flag。
3. 由于 flag 的开头是 ``hitcon{``\ ，一共有7个字节，所以我们任然可以通过控制 iv 来使得解密后的前 7 个字节为指定字节。这使得我们可以对于解密后的消息执行 ``get-md5`` 命令。而根据 unpad
   操作，我们可以控制解密后的消息恰好在消息的第几个字节处。所以我们可以开始时将控制解密后的消息为 ``hitcon{x``\ ，即只保留\ ``hitcon{``
   后的一个字节。这样便可以获得带一个字节哈希后的加密结果。类似地，我们也可以获得带制定个字节哈希后的加密结果。
4. 这样的话，我们可以在本地逐字节爆破，计算对应
   ``md5``\ ，然后再次利用任意命令执行的方式，控制解密后的明文为任意指定命令，如果控制不成功，那说明该字节不对，需要再次爆破；如果正确，那么就可以直接执行对应的命令。

具体代码如下

.. code:: python

    #coding=utf-8
    from pwn import *
    import base64, time, random, string
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256, MD5
    #context.log_level = 'debug'
    if args['REMOTE']:
        p = remote('52.193.157.19', 9999)
    else:
        p = remote('127.0.0.1', 7777)


    def strxor(str1, str2):
        return ''.join([chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(str1, str2)])


    def pad(msg):
        pad_length = 16 - len(msg) % 16
        return msg + chr(pad_length) * pad_length


    def unpad(msg):
        return msg[:-ord(msg[-1])]  # 去掉pad


    def flipplain(oldplain, newplain, iv):
        """flip oldplain to new plain, return proper iv"""
        return strxor(strxor(oldplain, newplain), iv)


    def bypassproof():
        p.recvuntil('SHA256(XXXX+')
        lastdata = p.recvuntil(')', drop=True)
        p.recvuntil(' == ')
        digest = p.recvuntil('\nGive me XXXX:', drop=True)

        def proof(s):
            return SHA256.new(s + lastdata).hexdigest() == digest

        data = pwnlib.util.iters.mbruteforce(
            proof, string.ascii_letters + string.digits, 4, method='fixed')
        p.sendline(data)
        p.recvuntil('Done!\n')


    iv_encrypt = '2jpmLoSsOlQrqyqE'


    def getmd5enc(i, cipher_flag, cipher_welcome):
        """return encrypt( md5( flag[7:7+i] ) )"""
        ## keep iv[7:] do not change, so decrypt won't change
        new_iv = flipplain("hitcon{".ljust(16, '\x00'), "get-md5".ljust(
            16, '\x00'), iv_encrypt)
        payload = new_iv + cipher_flag
        ## calculate the proper last byte number
        last_byte_iv = flipplain(
            pad("Welcome!!"),
            "a" * 15 + chr(len(cipher_flag) + 16 + 16 - (7 + i + 1)), iv_encrypt)
        payload += last_byte_iv + cipher_welcome
        p.sendline(base64.b64encode(payload))
        return p.recvuntil("\n", drop=True)


    def main():
        bypassproof()

        # result of encrypted Welcome!!
        cipher = p.recvuntil('\n', drop=True)
        cipher_welcome = base64.b64decode(cipher)[16:]
        log.info("cipher welcome is : " + cipher_welcome)

        # execute get-flag
        get_flag_iv = flipplain(pad("Welcome!!"), pad("get-flag"), iv_encrypt)
        payload = base64.b64encode(get_flag_iv + cipher_welcome)
        p.sendline(payload)
        cipher = p.recvuntil('\n', drop=True)
        cipher_flag = base64.b64decode(cipher)[16:]
        flaglen = len(cipher_flag)
        log.info("cipher flag is : " + cipher_flag)

        # get command not found cipher
        p.sendline(base64.b64encode(iv_encrypt + cipher_welcome))
        cipher_notfound = p.recvuntil('\n', drop=True)

        flag = ""
        # brute force for every byte of flag
        for i in range(flaglen - 7):
            md5_indexi = getmd5enc(i, cipher_flag, cipher_welcome)
            md5_indexi = base64.b64decode(md5_indexi)[16:]
            log.info("get encrypt(md5(flag[7:7+i])): " + md5_indexi)
            for guess in range(256):
                # locally compute md5 hash
                guess_md5 = MD5.new(flag + chr(guess)).digest()
                # try to null out the md5 plaintext and execute a command
                payload = flipplain(guess_md5, 'get-time'.ljust(16, '\x01'),
                                    iv_encrypt)
                payload += md5_indexi
                p.sendline(base64.b64encode(payload))
                res = p.recvuntil("\n", drop=True)
                # if we receive the block for 'command not found', the hash was wrong
                if res == cipher_notfound:
                    print 'Guess {} is wrong.'.format(guess)
                # otherwise we correctly guessed the hash and the command was executed
                else:
                    print 'Found!'
                    flag += chr(guess)
                    print 'Flag so far:', flag
                    break


    if __name__ == "__main__":
        main()

最后结果如下

.. code:: shell

    Flag so far: Paddin9_15_ve3y_h4rd__!!}\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10

参考链接
--------

-  `分组加密模式 <https://zh.wikipedia.org/wiki/%E5%88%86%E7%BB%84%E5%AF%86%E7%A0%81%E5%B7%A5%E4%BD%9C%E6%A8%A1%E5%BC%8F>`__
-  https://en.wikipedia.org/wiki/Padding_oracle_attack
-  http://netifera.com/research/poet/PaddingOraclesEverywhereEkoparty2010.pdf
-  https://ctftime.org/writeup/7975

.. |image0| image:: /crypto/symmetric/figure/ecb_encryption.png
.. |image1| image:: /crypto/symmetric/figure/ecb_decryption.png
.. |image2| image:: /crypto/symmetric/figure/cbc_encryption.png
.. |image3| image:: /crypto/symmetric/figure/cbc_decryption.png
.. |image4| image:: /crypto/symmetric/figure/pcbc_encryption.png
.. |image5| image:: /crypto/symmetric/figure/pcbc_decryption.png
.. |image6| image:: /crypto/symmetric/figure/cfb_encryption.png
.. |image7| image:: /crypto/symmetric/figure/cfb_decryption.png
.. |image8| image:: /crypto/symmetric/figure/ofb_encryption.png
.. |image9| image:: /crypto/symmetric/figure/ofb_decryption.png
.. |image10| image:: /crypto/symmetric/figure/ctr_encryption.png
.. |image11| image:: /crypto/symmetric/figure/ctr_decryption.png
