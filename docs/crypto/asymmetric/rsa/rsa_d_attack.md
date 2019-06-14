[EN](./rsa_d_attack.md) | [ZH](./rsa_d_attack-zh.md)
## d Leak attack


### Attack principle


First, when d is leaked, we can naturally decrypt all encrypted messages. We can even decompose the modulus N. The basic principle is as follows


We know $ed \equiv 1 \bmod \varphi(n)$, then $\varphi(n) | k=ed-1$. Obviously k is an even number, we can make $k=2^tr$, where r is odd and t is not less than 1. So for any number g that is relative to N, we have $g^k \equiv 1 \bmod n$. Then $z=g^{\frac{k}{2}}$ is the quadratic root of the modulo N. Then we have


$$

z^2 \equiv 1 \bmod p \\

z^2 \equiv 1 \bmod q

$$



Furthermore, we know that the equation has the following four solutions, the first two are


$$

x \ equiv \ PM1 \ N way
$$



The last two are $\pm x$, where x satisfies the following conditions


$$

x \ equiv 1 \ p \\ way
x \ equiv -1 \ q way
$$



Obviously, $z=g^{\frac{k}{2}}$ satisfies the latter condition, and we can calculate $gcd(z-1,N)$ to decompose N.


### Tools


Use the following tools to perform calculations directly


- RsaConverter.exe (https://sourceforge.net/projects/rsaconverter/ , for windows )

- [rsatool.py](https://github.com/ius/rsatool/blob/master/rsatool.py)





### 2017 HITB - hack in the card II



> The second smart card sent to us has been added some countermeasures by that evil company. They also changed the public key(attachments -> publickey.pem). However it seems that they missed something......  

> Can you decrypt the following hex-encoded ciphertext this time?  

> ```

&gt; 016d1d26a470fad51d52e5f3e90075ab77df69d2fb39905fe634ded81d10a5fd10c35e1277035a9efabb66e4d52fd2d1eaa845a93a4e0f1c4a4b70a0509342053728e89e977cfb9920d5150393fe9dcbf86bc63914166546d5ae04d83631594703db59a628de3b945f566bdc5f0ca7bdfa819a0a3d7248286154a6cc5199b99708423d0749d4e67801dff2378561dd3b0f10c8269dbef2630819236e9b0b3d3d8910f7f7afbbed29788e965a732efc05aef3194cd1f1cff97381107f2950c935980e8954f91ed2a653c91015abea2447ee2a3488a49cc9181a3b1d44f198ff9f0141badcae6a9ae45c6c75816836fb5f331c7f2eb784129a142f88b4dc22a0a977
> ```



This question is a question that follows 2017 HITB - hack in the card I. We use `openssl` to view the public key of `publickey.pem` and find that its N is the same as the N of the previous question, and the N of the previous question, e,d is known. Thus, you can directly use the above `rsatool.py` to get p, q, and calculate e from the e of this problem to get the plain text.


## Wiener&#39;s Attack


### Attack conditions


When d is small ($d&lt;\frac{1}{3}N^{\frac{1}{4}}$), an attacker can use **Wiener&#39;s Attack** to get the private key.


### Attack principle


- https://en.wikipedia.org/wiki/Wiener%27s_attack

- https://sagi.io/2016/04/crypto-classics-wieners-rsa-attack/



### Tools


- https://github.com/pablocelayes/rsa-wiener-attack





## Comprehensive example


### 2016 HCTF RSA1



Here we take the RSA 1 - Crypto So Interesting in the 2016 HCTF as an example, [source code link] (https://github.com/Hcamael/ctf-library/tree/master/RSA1).


First, bypass the proof part of the program, and you can bypass it with almost random data.


Second, let&#39;s analyze the specific code part. The program gets the flag according to our token. Here we directly use the token provided in the source code.


```python

	print "This is a RSA Decryption System"

	print "Please enter Your team token: "

	token = raw_input()

	try:

		flag = get_flag(token)

		assert len(flag) == 38

	except:

		print "Token error!"

		m_exit(-1)

```



Next we first know $n=pq$, let&#39;s take a closer look at how this e, d is obtained.


```python

	p=getPrime(2048)

	q=getPrime(2048)

	n = p * q

	e, d = get_ed(p, q)

	print "n: ", hex(n)

print &quot;e:&quot;, hex (e)
```



`get_ed` function is as follows


```python

def get_ed(p, q):

	k = cal_bit(q*p)

phi_n = (p-1) * (q-1)
r = random.randint (10, 99)
	while True:

		u = getPrime(k/4 - r)

		if gcd(u, phi_n) != 1:

			continue

t = invmod (u, phi_n)
e = pi_b (t)
if gcd (e, phi_n) == 1:
			break

d = invmod (e, phi_n)
	return (e, d)

```



It can be seen that the number of bits we get is less than a quarter of the number of bits in n, which is almost the same as Wiener&#39;s Attack. And we calculated u, t, e, d also meet the following conditions


$$

\begin{align*}

out &amp; equals 1 bmod varphi (n)
Others &amp; \ equiv 1 \ bt \\ way
ed &\equiv 1 \bmod \varphi(n)

\end{align*}

$$



According to the conditions given in the title, we already know n, e, bt.


So first we can know e according to the second formula above. At this time, you can use the first formula for Wiener&#39;s Attack to get u. Then we can use the private key index to leak the attack to decompose N to get p, q. Then we can get d.

First we bypassed proof and got N, e. The encrypted flag is as follows


```shell

n:  0x4b4403cd5ac8bdfaa3bbf83decdc97db1fbc7615fd52f67a8acf7588945cd8c3627211ffd3964d979cb1ab3850348a453153710337c6fe3baa15d986c87fca1c97c6d270335b8a7ecae81ae0ebde48aa957e7102ce3e679423f29775eef5935006e8bc4098a52a168e07b75e431a796e3dcd29c98dab6971d3eac5b5b19fb4d2b32f8702ef97d92da547da2e22387f7555531af4327392ef9c82227c5a2479623dde06b525969e9480a39015a3ed57828162ca67e6d41fb7e79e1b25e56f1cff487c1d0e0363dc105512d75c83ad0085b75ede688611d489c1c2ea003c3b2f81722cdb307a3647f2da01fb3ba0918cc1ab88c67e1b6467775fa412de7be0b44f2e19036471b618db1415f6b656701f692c5e841d2f58da7fd2bc33e7c3c55fcb8fd980c9e459a6df44b0ef70b4b1d813a57530446aa054cbfb9d1a86ffb6074b6b7398a83b5f0543b910dcb9f111096b07a98830a3ce6da47cd36b7c1ac1b2104ea60dc198c34f1c50faa5b697f2f195afe8af5d455e8ac7ca6eda669a5a1e3bfbd290a4480376abd1ff21298d529b26a4e614ab24c776a10f5f5d8e8809467a3e81f04cf5d5b23eb4a3412886797cab4b3c5724c077354b2d11d19ae4e301cd2ca743e56456d2a785b650c7e1a727b1bd881ee85c8d109792393cc1a92a66b0bc23b164146548f4e184b10c80ec458b776df10405b65399e32d657bc83e1451

is:
flag:  0x2517d1866acc5b7b802a51d6251673262e9e6b2d0e0e14a87b838c2751dee91e4ea29019b0a7877b849fddf9e08580d810622db538462b529412eba9d0f8a450fe1889021c0bbd12a62ccc3fff4627b1dbdebec3a356a066adc03f7650722a34fe41ea0a247cb480a12286fffc799d66b6631a220b8401f5f50daa12943856b35e59abf8457b2269efea14f1535fb95e56398fd5f3ac153e3ea1afd7b0bb5f02832883da46343404eb44594d04bbd254a9a35749af84eaf4e35ba1c5571d41cab4d58befa79b6745d8ecf93b64dd26056a6d1e82430afbff3dbc08d6c974364b57b30c8a8230c99f0ec3168ac4813c4205d9190481282ae14f7b94400caff3786ed35863b66fefcffbef1ad1652221746a5c8da083987b2b69689cf43e86a05ce4cf059934716c455a6410560e41149fbcf5fcea3c210120f106b8f6269b9a954139350626cf4dcb497ce86264e05565ec6c6581bf28c643bb4fab8677148c8034833cedacb32172b0ff21f363ca07de0fa2882ac896954251277adc0cdd0c3bd5a3f107dbebf5f4d884e43fe9b118bdd51dc80607608670507388ae129a71e0005826c7c82efccf9c86c96777d7d3b9b5cce425e3dcf9aec0643f003c851353e36809b9202ff3b79e8f33d40967c1d36f5d585ac9eba73611152fc6d3cf36fd9a60b4c621858ed1f6d4db86054c27828e22357fa3d7c71559d175ff8e8987df



```



Secondly, use the following method to get Wiener&#39;s Attack to get u, as follows


```python

if __name__ == "__main__":

bt =
e =
    t = gmpy2.invert(e, bt)

    n = 0x4b4403cd5ac8bdfaa3bbf83decdc97db1fbc7615fd52f67a8acf7588945cd8c3627211ffd3964d979cb1ab3850348a453153710337c6fe3baa15d986c87fca1c97c6d270335b8a7ecae81ae0ebde48aa957e7102ce3e679423f29775eef5935006e8bc4098a52a168e07b75e431a796e3dcd29c98dab6971d3eac5b5b19fb4d2b32f8702ef97d92da547da2e22387f7555531af4327392ef9c82227c5a2479623dde06b525969e9480a39015a3ed57828162ca67e6d41fb7e79e1b25e56f1cff487c1d0e0363dc105512d75c83ad0085b75ede688611d489c1c2ea003c3b2f81722cdb307a3647f2da01fb3ba0918cc1ab88c67e1b6467775fa412de7be0b44f2e19036471b618db1415f6b656701f692c5e841d2f58da7fd2bc33e7c3c55fcb8fd980c9e459a6df44b0ef70b4b1d813a57530446aa054cbfb9d1a86ffb6074b6b7398a83b5f0543b910dcb9f111096b07a98830a3ce6da47cd36b7c1ac1b2104ea60dc198c34f1c50faa5b697f2f195afe8af5d455e8ac7ca6eda669a5a1e3bfbd290a4480376abd1ff21298d529b26a4e614ab24c776a10f5f5d8e8809467a3e81f04cf5d5b23eb4a3412886797cab4b3c5724c077354b2d11d19ae4e301cd2ca743e56456d2a785b650c7e1a727b1bd881ee85c8d109792393cc1a92a66b0bc23b164146548f4e184b10c80ec458b776df10405b65399e32d657bc83e1451

    solve(n, t)

```



The solve function is the function of the corresponding Wiener&#39;s Attack.


We got u as follows


```shell

➜ rsa-wiener-attack git: (master) ✗ python RSAwienerHacker.py
Testing Wiener Attack

Hacked!

('hacked_d = ', mpz(404713159471231711408151571380906751680333129144247165378555186876078301457022630947986647887431519481527070603810696638453560506186951324208972060991323925955752760273325044674073649258563488270334557390141102174681693044992933206572452629140703447755138963985034199697200260653L))

-------------------------

Hacked!

('hacked_d = ', mpz(404713159471231711408151571380906751680333129144247165378555186876078301457022630947986647887431519481527070603810696638453560506186951324208972060991323925955752760273325044674073649258563488270334557390141102174681693044992933206572452629140703447755138963985034199697200260653L))

-------------------------

Hacked!

('hacked_d = ', mpz(404713159471231711408151571380906751680333129144247165378555186876078301457022630947986647887431519481527070603810696638453560506186951324208972060991323925955752760273325044674073649258563488270334557390141102174681693044992933206572452629140703447755138963985034199697200260653L))

-------------------------

Hacked!

('hacked_d = ', mpz(404713159471231711408151571380906751680333129144247165378555186876078301457022630947986647887431519481527070603810696638453560506186951324208972060991323925955752760273325044674073649258563488270334557390141102174681693044992933206572452629140703447755138963985034199697200260653L))

-------------------------

Hacked!

('hacked_d = ', mpz(404713159471231711408151571380906751680333129144247165378555186876078301457022630947986647887431519481527070603810696638453560506186951324208972060991323925955752760273325044674073649258563488270334557390141102174681693044992933206572452629140703447755138963985034199697200260653L))



```



Then use RsaConverter and u,t,n to get the corresponding p and q. as follows


```shell

94121F49C0E7A37A60FDE4D13F021675ED91032EB16CB070975A3EECECE8697ED161A27D86BCBC4F45AA6CDC128EB878802E0AD3B95B2961138C8CD04D28471B558CD816279BDCCF8FA1513A444AF364D8FDA8176A4E459B1B939EBEC6BB164F06CDDE9C203C612541E79E8B6C266436AB903209F5C63C8F0DA192F129F0272090CBE1A37E2615EF7DFBB05D8D88B9C964D5A42A7E0D6D0FF344303C4364C894AB7D912065ABC30815A3B8E0232D1B3D7F6B80ED7FE4B71C3477E4D6C2C78D733CF23C694C535DB172D2968483E63CC031DFC5B27792E2235C625EC0CFDE33FD3E53915357772975D264D24A7F31308D72E1BD7656B1C16F58372E7682660381
8220863F1CFDA6EDE52C56B4036485DB53F57A4629F5727EDC4C5637603FE059EB44751FC49EC846C0B8B50966678DFFB1CFEB350EC44B57586A81D35E4887F1722367CE99116092463079A63E3F29D4F4BC416E7728B26248EE8CD2EFEA6925EC6F455DF966CEE13C808BC15CA2A6AAC7FEA69DB7C9EB9786B50EBD437D38B73D44F3687AEB5DF03B6F425CF3171B098AAC6708D534F4D3A9B3D43BAF70316812EF95FC7EBB7E224A7016D7692B52CB0958951BAB4FB5CB1ABB4DAC606F03FA15697CC3E9DF26DE5F6D6EC45A683CD5AAFD58D416969695067795A2CF7899F61669BC7543151AB700A593BF5A1E5C2AFBCE45A08A2A9CC1685FAF1F96B138D1
```



Then we go directly to get d, and then we can recover the plaintext.


```python

    p = 0x94121F49C0E7A37A60FDE4D13F021675ED91032EB16CB070975A3EECECE8697ED161A27D86BCBC4F45AA6CDC128EB878802E0AD3B95B2961138C8CD04D28471B558CD816279BDCCF8FA1513A444AF364D8FDA8176A4E459B1B939EBEC6BB164F06CDDE9C203C612541E79E8B6C266436AB903209F5C63C8F0DA192F129F0272090CBE1A37E2615EF7DFBB05D8D88B9C964D5A42A7E0D6D0FF344303C4364C894AB7D912065ABC30815A3B8E0232D1B3D7F6B80ED7FE4B71C3477E4D6C2C78D733CF23C694C535DB172D2968483E63CC031DFC5B27792E2235C625EC0CFDE33FD3E53915357772975D264D24A7F31308D72E1BD7656B1C16F58372E7682660381

    q = 0x8220863F1CFDA6EDE52C56B4036485DB53F57A4629F5727EDC4C5637603FE059EB44751FC49EC846C0B8B50966678DFFB1CFEB350EC44B57586A81D35E4887F1722367CE99116092463079A63E3F29D4F4BC416E7728B26248EE8CD2EFEA6925EC6F455DF966CEE13C808BC15CA2A6AAC7FEA69DB7C9EB9786B50EBD437D38B73D44F3687AEB5DF03B6F425CF3171B098AAC6708D534F4D3A9B3D43BAF70316812EF95FC7EBB7E224A7016D7692B52CB0958951BAB4FB5CB1ABB4DAC606F03FA15697CC3E9DF26DE5F6D6EC45A683CD5AAFD58D416969695067795A2CF7899F61669BC7543151AB700A593BF5A1E5C2AFBCE45A08A2A9CC1685FAF1F96B138D1

    if p * q == n:

        print 'true'

Phin = (p - 1) * (q - 1)
d = gmpy2.invert (e, phin)
    cipher = 0x2517d1866acc5b7b802a51d6251673262e9e6b2d0e0e14a87b838c2751dee91e4ea29019b0a7877b849fddf9e08580d810622db538462b529412eba9d0f8a450fe1889021c0bbd12a62ccc3fff4627b1dbdebec3a356a066adc03f7650722a34fe41ea0a247cb480a12286fffc799d66b6631a220b8401f5f50daa12943856b35e59abf8457b2269efea14f1535fb95e56398fd5f3ac153e3ea1afd7b0bb5f02832883da46343404eb44594d04bbd254a9a35749af84eaf4e35ba1c5571d41cab4d58befa79b6745d8ecf93b64dd26056a6d1e82430afbff3dbc08d6c974364b57b30c8a8230c99f0ec3168ac4813c4205d9190481282ae14f7b94400caff3786ed35863b66fefcffbef1ad1652221746a5c8da083987b2b69689cf43e86a05ce4cf059934716c455a6410560e41149fbcf5fcea3c210120f106b8f6269b9a954139350626cf4dcb497ce86264e05565ec6c6581bf28c643bb4fab8677148c8034833cedacb32172b0ff21f363ca07de0fa2882ac896954251277adc0cdd0c3bd5a3f107dbebf5f4d884e43fe9b118bdd51dc80607608670507388ae129a71e0005826c7c82efccf9c86c96777d7d3b9b5cce425e3dcf9aec0643f003c851353e36809b9202ff3b79e8f33d40967c1d36f5d585ac9eba73611152fc6d3cf36fd9a60b4c621858ed1f6d4db86054c27828e22357fa3d7c71559d175ff8e8987df

    flag = gmpy2.powmod(cipher, d, n)

    print long_to_bytes(flag)

```



Get flag


```shell

true

hctf{d8e8fca2dc0f896fd7cb4cb0031ba249}

```


