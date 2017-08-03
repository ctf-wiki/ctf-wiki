# MMA-CTF-2015: Alicegame

**Category:** Crypto
**Points:** 250
**Solves:** 13
**Description:**

> Decrypt a message.
>
> `nc cry1.chal.mmactf.link 39985`
>
> Hint: [server.py](server.py-192ac80a12223d53a07c4b370966eb39e5cd6a00bcb36e54840756a6ac4e5a77)


## Write-up

離散対数問題を安全性の根拠としているElGamal暗号だが、φ(p)の最大素因数がある程度小さいとPohlig–Hellman algorithm × Baby-step Giant-step algorithmで高速に離散対数を計算できる。

[solver.py](solver.py)

## Other write-ups and resources

* [b01lers](https://b01lers.net/challenges/MMA%20CTF%202015/Alicegame/59/) 
* <https://github.com/pwning/public-writeup/blob/master/mma2015/crypto250-alicegame/writeup.md>
