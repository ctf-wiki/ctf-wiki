# 综合题目

## 2017 34c3 Software_update

可以看出，程序的大概意思是上传一个 zip 压缩包，然后对 signed_data 目录下的文件进行签名验证。其中，最后验证的手法是大概是将每一个文件进行 sha256 哈希，然后**异或**起来作为输入传递给 rsa 进行签名。如果通过验证的话，就会执行对应的 pre-copy.py 和 post-copy.py 文件。

很自然的想法是我们修改 pre-copy.py 或者 post-copy.py 文件，使其可以读取 flag，然后再次绕过签名即可。主要有两种思路

1. 根据给定的公钥文件获取对应的私钥，进而再修改文件后伪造签名，然后大概看了看公钥文件几乎不可破，所以这一点，基本上可以放弃。
2. 修改对应文件后，利用**异或的特性使得其哈希值仍然与原来相同**，从而绕过签名检测。即使得 signed_data 目录下包含多个文件，使得这些文件的哈希值最后异或起来可以抵消修改 pre-copy.py 或者 post-copy.py文件所造成的哈希值的不同。

这里，我们选择第二种方法，这里我们选择修改 pre-copy.py 文件，具体思路如下

1. 计算 pre-copy.py 的原 hash 值。
2. 修改 pre-copy.py 文件，使其可以读取 flag。与此同时，计算新的 hash 值。将两者异或，求得异或差值 delta。
3. 寻找一系列的文件，使其 hash 值异或起来正好为 delta。

关键的步骤在于第三步，而其实这个文件可以看做是一个线性组合的问题，即寻找若干个 256 维01向量使其异或值为 delta。而 
$$
(F=\{0,1\},F^{256},\oplus ,\cdot)
$$
是一个 256 维的向量空间。如果我们可以求得该向量空间的一个基，那么我们就可以求得该空间中任意指定值的所需要的向量。

我们可以使用 sage 来辅助我们求，如下

```python
# generage the base of <{0,1},F^256,xor,*>
def gen_gf2_256_base():
    v = VectorSpace(GF(2), 256)
    tmphash = compute_file_hash("0.py", "")
    tmphash_bin = hash2bin(tmphash)
    base = [tmphash_bin]
    filelist = ['0.py']
    print base
    s = v.subspace(base)
    dim = s.dimension()
    cnt = 1
    while dim != 256:
        tmpfile = str(cnt) + ".py"
        tmphash = compute_file_hash(tmpfile, "")
        tmphash_bin = hash2bin(tmphash)
        old_dim = dim
        s = v.subspace(base + [tmphash_bin])
        dim = s.dimension()
        if dim > old_dim:
            base += [tmphash_bin]
            filelist.append(tmpfile)
            print("dimension " + str(s.dimension()))
        cnt += 1
        print(cnt)
    m = matrix(GF(2), 256, 256, base)
    m = m.transpose()
    return m, filelist
```

关于更加详细的解答，请参考 `exp.py`。

这里我修改 pre-copy 多输出  `!!!!come here!!!!` 字眼，如下

```shell
➜  software_update git:(master) python3 installer.py now.zip
Preparing to copy data...
!!!!come here!!!!
Software update installed successfully.
```

## 参考文献

- https://sectt.github.io/writeups/34C3CTF/crypto_182_software_update/Readme
- https://github.com/OOTS/34c3ctf/blob/master/software_update/solution/exploit.py



