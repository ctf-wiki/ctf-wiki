[EN](./complex.md) | [ZH](./complex-zh.md)
# 综合


## 2017 34c3 Software_update



As you can see, the general meaning of the program is to upload a zip archive and then verify the signature of the files in the signed_data directory. Among them, the final verification method is to perform a sha256 hash on each file, and then XOR X is sent as input to rsa for signature. If verified, the corresponding pre-copy.py and post-copy.py files will be executed.


The natural idea is that we modify the pre-copy.py or post-copy.py file so that it can read the flag and then bypass the signature again. There are two main ideas


1. According to the given public key file to obtain the corresponding private key, and then modify the file to forge the signature, and then look at the public key file is almost unbreakable, so this can basically give up.
2. After modifying the corresponding file, use the XOR feature to make its hash value the same as the original **, thus bypassing the signature detection. That is, the signed_data directory contains multiple files, so that the hash values of these files are finally XORed to offset the difference in hash values caused by modifying the pre-copy.py or post-copy.py files.


Here, we choose the second method, here we choose to modify the pre-copy.py file, the specific ideas are as follows


1. Calculate the original hash value of pre-copy.py.
2. Modify the pre-copy.py file so that it can read the flag. At the same time, calculate the new hash value. XOR the two and find the difference or delta.
3. Look for a series of files whose X-values are XORed exactly as delta.


The key step is the third step, but in fact this file can be seen as a linear combination problem, that is, looking for several 256-dimensional 01 vectors to make the XOR value delta. and
$$

(F=\{0,1\},F^{256},\oplus ,\cdot)

$$

Is a 256-dimensional vector space. If we can find a basis for the vector space, then we can find the required vector for any given value in the space.


We can use sage to assist us, as follows


```python

# generage the base of <{0,1},F^256,xor,*>

def gen_gf2_256_base():

    v = VectorSpace(GF(2), 256)

    tmphash = compute_file_hash("0.py", "")

tmphash_bin = hash2bin (tmphash)
    base = [tmphash_bin]

    filelist = ['0.py']

    print base

    s = v.subspace(base)

    dim = s.dimension()

    cnt = 1

    while dim != 256:

        tmpfile = str(cnt) + ".py"

        tmphash = compute_file_hash(tmpfile, "")

tmphash_bin = hash2bin (tmphash)
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



For more detailed answers, please refer to `exp.py`.


Here I am modifying the pre-copy multi-output `!!!!come here!!!!` word, as follows


```shell

➜  software_update git:(master) python3 installer.py now.zip

Preparing to copy data...

!!!!come here!!!!

Software update installed successfully.

```



## references


- https://sectt.github.io/writeups/34C3CTF/crypto_182_software_update/Readme

- https://github.com/OOTS/34c3ctf/blob/master/software_update/solution/exploit.py






