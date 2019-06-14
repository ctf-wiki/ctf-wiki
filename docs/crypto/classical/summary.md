[EN](./summary.md) | [ZH](./summary-zh.md)
# to sum up


## Classical Password Analysis


The questions about classical ciphers in CTF are usually based on ciphertext to obtain plaintext. Therefore, ** ciphertext attack ** is mostly used. The basic analysis ideas are summarized as follows:


1. Determine the password type: according to the prompt, encryption method, ciphertext character set, cipher text display form and other information.
2. Determine the attack method: including direct analysis, brute force attack, statistical analysis and other methods. For special passwords of unknown type, the appropriate attack method should be selected according to their password characteristics.
3. Identify analysis tools: Focus on online password analysis tools and Python scripting tools, supplemented by offline cryptanalysis tools and manual analysis.


The applicable scenarios and examples of the above ciphertext attack methods are as follows:


| Attack Methods | Applicable Scenarios | Examples |
| ---------- | ---------------------------------- | -------------------------------------- |

Direct Analysis Method | The password for the mapping relationship can be determined by the password type | Caesar password, pig password, keyboard password, etc. |
| Brute force attack method | Replacement password or replacement password with small key space | Shift password, fence password, etc. |
| Statistical Analysis | Replacement passwords with large key spaces | Simple replacement passwords, affine passwords, Virginia passwords, etc. |


## Experiment, love in the fence


Description of the topic


&gt; I have been wondering about a question recently. Is QWE not equal to ABC?
>

> -.- .. --.- .-.. .-- - ..-. -.-. --.- --. -. ... --- ---

>

&gt; flag format: CTF{xxx}


First of all, according to the password style, it is Moss code. After decryption, it gets `KIQLWTFCQGNSOO`. It doesn&#39;t look like flag. There are still fences and `QWE in the end. It doesn&#39;t equal ABC`. After both try it, It is found that QWE and then the fence can get the result.


First, the keyboard QWE decrypts and tries to decrypt it to get `IILYOAVNEBSAHR`. Then the fence decrypts to get `ILOVESHIYANBAR`.


## 2017 SECCON Vigenere3d



The procedure is as follows


```python

# Vigenere3d.py

import sys

def _l(idx, s):

    return s[idx:] + s[:idx]

def main(p, k1, k2):

    s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}"

    t = [[_l((i+j) % len(s), s) for j in range(len(s))] for i in range(len(s))]

    i1 = 0

    i2 = 0

    c = ""

    for a in p:

        c += t[s.find(a)][s.find(k1[i1])][s.find(k2[i2])]

i1 = (i1 + 1)% only (k1)
i2 = (i2 + 1)% yen (k2)
    return c

print main(sys.argv[1], sys.argv[2], sys.argv[2][::-1])



$ python Vigenere3d.py SECCON {*************************** **************
POR4dnyTLHBfwbxAAZhe}}ocZR3Cxcftw9

```



**Solution 1**:


First, let’s first analyze the composition of t.
$$

t[i][j]=s[i+j:]+s[:i+j] \\

t[i][k]=s[i+k:]+s[:i+k]

$$



$t[i][j][k]$ is the kth character in $t[i][j]$, $t[i][k][j]$ is $t[i][k] The jth character in $. Whether $i+j+k$ exceeds `len(s)` is always consistent, ie $t[i][j][k]=t[i][k][j]$ .


Therefore, in fact, for the same plaintext, there may be multiple keys to generate the same ciphertext.


However, the above analysis is simply analysis, and the following begins.


It is not difficult to see that each bit of the ciphertext is only related to the corresponding bit of the plaintext, and the space of each bit of the key is the size of s, so we can use the blast to obtain the key. Here, according to the above command line prompt, it can be known that the key length is 14, just the first 7 bytes of the plaintext are known. The recovery key exp is as follows


```python

def get_key(plain, cipher):

    s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}"

    t = [[_l((i + j) % len(s), s) for j in range(len(s))]

         for i in range(len(s))]

    i1 = 0

    i2 = 0

    key = ['*'] * 14

    for i in range(len(plain)):

        for i1 in range(len(s)):

            for i2 in range(len(s)):

                if t[s.find(plain[i])][s.find(s[i1])][s.find(s[i2])] == cipher[

                        i]:

                    key[i] = s[i1]

                    key[13 - i] = s[i2]

    return ''.join(key)

```



The script to restore the plaintext is as follows


```python

def decrypt(cipher, k1, k2):

    s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}"

    t = [[_l((i + j) % len(s), s) for j in range(len(s))]

         for i in range(len(s))]

    i1 = 0

    i2 = 0

    plain = ""

    for a in cipher:

        for i in range(len(s)):

            if t[i][s.find(k1[i1])][s.find(k2[i2])] == a:

                plain += s[i]

                break

i1 = (i1 + 1)% only (k1)
i2 = (i2 + 1)% yen (k2)
    return plain

```



Get the plain text below


```shell

➜  2017_seccon_vigenere3d git:(master) python exp.py

SECCON{Welc0me_to_SECCON_CTF_2017}

```

**Solution 2**


Analysis of this question:


1. Considering that the array access will not cross the boundary under normal program operation, we will make the following convention when discussing: $arr[index] \Leftrightarrow arr[index \% len(arr)]$
2. For the `_l` function defined in the python program, find the following equivalence relationship: $\_l(offset, arr)[index] \Leftrightarrow arr[index + offset]$
3. For the definition of the three-dimensional matrix t in python&#39;s main function, find the following equivalence relation: $t[a][b][c] \Leftrightarrow \_l(a+b, s)[c]$
4. Based on the observation of the second point 3, there is the following equivalence relation: $t[a][b][c] \Leftrightarrow s[a+b+c]$
5. We consider s as an encoding format, namely: encoding process s.find(x), decoding process s[x]. And directly replace the string it refers to by using the number of its encoded result, then the encryption process can be expressed by the following formula:   - $e = f +  k1 +k2$

- where e is ciphertext, f is plaintext, k1 and k2 are keys obtained by the copy method and of the same length as f, and ** addition is vector plus **.


So we only need to calculate the key by calculating `k1+k2` and decrypt it. Decrypt the python script for this question:


```python

# exp2.py

enc_str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}'

dec_dic = {k:v for v,k in enumerate(enc_str)}

encrypt = 'POR4dnyTLHBfwbxAAZhe}}ocZR3Cxcftw9'

flag_bg = 'SECCON{**************************}'



Sim_key = [dec_dic[encrypt[i]]-dec_dic[flag_bg[i]] for i in range(7)] #crack the emulation key
sim_key = sim_key + sim_key[::-1]



Flag_ed = [dec_dic[v]-sim_key[k%14] for k,v in enumerate(encrypt)] #imitation key decryption
flag_ed = ''.join([enc_str[i%len(enc_str)] for i in flag_ed]) # 解码

print(flag_ed)

```



Get the plain text as follows:


```bash

$ python exp2.py

SECCON{Welc0me_to_SECCON_CTF_2017}

```



## The disappearing triple password


Ciphertext
```

or sit kggd sit qkt ygxk ortfzoeqs wqlatzwqssl qfr zvg ortfzoeqs yggzwqssl. fgv oy ngx vqfz so-called hxz zitd or gft soft.piv dgfn lgsxzogfl qkt zitkt? zohl: hstqlt eiqfut is ygkd gy is fxdwtk ngx utz.zit hkgukqddtkl!
```



Use quipquip to decrypt directly.