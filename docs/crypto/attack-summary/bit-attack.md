[EN](./bit-attack.md) | [ZH](./bit-attack-zh.md)
#比特攻


## Overview


Simply put, it is to use the relationship between the bits to attack.


## 2018 Plaid CTF transducipher



The title is as follows


```python

#!/usr/bin/env python3.6

import


BLOCK_SIZE = 64



T = [

    ((2, 1), 1),

    ((5, 0), 0),

    ((3, 4), 0),

    ((1, 5), 1),

    ((0, 3), 1),

    ((4, 2), 0),

]





def block2bin(b, length=BLOCK_SIZE):

    return list(map(int, bin(b)[2:].rjust(length, '0')))





def bin2block(b):

    return int("".join(map(str, b)), 2)





def transduce(b, s=0):

if len (b) == 0:
        return b

    d, t = T[s]

    b0, bp = b[0], b[1:]

    return [b0 ^ t] + transduce(bp, s=d[b0])





def transduceblock(b):

    return bin2block(transduce(block2bin(b)))





def swap(b):

    l = BLOCK_SIZE // 2

    m = (1 << l) - 1

    return (b >> l) | ((b & m) << l)





class Transducipher:



    def __init__(self, k):

self.k = [k]
        for i in range(1, len(T)):

            k = swap(transduceblock(k))

            self.k.append(k)



    def encrypt(self, b):

        for i in range(len(T)):

            b ^= self.k[i]

            b = transduceblock(b)

            b = swap(b)

        return b





if __name__ == "__main__":

    flag = bytes.hex(os.urandom(BLOCK_SIZE // 8))

    k = int(flag, 16)

    C = Transducipher(k)

    print("Your flag is PCTF{%s}" % flag)

    with open("data1.txt", "w") as f:

        for i in range(16):

            pt = int(bytes.hex(os.urandom(BLOCK_SIZE // 8)), 16)

            ct = C.encrypt(pt)

            f.write(str((pt, ct)) + "\n")



```



The topic gave 16 groups of ciphertext pairs.


- Clear text size 8 bytes
- cipher text size 8 bytes
- The key size is also 8 bytes


The key we need to solve is the key.


It can be seen that there are two main operations here.


- swap



```python

def swap(b):

    l = BLOCK_SIZE // 2

    m = (1 << l) - 1

    return (b >> l) | ((b & m) << l)

```



Swaps the upper 32 bits of the given data with the lower 32 bits.


- transduce



```python

T = [

    ((2, 1), 1),

    ((5, 0), 0),

    ((3, 4), 0),

    ((1, 5), 1),

    ((0, 3), 1),

    ((4, 2), 0),

]

def transduce(b, s=0):

if len (b) == 0:
        return b

    d, t = T[s]

    b0, bp = b[0], b[1:]

    return [b0 ^ t] + transduce(bp, s=d[b0])

```



among them,


- b is an array of 01 with an initial time size of 64.
- s is a subscript.


The basic process is as follows

1. Select which element of T to use based on s and divide it into d and t.
2. Divide b into two parts, one containing only the head element and the other containing the other elements.
3. XOR the header element with t as the current header element and continue to convert the rest.


In fact, we can convert this function into an iterative function.


```python

def transduce_iter(b, s=0):

ans = []
    for c in b:

        d, t = T[s]

years + = [ct]
        s = d[c]

return years
```



And since each time the first element of the list is processed, the function is actually reversible, as follows


```python

def invtransduce(b, s=0):

if len (b) == 0:
        return b

    d, t = T[s]

    b0, bp = b[0], b[1:]

    return [b0 ^ t] + transduce(bp, s=d[b0 ^ t])

```



The following is the core flow of the analysis program. The first is to generate the key part. The encryption algorithm generates 6 keys, each time the method is generated.


1. transduce the previous key to get the intermediate value t
2. Swap t
3. Continuous iteration 5 times


```python

    def __init__(self, k):

self.k = [k]
        for i in range(1, len(T)):

            k = swap(transduceblock(k))

            self.k.append(k)

```



The encryption algorithm is as follows, a total of 6 iterations, the basic process


XOR key transduce
2. Exchange


```python

    def encrypt(self, b):

        for i in range(len(T)):

            b ^= self.k[i]

            b = transduceblock(b)

            b = swap(b)

        return b

```



Through the analysis program, it can be known that the encryption algorithm is a block encryption, and the basic information is as follows


- Block size is 8 bytes
- Rounds of 6 rounds
- The basic operations of each round of the encryption algorithm are transduce and swap.
- The extension of the key is also related to transduce and swap.


more specific


1. swap is to swap the upper 32 bits of the 8 bytes with the lower 32 bits.
2. transduce is XORed to a value bit by bit for each bit of 8 bytes. This value is related to T.


Through further analysis, we can find that these two functions are all reversible. That is to say, if we know the final ciphertext, then we can actually shorten the original number of rounds to almost 5 rounds, because the last round of `transduce` and `swap` have no effect.


We can define the following variables


| Name | Meaning |
| --------- | --------------------------- |

| $k_{i,0}$ | The upper 32 bits of the key used in the i-th round |
| $k_{i,1}$ | The lower 32 bits of the key used in the i-th round |
| $d_{i,0}$ | The upper 32 bits of the input used by the i-th wheel |
| $d_{i,1}$ | The lower 32 bits of the input used by the i-th wheel |


Since one of the core operations is swap, only high or low 32 bits are manipulated, so we can consider it in two parts. The simplified definition is as follows


- Transduce is simplified to T, although it conflicts with the source code, but we can temporarily understand it.
- Swap is reduced to S.


Then each round of the ciphertext, the key is as follows


| Number of rounds | Left key | Left ciphertext | Right key | Right ciphertext |
| ---- | ---------------------- | -------------------------------------- | -------------------- | ----------------------------------- |

| 0    | $k_{0,0}$              | $d_{1,0}=T(k_{0,1} \oplus d_{0,1} ,s)$ | $k_{0,1}$            | $d_{1,1}=T(k_{0,0} \oplus d_{0,0})$ |

| 1    | $k_{1,0}=T(k_{0,1},s)$ | $d_{2,0}=T(k_{1,1} \oplus d_{1,1} ,s)$ | $k_{1,1}=T(k_{0,0})$ | $d_{2,1}=T(k_{1,0} \oplus d_{1,0})$ |

| 2    | $k_{2,0}=T(k_{1,1},s)$ | $d_{3,0}=T(k_{2,1} \oplus d_{2,1} ,s)$ | $k_{2,1}=T(k_{1,0})$ | $d_{3,1}=T(k_{2,0} \oplus d_{2,0})$ |

| 3    | $k_{3,0}=T(k_{2,1},s)$ | $d_{4,0}=T(k_{3,1} \oplus d_{3,1} ,s)$ | $k_{3,1}=T(k_{2,0})$ | $d_{4,1}=T(k_{3,0} \oplus d_{3,0})$ |

| 4    | $k_{4,0}=T(k_{3,1},s)$ | $d_{5,0}=T(k_{4,1} \oplus d_{4,1} ,s)$ | $k_{4,1}=T(k_{3,0})$ | $d_{5,1}=T(k_{4,0} \oplus d_{4,0})$ |

| 5    | $k_{5,0}=T(k_{4,1},s)$ | $d_{6,0}=T(k_{5,1} \oplus d_{5,1} ,s)$ | $k_{5,1}=T(k_{4,0})$ | $d_{6,1}=T(k_{5,0} \oplus d_{5,0})$ |



Then, we can enumerate the upper 32 bits of k bit by bit and enumerate the possible s status bits when performing the T operation, so that we can get the high 32-bit key. After performing a bit-by-bit blast, we can get two possible results


```

[2659900894, 2659900895]

```



According to the results on the left, you can get the possible results on the right. The possible results obtained with 2659900894 are as follows:


```

# The first set of ciphertexts may have too many corresponding keys.
# The second group has a total of 6.
[2764038144, 2764038145, 2764038152, 2764038153, 2764038154, 2764038155]

# The third group
[2764038144, 2764038145]

```



Then in fact, we can manually try to encrypt all the ciphertext, if not, just judge the error directly. This can actually be filtered very quickly. Finally, you can find that the key is


```

2659900894|2764038145

```



That is 11624187353095200769. Also got the flag.


Of course, this problem can also use the attack method of the middle encounter, that is, the key used in the 0th round and the key used in the last round are respectively enumerated to make a collision in the third round.


## Reference


- http://blog.rb-tree.xyz/2018/05/07/plaidctf-2018-transducipher/
