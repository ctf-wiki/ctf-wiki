[EN](./challenge.md) | [ZH](./challenge-zh.md)
#题


## 2016 Google CTF woodman



The approximate meaning of the program is a guessing game. If you guess a number of times in a row, even if you get the flag, the core code behind the corresponding number is as follows:


```python

class SecurePrng(object):

    def __init__(self):

        # generate seed with 64 bits of entropy

        self.p = 4646704883L

        self.x = random.randint(0, self.p)

        self.y = random.randint(0, self.p)



    def next(self):

        self.x = (2 * self.x + 3) % self.p

        self.y = (3 * self.y + 9) % self.p

        return (self.x ^ self.y)

```



Here we obviously, we guessed that the first two rounds are still relatively easy, after all, the probability is also 0.25. Here, after we guessed the first two rounds, we used Z3 to solve the initial x and y, then we can easily guess the remaining values.


The specific script is as follows, but Z3 seems to be problematic when solving such problems. . .


Here we consider another method, ** sequentially extracting the value of x from the low-bit enumeration to the high-bit bit. The reason for this is that it depends on such observation.


- a + b = c, the value of the ith bit of c is only affected by the a and b bits and lower bits. **Because the i-th bit is operated, only the carry value of the low bit may be received. **
- a - b = c, the value of the ith bit of c is only affected by the a and b bits and lower bits. **Because the i-th bit is operated, there is only a possible borrow from the low bit. **
- a * b = c, the value of the ith bit of c is only affected by the a and b bits and lower bits. Because this can be seen as multiple additions.
- a % b = c, the value of the ith bit of c is only affected by the a and b bits and lower bits. Because this can be seen as multiple subtractions.
- a ^ b = c, the value of the ith bit of c is only affected by the bits a and b. This is obvious.


**Note: Personally feel this technique is very useful. **


In addition, it is not difficult to know that the bit of p is 33 bits. The specific use ideas are as follows


1. First get the value you guessed twice, this probability is 0.25.
2. In turn, enumerate the corresponding bits of x after the first iteration from the low bit to the high bit.
3. Calculate the second value according to the value of the enumeration. Only when the corresponding bit is correct, you can add it to the candidate correct value. It should be noted that due to the modulo, we need to reduce the number of enumerations in the end.
4. In addition, in the final judgment, it is still necessary to ensure that the corresponding value meets certain requirements, because the number of reductions has been enumerated before.


The specific use code is as follows


```python

import
import random

from itertools import product





class SecurePrng(object):

    def __init__(self, x=-1, y=-1):

        # generate seed with 64 bits of entropy

        self.p = 4646704883L  # 33bit

        if x == -1:

            self.x = random.randint(0, self.p)

        else:

            self.x = x

        if y == -1:

            self.y = random.randint(0, self.p)

        else:

self.y = and


    def next(self):

        self.x = (2 * self.x + 3) % self.p

        self.y = (3 * self.y + 9) % self.p

        return (self.x ^ self.y)





def getbiti(num, idx):

    return bin(num)[-idx - 1:]





def main():

    sp = SecurePrng()

    targetx = sp.x

    targety = sp.y

    print "we would like to get x ", targetx

    print "we would like to get y ", targety



    # suppose we have already guess two number

guess1 = sp.next ()
    guess2 = sp.next()



    p = 4646704883



    # newx = tmpx*2+3-kx*p

    for kx, ky in product(range(3), range(4)):

        candidate = [[0]]

        # only 33 bit

        for i in range(33):

            #print 'idx ', i

            new_candidate = []

            for old, bit in product(candidate, range(2)):

                #print old, bit

                oldx = old[0]

                #oldy = old[1]

                tmpx = oldx | ((bit & 1) << i)

                #tmpy = oldy | ((bit / 2) << i)

                tmpy = tmpx ^ guess1

                newx = tmpx * 2 + 3 - kx * p + (1 << 40)

newy = tmpy * 3 + 9 - ky * p + (1 &lt;&lt; 40)
tmp1 = newx ^ newy
                #print "tmpx:    ", bin(tmpx)

                #print "targetx: ", bin(targetx)

                #print "calculate:     ", bin(tmp1 + (1 << 40))

                #print "target guess2: ", bin(guess1 + (1 << 40))

                if getbiti(guess2 + (1 << 40), i) == getbiti(

tmp1 + (1 &lt;&lt; 40), i):
                    if [tmpx] not in new_candidate:

                        #print "got one"

                        #print bin(tmpx)

                        #print bin(targetx)

                        #print bin(tmpy)

                        new_candidate.append([tmpx])

            candidate = new_candidate

#print len (candidate)
            #print candidate

        print "candidate x for kx: ", kx, " ky ", ky

        for item in candidate:

            tmpx = candidate[0][0]

            tmpy = tmpx ^ guess1

            if tmpx >= p or tmpx >= p:

                continue

            mysp = SecurePrng(tmpx, tmpy)

            tmp1 = mysp.next()

            if tmp1 != guess2:

                continue
            print tmpx, tmpy

            print(targetx * 2 + 3) % p, (targety * 3 + 9) % p





if __name__ == "__main__":

    main()

```


