import os
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
            self.y = y

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
    guess1 = sp.next()
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
                newy = tmpy * 3 + 9 - ky * p + (1 << 40)
                tmp1 = newx ^ newy
                #print "tmpx:    ", bin(tmpx)
                #print "targetx: ", bin(targetx)
                #print "calculate:     ", bin(tmp1 + (1 << 40))
                #print "target guess2: ", bin(guess1 + (1 << 40))
                if getbiti(guess2 + (1 << 40), i) == getbiti(
                        tmp1 + (1 << 40), i):
                    if [tmpx] not in new_candidate:
                        #print "got one"
                        #print bin(tmpx)
                        #print bin(targetx)
                        #print bin(tmpy)
                        new_candidate.append([tmpx])
            candidate = new_candidate
            #print len(candidate)
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
