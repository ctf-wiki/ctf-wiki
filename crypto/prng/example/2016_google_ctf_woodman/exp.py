import os
import random
from z3 import *


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


def main():
    sp = SecurePrng()
    print "we would like to get x ", sp.x
    print "we would like to get y ", sp.y

    # suppose we have already guess two number
    guess1 = sp.next()
    guess2 = sp.next()

    s = Solver()

    p = 4646704883
    x = BitVec("x", 35)
    y = BitVec("y", 35)
    s.add(x < p)
    s.add(y < p)
    s.add(guess1 == (((2 * x + 3) % p) ^ ((3 * y + 9) % p)))
    s.add(guess2 == (((4 * x + 9) % p) ^ ((9 * y + 36) % p)))
    print s
    while s.check() == sat:
        ans = s.model()
        print ans
        getx = int(str(ans[x]))
        gety = int(str(ans[y]))
        s.add(Or(x != getx, y != gety))
        mysp = SecurePrng(getx, gety)
        if mysp.next() != guess1 and mysp.next() != guess2:
            continue
        if getx >= p and gety >= p:
            continue
        print "-------------"
        print "we get x: ", getx
        print "we get y: ", gety


if __name__ == "__main__":
    main()
