from fractions import Fraction
from Crypto.PublicKey import RSA
import math
f

def fractionToFloat(fraction):
    '''
    Debug function
    '''
    d = float(fraction)
    return d


def printFractions(fractions):
    '''
    Debug function
    '''
    for fraction in fractions:
        print "%f \t\t= \t\t%s" % (fraction, fraction)


def getContinuedFractions(fraction):
    x = fraction.numerator
    y = fraction.denominator
    if (x % y) == 0:
        return [x / y]
    fractions = getContinuedFractions(Fraction(y, x % y))
    fractions.insert(0, x / y)
    return (fractions)


def getFractionFromContinuedFractions(fractions):
    length = len(fractions)
    if length == 0:
        return (Fraction(0, 1))
    elif length == 1:
        return (Fraction(fractions[0], 1))
    else:
        rest = fractions[1:length]
        f = getFractionFromContinuedFractions(rest)
        return (Fraction(fractions[0] * f.numerator + f.denominator,
                         f.numerator))


def getConvergents(fractions):
    convergents = []
    for i, _ in enumerate(fractions):
        convergents.append(getFractionFromContinuedFractions(fractions[0:i]))
    return convergents


if __name__ == '__main__':
    with open('./public.key') as f:
        key = RSA.importKey(f)
        e = key.e
        N = key.n
        d = "Unknown"

    print("Parameters: ")
    print("e = " + str(e))
    print("N = " + str(N))

    continuedFraction = getContinuedFractions(Fraction(e, N))
    convergents = getConvergents(continuedFraction)

    for frac in convergents:
        de = e * frac.denominator
        if frac.numerator != 0 and (de - 1) % frac.numerator == 0:
            fi = (de - 1) // frac.numerator
            b = N - fi + 1
            delta = b * b - 4 * N
            if delta >= 0:
                x = gmpy math.sqrt(delta)
                if (x % 1 == 0) and (frac.denominator > 1):
                    d = frac.denominator
                    print("Found d = %s" % d)
