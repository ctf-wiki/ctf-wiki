'''
Created on Dec 14, 2011

@author: pablocelayes
'''

import ContinuedFractions, Arithmetic
from Crypto.PublicKey import RSA


def hack_RSA(e, n):
    '''
    Finds d knowing (e,n)
    applying the Wiener continued fraction attack
    '''
    frac = ContinuedFractions.rational_to_contfrac(e, n)
    convergents = ContinuedFractions.convergents_from_contfrac(frac)

    for (k, d) in convergents:
        #check if d is actually the key
        if k != 0 and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = n - phi + 1
            # check if the equation x^2 - s*x + n = 0
            # has integer roots
            discr = s * s - 4 * n
            if (discr >= 0):
                t = Arithmetic.is_perfect_square(discr)
                if t != -1 and (s + t) % 2 == 0:
                    print("Hacked!")
                    return d


if __name__ == "__main__":
    with open('./public.key') as f:
        key = RSA.importKey(f)
        n = key.n
        e = key.e

    print("Testing Wiener Attack")
    times = 5
    while (times > 0):
        hacked_d = hack_RSA(e, n)
        print("hacked_d = ", hacked_d)
        print("-------------------------")
        times -= 1
