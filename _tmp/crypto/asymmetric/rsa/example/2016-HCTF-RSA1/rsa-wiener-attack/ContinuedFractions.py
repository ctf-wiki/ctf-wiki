'''
Created on Dec 14, 2011

@author: pablocelayes
    
'''

def rational_to_contfrac(x,y):
    '''
    Converts a rational x/y fraction into
    a list of partial quotients [a0, ..., an]
    '''
    a = x//y
    pquotients = [a]
    while a * y != x:
        x,y = y,x-a*y
        a = x//y
        pquotients.append(a)
    return pquotients

#TODO: efficient method that calculates convergents on-the-go, without doing partial quotients first
def convergents_from_contfrac(frac):
    '''
    computes the list of convergents
    using the list of partial quotients
    '''
    convs = [];
    for i in range(len(frac)):
        convs.append(contfrac_to_rational(frac[0:i]))
    return convs

def contfrac_to_rational (frac):
    '''Converts a finite continued fraction [a0, ..., an]
     to an x/y rational.
     '''
    if len(frac) == 0:
        return (0,1)
    num = frac[-1]
    denom = 1
    for _ in range(-2,-len(frac)-1,-1):
        num, denom = frac[_]*num+denom, num
    return (num,denom)

def test1():
    '''
    Verify that the basic continued-fraction manipulation stuff works.
    '''
    testnums = [(1, 1), (1, 2), (5, 15), (27, 73), (73, 27)]
    for r in testnums:
        (num, denom) = r
        print('rational number:')
        print(r)

        contfrac = rational_to_contfrac (num, denom)
        print('continued fraction:')
        print(contfrac)

        print('convergents:')
        print(convergents_from_contfrac(contfrac))
        print('***********************************')

if __name__ == "__main__":
    test1()
