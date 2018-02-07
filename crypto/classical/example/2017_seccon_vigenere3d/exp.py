import sys


def _l(idx, s):
    return s[idx:] + s[:idx]


def main(p, k1, k2):
    s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}"
    t = [[_l((i + j) % len(s), s) for j in range(len(s))]
         for i in range(len(s))]
    i1 = 0
    i2 = 0
    c = ""
    for a in p:
        c += t[s.find(a)][s.find(k1[i1])][s.find(k2[i2])]
        i1 = (i1 + 1) % len(k1)
        i2 = (i2 + 1) % len(k2)
    return c


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
        i1 = (i1 + 1) % len(k1)
        i2 = (i2 + 1) % len(k2)
    return plain


plain = 'SECCON{**************************}'
cipher = 'POR4dnyTLHBfwbxAAZhe}}ocZR3Cxcftw9'

key = get_key(plain[:7], cipher[:7])

print decrypt(cipher, key, key[::-1])
