from pwn import *
from simon import SIMON

plain = 0x6d564d37426e6e71
cipher = 0xbb5d12ba422834b5


def compare(key):
    key = "SECCON{" + key + "}"
    key = key.encode('hex')
    key = int(key, 16)
    my_simon = SIMON(64, 96, key)
    test = my_simon.encrypt(plain)
    if test == cipher:
        return True
    else:
        return False


def solve():
    visible = string.uppercase + string.lowercase + string.digits + string.punctuation + " "
    key = pwnlib.util.iters.mbruteforce(compare, visible, 4, method="fixed")
    print key


if __name__ == "__main__":
    solve()
