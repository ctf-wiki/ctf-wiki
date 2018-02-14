#!/usr/bin/env python

# This code is released under MIT license.

CONFIG = {
    (32, 64): (32, 0),
    (48, 72): (36, 0),
    (48, 96): (36, 1),
    (64, 96): (42, 2),
    (64, 128): (44, 3),
    (96, 96): (52, 2),
    (96, 144): (54, 3),
    (128, 128): (68, 2),
    (128, 192): (69, 3),
    (128, 256): (72, 4),
}


def get_const_seq(seq_id):
    assert seq_id in range(5)
    seq = []

    st = [0, 0, 0, 0, 1]
    for i in range(62):
        f = st[2] ^ st[4]
        # LFSRs not in "the usual way"
        if seq_id in (0, 2):
            st[3] ^= st[4]
        elif seq_id in (1, 3):
            st[1] ^= st[0]
        res = st.pop()
        st.insert(0, f)
        if seq_id >= 2:
            res ^= i % 2
        seq.append(res)

    return tuple(seq)


class SIMON:
    """
    one of the two lightweight block ciphers designed by NSA
    this one is optimized for hardware implementation
    """
    def __init__(self, block_size, key_size, master_key=None):
        assert (block_size, key_size) in CONFIG
        self.block_size = block_size
        self.key_size = key_size
        self.__num_rounds, seq_id = CONFIG[(block_size, key_size)]
        self.__const_seq = get_const_seq(seq_id)
        assert len(self.__const_seq) == 62
        self.__dim = block_size / 2
        self.__mod = 1 << self.__dim
        if master_key is not None:
            self.change_key(master_key)

    def __lshift(self, x, i=1):
        return ((x << i) % self.__mod) | (x >> (self.__dim - i))

    def __rshift(self, x, i=1):
        return ((x << (self.__dim - i)) % self.__mod) | (x >> i)

    def change_key(self, master_key):
        assert 0 <= master_key < (1 << self.key_size)
        c = (1 << self.__dim) - 4
        m = self.key_size / self.__dim
        self.__round_key = []
        for i in range(m):
            self.__round_key.append(master_key % self.__mod)
            master_key >>= self.__dim
        for i in range(m, self.__num_rounds):
            k = self.__rshift(self.__round_key[-1], 3)
            if m == 4:
                k ^= self.__round_key[-3]
            k ^= self.__rshift(k) ^ self.__round_key[-m]
            k ^= c ^ self.__const_seq[(i - m) % 62]
            self.__round_key.append(k)

    def __feistel_round(self, l, r, k):
        f = (self.__lshift(l) & self.__lshift(l, 8)) ^ self.__lshift(l, 2)
        return r ^ f ^ k, l

    def encrypt(self, plaintext):
        assert 0 <= plaintext < (1 << self.block_size)
        l = plaintext >> self.__dim
        r = plaintext % self.__mod
        for i in range(self.__num_rounds):
            l, r = self.__feistel_round(l, r, self.__round_key[i])
        ciphertext = (l << self.__dim) | r
        assert 0 <= ciphertext < (1 << self.block_size)
        return ciphertext

    def decrypt(self, ciphertext):
        assert 0 <= ciphertext < (1 << self.block_size)
        l = ciphertext >> self.__dim
        r = ciphertext % self.__mod
        for i in range(self.__num_rounds - 1, -1, -1):
            r, l = self.__feistel_round(r, l, self.__round_key[i])
        plaintext = (l << self.__dim) | r
        assert 0 <= plaintext < (1 << self.block_size)
        return plaintext


if __name__ == '__main__':
    const_seq = (
        (1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0,
         0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1,
         0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0),
        (1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0,
         0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1,
         1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0),
        (1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0,
         1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0,
         0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1),
        (1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0,
         1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0,
         1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1),
        (1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0,
         1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0,
         1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1),
    )
    for i in range(len(const_seq)):
        assert const_seq[i] == get_const_seq(i)

    test_vectors = (
        # block_size, key_size, key, plaintext, ciphertext
        (32, 64,
            0x1918111009080100,
            0x65656877,
            0xc69be9bb),
        (48, 72,
            0x1211100a0908020100,
            0x6120676e696c,
            0xdae5ac292cac),
        (48, 96,
            0x1a19181211100a0908020100,
            0x72696320646e,
            0x6e06a5acf156),
        (64, 96,
            0x131211100b0a090803020100,
            0x6f7220676e696c63,
            0x5ca2e27f111a8fc8),
        (64, 128,
            0x1b1a1918131211100b0a090803020100,
            0x656b696c20646e75,
            0x44c8fc20b9dfa07a),
        (96, 96,
            0x0d0c0b0a0908050403020100,
            0x2072616c6c69702065687420,
            0x602807a462b469063d8ff082),
        (96, 144,
            0x1514131211100d0c0b0a0908050403020100,
            0x74616874207473756420666f,
            0xecad1c6c451e3f59c5db1ae9),
        (128, 128,
            0x0f0e0d0c0b0a09080706050403020100,
            0x63736564207372656c6c657661727420,
            0x49681b1e1e54fe3f65aa832af84e0bbc),
        (128, 192,
            0x17161514131211100f0e0d0c0b0a09080706050403020100,
            0x206572656874206e6568772065626972,
            0xc4ac61effcdc0d4f6c9c8d6e2597b85b),
        (128, 256,
            0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100,
            0x74206e69206d6f6f6d69732061207369,
            0x8d2b5579afc8a3a03bf72a87efe7b868)
    )

    for bsize, ksize, key, plain, cipher in test_vectors:
        my_simon = SIMON(bsize, ksize, key)
        encrypted = my_simon.encrypt(plain)
        assert encrypted == cipher
        for i in range(1000):
            encrypted = my_simon.encrypt(encrypted)
        for i in range(1000):
            encrypted = my_simon.decrypt(encrypted)
        decrypted = my_simon.decrypt(encrypted)
        assert decrypted == plain

    print 'All tests passed'
