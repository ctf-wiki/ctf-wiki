import hashlib
import zipfile
import tempfile
import sys
import shutil
from sage.all import *


def unpack(zip_file_path, unpack_path):
    with zipfile.ZipFile(zip_file_path) as z:
        z.extractall(unpack_path)


def xor(str1, str2):
    assert (len(str1) == len(str2))
    result = [b1 ^ b2 for b1, b2 in zip(str1, str2)]
    return result


def compute_file_hash(relative_path, content):
    h = hashlib.sha256(relative_path.encode("ASCII"))
    h.update("\0")
    h.update(content)
    return [ord(c) for c in h.digest()]


# convert hash to bin
def hash2bin(h):
    ans = []
    for v in h:
        for i in range(8):
            if ((v >> i) & 1) == 1:
                ans.append(1)
            else:
                ans.append(0)
    return ans


# generage the base of <{0,1},F^256,xor,*>
def gen_gf2_256_base():
    v = VectorSpace(GF(2), 256)
    tmphash = compute_file_hash("0.py", "")
    tmphash_bin = hash2bin(tmphash)
    base = [tmphash_bin]
    filelist = ['0.py']
    print base
    s = v.subspace(base)
    dim = s.dimension()
    cnt = 1
    while dim != 256:
        tmpfile = str(cnt) + ".py"
        tmphash = compute_file_hash(tmpfile, "")
        tmphash_bin = hash2bin(tmphash)
        old_dim = dim
        s = v.subspace(base + [tmphash_bin])
        dim = s.dimension()
        if dim > old_dim:
            base += [tmphash_bin]
            filelist.append(tmpfile)
            print("dimension " + str(s.dimension()))
        cnt += 1
        print(cnt)
    m = matrix(GF(2), 256, 256, base)
    m = m.transpose()
    return m, filelist


def main(zipfilepath, outzipfile):
    print("unpacking original zip file")
    d = "software_update_"
    unpack(zipfilepath, d)
    print("compute the original hash of pre-copy.py")
    content = open(d + '/signed_data/pre-copy.py').read()
    original_hash = compute_file_hash("pre-copy.py", content)

    print("compute the new hash of the pre-copy.py")
    content = open("target.py").read()
    new_hash = compute_file_hash("pre-copy.py", content)

    print("write target py in original pre-copy.py")
    with open(d + '/signed_data/pre-copy.py', 'w') as f:
        f.write(content)
    diff_hash = xor(original_hash, new_hash)
    print("the diff hash is " + str(diff_hash))

    print("get the base of <{0,1},F^256,xor,*>")
    m, filelist = gen_gf2_256_base()
    diff_hash_bin = hash2bin(diff_hash)
    diff_hash_bin = vector(diff_hash_bin)

    print("generate the answer")
    ans = m.solve_right(diff_hash_bin)

    print("generate the file in the dir d")
    for i, b in enumerate(ans):
        if b == 1:
            with open(d + "/signed_data/" + filelist[i], "w"):
                pass

    shutil.make_archive(outzipfile, "zip", d)


if __name__ == "__main__":
    main(sys.argv[1], "now.zip")
