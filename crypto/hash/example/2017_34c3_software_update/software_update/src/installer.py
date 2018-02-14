#!/usr/bin/python3

import hashlib
import zipfile
import glob
import os
import os.path
import tempfile
import subprocess
import sys
from shutil import copy2, Error, copystat

from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
import Crypto.Hash


timeout = 10
public_key_path = "public_key.der"
signature_filename = "signature.bin"
zip_filename = "sw_update.zip"
size_limit = 1 << 17



def read_public_key(filename):
    with open(filename, "rb") as f:
        return RSA.importKey(f.read())


# copied and adapted from
# https://github.com/python/cpython/blob/3.6/Lib/shutil.py
# (at commit 9bb6fe52742340f6c92f0dda18599a4577a94e18)
# Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
# 2011, 2012, 2013, 2014, 2015, 2016, 2017 Python Software Foundation; All Rights
# Reserved
# 
# Change: added the exist_ok parameter, which is passed on to
# os.makedirs() and all recursive calls. If it is set to True,
# then this function will not fail if copying to an existing directory.
# (The official shutil.copytree does.)
# Also, this version does not do copystat().
# Also, removed docstring.
def copytree(src, dst, symlinks=False, ignore=None, copy_function=copy2,
             ignore_dangling_symlinks=False, exist_ok=False):
    
    names = os.listdir(src)
    if ignore is not None:
        ignored_names = ignore(src, names)
    else:
        ignored_names = set()

    os.makedirs(dst, exist_ok = exist_ok)
    errors = []
    for name in names:
        if name in ignored_names:
            continue
        srcname = os.path.join(src, name)
        dstname = os.path.join(dst, name)
        try:
            if os.path.islink(srcname):
                linkto = os.readlink(srcname)
                if symlinks:
                    # We can't just leave it to `copy_function` because legacy
                    # code with a custom `copy_function` may rely on copytree
                    # doing the right thing.
                    os.symlink(linkto, dstname)
                    copystat(srcname, dstname, follow_symlinks=not symlinks)
                else:
                    # ignore dangling symlink if the flag is on
                    if not os.path.exists(linkto) and ignore_dangling_symlinks:
                        continue
                    # otherwise let the copy occurs. copy2 will raise an error
                    if os.path.isdir(srcname):
                        copytree(srcname, dstname, symlinks, ignore,
                                 copy_function, exist_ok=exist_ok)
                    else:
                        copy_function(srcname, dstname)
            elif os.path.isdir(srcname):
                copytree(srcname, dstname, symlinks, ignore,
                    copy_function, exist_ok = exist_ok
                )
            else:
                # Will raise a SpecialFileError for unsupported file types
                copy_function(srcname, dstname)
        # catch the Error from the recursive copytree so that we can
        # continue with other files
        except Error as err:
            errors.extend(err.args[0])
        except OSError as why:
            errors.append((srcname, dstname, str(why)))
    
    if errors:
        raise Error(errors)
    return dst


def unpack(zip_file_path, unpack_path):
    with zipfile.ZipFile(zip_file_path) as z:
        z.extractall(unpack_path)

def check_signature(path, public_key):
    
    hash_value = compute_hash(path + "/signed_data")
    with open(path + "/" + signature_filename, "rb") as f:
        signature = f.read()
    verifier = PKCS1_PSS.new(public_key)
    return verifier.verify(Crypto.Hash.SHA256.new(hash_value), signature)
    

def xor(str1, str2):
    assert(len(str1) == len(str2))
    result = bytearray((b1 ^ b2 for b1, b2 in zip(str1, str2)))
    return result


def compute_hash(directory):
    """compute a hash of all files contained in <directory>."""
    
    files = glob.glob(directory + "/**", recursive=True)
    files.sort()
    files.remove(directory + "/")
    result = bytearray(hashlib.sha256().digest_size)
    
    for filename in files:
        complete_path = filename
        relative_path = os.path.relpath(filename, directory)
        if os.path.isfile(complete_path):
            with open(complete_path, "rb") as f:
                h = hashlib.sha256(relative_path.encode('ASCII'))
                h.update(b"\0")
                h.update(f.read())
        elif os.path.isdir(complete_path):
            relative_path += "/"
            h = hashlib.sha256(relative_path.encode('ASCII') + b"\0")
        else:
            pass
        
        result = xor(result, h.digest())
    
    return result


def do_install(from_path):
    
    # pre-copy
    p = subprocess.run(
        ['python3', 'signed_data/pre-copy.py'],
        cwd=from_path,
        timeout = timeout,
        check=True
    )
    
    # copy new data
    copytree(from_path + "/signed_data/files", "/",
        symlinks=True, exist_ok=True
    )
    
    # post-copy
    p = subprocess.run(
        ['python3', 'signed_data/post-copy.py'],
        cwd=from_path,
        timeout = timeout,
        check=True
    )


def verify_and_install_software_update(zipfile_path, public_key):
    
    size = os.stat(zipfile_path).st_size
    if size > size_limit:
        raise RuntimeError(
            "zip file of {} bytes is larger than allowed ({})".format(
                size, size_limit
            )
        )
    
    with zipfile.ZipFile(zipfile_path) as f:
        contained_files = f.infolist()
    
    total_size = 0
    for f in contained_files:
        total_size += f.file_size
        if total_size > size_limit:
            raise RuntimeError(
                "uncompressed zip file would be too large.\n" \
                "Allowed size ({}) exceeded at object {}".format(
                    size_limit,
                    f.filename
                )
            )
    
    with tempfile.TemporaryDirectory(prefix = "software_update_") as d:
        unpack(zipfile_path, d)
        valid = check_signature(d, public_key)
        
        if not valid:
            raise RuntimeError("invalid signature")
        else:
            do_install(d)
    

def main(argv):
    
    public_key = read_public_key(public_key_path)
    
    import argparse
    parser = argparse.ArgumentParser(description='Install a software update')
    parser.add_argument('zipfile', nargs='?', default='sw_update.zip',
        help='path to the zip file which contains the update')
    args = parser.parse_args(argv[1:])
    
    try:
        verify_and_install_software_update(args.zipfile, public_key)
        print("Software update installed successfully.")
    except Exception as e:
        print("There was an error installing the update:\n{}".format(e))
        exit(1)

if __name__ == "__main__":
    main(sys.argv)
