#!/usr/bin/env python3

import sys
import socketserver
import telnetlib
import tempfile
import installer
import base64
import signal
import os

pow_hardness = 2**23

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    if 0 != os.system('python3 pow.py ask {}'.format(pow_hardness)):
        exit(1)
    print("Welcome to SuperSecureRouter Ltd.'s super secure router Telnet interface!")
    public_key = installer.read_public_key(installer.public_key_path)
    print("You can upload a software update here.")
    zipfile = input()
    zipfile = base64.b64decode(zipfile)
    print("Processing your update...")
    with tempfile.NamedTemporaryFile(suffix='.zip') as f:
        f.write(zipfile)
        f.flush()
        try:
            installer.verify_and_install_software_update(f.name, public_key)
            print("Software update was installed successfully.")
        except Exception as e:
            msg = "There was an error installing the update:\n{}".format(e)
            print(msg)
