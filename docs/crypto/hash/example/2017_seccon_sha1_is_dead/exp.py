from hashlib import sha1
from hashlib import sha256

pdf1 = open('./shattered-1.pdf').read(320)
pdf2 = open('./shattered-2.pdf').read(320)
pdf1 = pdf1.ljust(2017 * 1024 + 1 - 320, "\00")  #padding pdf to 2017Kib + 1
pdf2 = pdf2.ljust(2017 * 1024 + 1 - 320, "\00")
open("upload1", "w").write(pdf1)
open("upload2", "w").write(pdf2)

print sha1(pdf1).hexdigest()
print sha1(pdf2).hexdigest()
print sha256(pdf1).hexdigest()
print sha256(pdf2).hexdigest()
