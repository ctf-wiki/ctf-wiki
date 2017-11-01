import sys
f = open(sys.argv[1])
f1 = open(sys.argv[1][:-3] + '1.md', 'w')
for line in f.readlines():
    if line.startswith('#'):
        line = '#' + line
    f1.writelines(line)
f1.close()
