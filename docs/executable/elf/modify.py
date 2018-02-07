import sys
f = open(sys.argv[1], encoding='utf-8')
f1 = open(sys.argv[1][:-3] + '1.md', 'w', encoding='utf-8')
for line in f.readlines():
    if line.startswith('#'):
        line = '#' + line
    f1.writelines(line)
f1.close()
