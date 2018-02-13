import os
import sys
if len(sys.argv) == 2:
    for f in os.listdir('./'):
        if os.path.isfile(f) and f.endswith('.rst'):
            cmd = 'pandoc --columns=200  --from rst --to markdown -s ' + f + ' -o ' + f[:-4] + '.md'
            os.system(cmd)
else:
    cmd = 'pandoc --columns=200  --from rst --to markdown -s ' + sys.argv[1] + ' -o ' + sys.argv[1][:-3] + '.md'
    os.system(cmd)
