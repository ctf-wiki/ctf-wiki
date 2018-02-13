import os
import sys
if len(sys.argv) == 1:
    for f in os.listdir('./'):
        if os.path.isfile(f) and f.endswith('.md'):
            print f
            cmd = 'pandoc --columns=200  --from markdown --to rst -s ' + f + ' -o ' + f[:
                                                                                        -3] + '.rst'
            print cmd
            os.system(cmd)
else:
    cmd = 'pandoc --columns=200  --from markdown --to rst -s ' + sys.argv[1] + ' -o ' + sys.argv[1][:
                                                                                                    -3] + '.rst'
    print cmd
    os.system(cmd)
