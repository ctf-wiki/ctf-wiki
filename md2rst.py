import os
for f in os.listdir('./'):
    if os.path.isfile(f) and f.endswith('.md'):
        cmd = 'pandoc --from markdown --to rst -s ' + f + ' -o ' + f[:-3] + '.rst'
        os.system(cmd)
