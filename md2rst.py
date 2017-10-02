# -*- coding: utf-8 -*-
# __author__ = '40huo'
import os


def convert(root_dir):
    for dir_path, subpaths, files in os.walk(top=root_dir, topdown=False):
        for file in files:
            if file.endswith('.md') and not file.startswith('index') and not file.startswith('README'):
                file_path = os.path.join(dir_path, file)
                print(file_path)
                os.system('pandoc --from markdown --to rst -s {md} -o {rst}'.format(md=file_path, rst=file_path.replace('.md', '.rst')))


if __name__ == '__main__':
    root_path = os.path.dirname(__file__)
    print(root_path)
    convert(root_path)
