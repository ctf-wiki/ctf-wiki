#!/usr/bin/env bash
# Push HTML files to gh-pages automatically.

# Fill this out with the correct org/repo
ORG=ctf-wiki
REPO=ctf-wiki
# This probably should match an email for one of your users.
EMAIL=git@40huo.cn

set -e

# Clone Theme for Editing
if [ ! -d "mkdocs-material" ] ; then
  git clone --depth 1 https://github.com/squidfunk/mkdocs-material.git
fi
sed -i "s/name: 'material'/name: null\n  custom_dir: 'mkdocs-material\/material'\n  static_templates:\n    - 404.html/g" mkdocs.yml

# Change Google CDN to loli.net
sed -i 's/fonts.gstatic.com/gstatic.loli.net/g' mkdocs-material/material/base.html
sed -i 's/fonts.googleapis.com/fonts.loli.net/g' mkdocs-material/material/base.html
cp ./static/gitalk.html mkdocs-material/material/partials/integrations/disqus.html

mkdocs build -v
