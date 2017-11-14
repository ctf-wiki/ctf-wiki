#!/usr/bin/env bash
# Push HTML files to gh-pages automatically.

# Fill this out with the correct org/repo
ORG=ctf-wiki
REPO=ctf-wiki
# This probably should match an email for one of your users.
EMAIL=git@40huo.cn

set -e

# Clone the gh-pages branch outside of the repo and cd into it.
cd ..
git clone -b gh-pages "https://$GH_TOKEN@github.com/$ORG/$REPO.git" gh-pages
cd gh-pages

# Update git configuration so I can push.
if [ "$1" != "dry" ]; then
    # Update git config.
    git config user.name "Travis Builder"
    git config user.email "$EMAIL"
fi

# Copy in the HTML.  You may want to change this with your documentation path.
rm -rf * .*
cp -R ../$REPO/_build/html/* ./

# Add and commit changes.
git add -A .
git commit -m "[ci skip] Autodoc commit for $COMMIT."
if [ "$1" != "dry" ]; then
    # -q is very important, otherwise you leak your GH_TOKEN
    git push -q origin gh-pages
fi