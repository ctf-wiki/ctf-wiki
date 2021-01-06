#! /usr/bin/env bash

set -x
set -e

if [ -f site.zip ]; then
    rm -rf site.zip
fi
zip -r site.zip ./site