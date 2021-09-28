#!/bin/sh
set -xe
autoreconf -f -i -s

cd man
./make.sh
