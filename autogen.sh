#!/bin/sh

export WANT_AUTOMAKE=1.13
autoreconf -f -i

cd man
./make.sh
