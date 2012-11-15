#!/bin/sh

set -e
  
aclocal && \
autoheader && \
autoconf && \
libtoolize --copy && \
automake --add-missing --copy
