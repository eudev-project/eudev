#!/bin/sh

set -e
  
aclocal && \
autoheader && \
autoconf && \
libtoolize --copy && \
gtkdocize --docdir docs && \
automake --add-missing --copy
