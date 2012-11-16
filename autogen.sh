#!/bin/sh

set -e

if type -p gtkdocize > /dev/null; then
    gtkdocize --docdir docs
    gtkdocargs=--enable-gtk-doc
fi
  
aclocal && \
autoheader && \
autoconf && \
libtoolize --copy && \
automake --add-missing --copy
