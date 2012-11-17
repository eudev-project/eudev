#!/bin/sh

type -p gtkdocize > /dev/null && gtkdocize --docdir docs

autoreconf -f -i
