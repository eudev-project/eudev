#!/bin/sh

mkdir -p m4

if type -p gtkdocize > /dev/null; then
	gtkdocize --docdir docs
else
	echo 'EXTRA_DIST =' > docs/gtk-doc.make
	echo 'AC_DEFUN([GTK_DOC_CHECK], [AM_CONDITIONAL([ENABLE_GTK_DOC], [FALSE])])' > m4/gtk-doc.m4
fi

autoreconf -f -i
