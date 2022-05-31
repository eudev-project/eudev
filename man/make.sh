#/bin/sh

set -e

XSLTPROC="/usr/bin/xsltproc"

XSLTPROC_FLAGS="--nonet \
--xinclude \
--maxdepth 9000 \
--stringparam man.output.quietly 1 \
--stringparam funcsynopsis.style ansi \
--stringparam man.th.extra1.suppress 1 \
--stringparam man.authors.section.enabled 0 \
--stringparam man.copyright.section.enabled 0"

xslt_proc() {
	[ "$V" = 1 ] && echo $XSLTPROC -o $1.$2 $XSLTPROC_FLAGS custom-man.xsl $1.xml
	$XSLTPROC -o $1.$2 $XSLTPROC_FLAGS custom-man.xsl $1.xml
}

xslt_proc udev 7
xslt_proc hwdb 7
xslt_proc udev.conf 5
xslt_proc udevd 8
xslt_proc udevadm 8
