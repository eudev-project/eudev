#/bin/sh

set -e

XSLTPROC="/usr/bin/xsltproc"

XSLTPROC_FLAGS="--stringparam man.output.quietly 1 \
--stringparam funcsynopsis.style ansi \
--stringparam man.th.extra1.suppress 1 \
--stringparam man.authors.section.enabled 0 \
--stringparam man.copyright.section.enabled 0"

xslt_proc() {
	$XSLTPROC -o $1.$2 $XSLTPROC_FLAGS http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $1.xml
}

xslt_proc udev 7
xslt_proc udev.conf 5
xslt_proc udevd 8
xslt_proc udevadm 8
