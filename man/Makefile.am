ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

XMLPAGES = \
	udev.xml \
	udevd.xml \
	udevadm.xml

noinst_DATA = \
	$(XMLPAGES)

EXTRA_DIST = \
	$(XMLPAGES)

MANPAGES = \
	udev.7 \
	udevd.8 \
	udevadm.8

man_MANS = \
	$(MANPAGES)

CLEANFILES = \
	$(MANPAGES)

XSLTPROC_FLAGS += \
	--stringparam man.output.quietly 1 \
	--stringparam funcsynopsis.style ansi \
	--stringparam man.th.extra1.suppress 1 \
	--stringparam man.authors.section.enabled 0 \
	--stringparam man.copyright.section.enabled 0

XSLTPROC_PROCESS_MAN = \
	$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

udev.7: udev.xml
	$(XSLTPROC_PROCESS_MAN)

udevd.8: udevd.xml
	$(XSLTPROC_PROCESS_MAN)

udevadm.8: udevadm.xml
	$(XSLTPROC_PROCESS_MAN)
