ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

MANPAGES = \
	udev.7 \
	udevadm.8

XML_FILES = \
	${patsubst %.7,%.xml,${patsubst %.8,%.xml,$(MANPAGES)}}

XSLTPROC_FLAGS = \
	--nonet \
	--stringparam man.output.quietly 1 \
	--stringparam funcsynopsis.style ansi \
	--stringparam man.th.extra1.suppress 1 \
	--stringparam man.authors.section.enabled 0 \
	--stringparam man.copyright.section.enabled 0

man_MANS = \
	$(MANPAGES)

noinst_DATA = \
	$(XML_FILES)

CLEANFILES = \
	$(MANPAGES)

XSLTPROC_PROCESS_MAN = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

%.7: %.xml
	$(XSLTPROC_PROCESS_MAN)

%.8: %.xml
	$(XSLTPROC_PROCESS_MAN)
