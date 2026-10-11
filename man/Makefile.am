ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

XMLPAGES = \
	hwdb.xml \
	systemd-hwdb.xml \
	udev.xml \
	udev.conf.xml \
	udevd.xml \
	udevadm.xml

noinst_DATA = \
	$(XMLPAGES)

# make.sh regenerates the man pages from the XML pages with the style sheet custom-man.xsl
EXTRA_DIST = \
	$(XMLPAGES) \
	make.sh \
	custom-man.xsl

MANPAGES = \
	hwdb.7 \
	udev.7 \
	udev.conf.5 \
	udevd.8 \
	udevadm.8

if ENABLE_SYSTEMD_HWDB
MANPAGES += \
	systemd-hwdb.8
endif

dist_man_MANS = \
	$(MANPAGES)

EXTRA_DIST += \
	systemd-hwdb.8

# The further names of the pages, the other refnames of their XML pages, are symbolic links to them, as
# custom-man.xsl writes no ".so" pages for them.
install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(man5dir)
	cd $(DESTDIR)$(man5dir) && rm -f udev.conf.d.5 && $(LN_S) udev.conf.5 udev.conf.d.5

uninstall-hook:
	rm -f $(DESTDIR)$(man5dir)/udev.conf.d.5
