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
	udevadm.8

# The pages that describe the default of net.ifnames=: they are made for --with-net-ifnames-default=yes,
# and for no, the build turns them into the pages for no with the sed scripts in net-ifnames-no/, which
# make.sh writes along with them. A script is only run on the page it was made for, which the cksum in
# it tells.
NET_IFNAMES_PAGES = \
	udev.7 \
	udev.conf.5 \
	udevd.8

if NET_IFNAMES_DEFAULT_NO
nodist_man_MANS = \
	net-ifnames-no/udev.7 \
	net-ifnames-no/udev.conf.5 \
	net-ifnames-no/udevd.8

CLEANFILES = \
	$(nodist_man_MANS)
else
MANPAGES += \
	$(NET_IFNAMES_PAGES)
endif

net_ifnames_no_page = \
	$(MKDIR_P) net-ifnames-no; \
	sum=`cksum < $(srcdir)/$(@F)` && \
	if grep -F -e "made for $(@F) with the cksum $$sum" $(srcdir)/$@.sed >/dev/null; then :; else \
		echo "man/$(@F) does not match man/$@.sed: run man/make.sh" >&2; exit 1; \
	fi; \
	$(SED) -f $(srcdir)/$@.sed $(srcdir)/$(@F) > $@.tmp && mv $@.tmp $@

net-ifnames-no/udev.7: udev.7 net-ifnames-no/udev.7.sed
	$(AM_V_GEN)$(net_ifnames_no_page)

net-ifnames-no/udev.conf.5: udev.conf.5 net-ifnames-no/udev.conf.5.sed
	$(AM_V_GEN)$(net_ifnames_no_page)

net-ifnames-no/udevd.8: udevd.8 net-ifnames-no/udevd.8.sed
	$(AM_V_GEN)$(net_ifnames_no_page)

if ENABLE_SYSTEMD_HWDB
MANPAGES += \
	systemd-hwdb.8
endif

dist_man_MANS = \
	$(MANPAGES)

EXTRA_DIST += \
	systemd-hwdb.8 \
	$(NET_IFNAMES_PAGES) \
	net-ifnames-no/udev.7.sed \
	net-ifnames-no/udev.conf.5.sed \
	net-ifnames-no/udevd.8.sed

# The further names of the pages, the other refnames of their XML pages, are symbolic links to them, as
# custom-man.xsl writes no ".so" pages for them.
install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(man5dir)
	cd $(DESTDIR)$(man5dir) && rm -f udev.conf.d.5 && $(LN_S) udev.conf.5 udev.conf.d.5

uninstall-hook:
	rm -f $(DESTDIR)$(man5dir)/udev.conf.d.5
