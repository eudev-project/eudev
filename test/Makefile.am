ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

TESTS = \
	udev-test.pl \
	rules-test.sh

check_DATA = \
	test/sys

test/sys:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)tar -C $(top_builddir)/test/ -xJf $(top_srcdir)/test/sys.tar.xz

test-sys-distclean:
	-rm -rf $(top_builddir)/test/sys

DISTCLEAN_LOCAL_HOOKS = \
	test-sys-distclean

EXTRA_DIST = \
	sys.tar.xz \
	udev-test.pl \
	rules-test.sh \
	rule-syntax-check.py
