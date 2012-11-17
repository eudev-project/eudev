ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

rootprefix=@rootprefix@
udevlibexecdir=$(rootprefix)/lib/udev

udevlibexec_PROGRAMS = \
	keymap

keymap_SOURCES = \
	keymap.c

keymap_CPPFLAGS = \
	$(AM_CPPFLAGS) -I keymap

nodist_keymap_SOURCES = \
	keys-from-name.h \
	keys-to-name.h

BUILT_SOURCES = \
	$(nodist_keymap_SOURCES)

dist_doc_DATA = \
	README.keymap.txt

dist_udevhome_SCRIPTS = \
	findkeyboards \
	keyboard-force-release.sh

TESTS = \
	check-keymaps.sh

CLEANFILES += \
	keys.txt \
	keys-from-name.gperf \
	keyboard-force-release.sh

keys.txt: Makefile
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include linux/input.h - < /dev/null | $(AWK) '/^#define[ \t]+KEY_[^ ]+[ \t]+[0-9]/ { if ($$2 != "KEY_MAX") { print $$2 } }' | sed 's/^KEY_COFFEE$$/KEY_SCREENLOCK/' > $@

keys-from-name.gperf: keys.txt Makefile
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct key { const char* name; unsigned short id; };"; print "%null-strings"; print "%%";} { print $$1 ", " $$1 }' < $< > $@

keys-from-name.h: keys-from-name.gperf Makefile
	$(AM_V_GEN)$(GPERF) -L ANSI-C -t --ignore-case -N lookup_key -H hash_key_name -p -C < $< > $@

keys-to-name.h: keys.txt Makefile
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "const char* const key_names[KEY_CNT] = { "} { print "[" $$1 "] = \"" $$1 "\"," } END{print "};"}' < $< > $@
endif

EXTRA_DIST += \
	check-keymaps.sh \
	keyboard-force-release.sh.in
