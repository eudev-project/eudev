ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

SUBDIRS = \
	src \
	rules \
	hwdb \
	docs \
	test

if ENABLE_KEYMAP
SUBDIRS += \
	keymaps \
	keymaps-force-release
endif

if ENABLE_MANPAGES
SUBDIRS += \
	man
endif
