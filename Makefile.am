ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
DISTCHECK_CONFIGURE_FLAGS=--enable-gtk-doc

SUBDIRS = \
	src \
	rules \
	hwdb \
	docs \
	test

if ENABLE_MANPAGES
SUBDIRS += \
	man
endif

if ENABLE_RULE_GENERATOR
SUBDIRS += \
	rule_generator
endif
