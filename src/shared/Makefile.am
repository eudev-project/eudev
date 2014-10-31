ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h

libudev_shared_la_SOURCES=\
	cgroup-util.c \
	conf-files.c \
	device-nodes.c \
	dev-setup.c \
	exit-status.c \
	fileio.c \
	hashmap.c \
	label.c \
	log.c \
	mempool.c \
	mkdir.c \
	mkdir-label.c \
	MurmurHash2.c \
	path-util.c \
	selinux-util.c \
	siphash24.c \
	smack-util.c \
	strbuf.c \
	strv.c \
	strxcpyx.c  \
	time-util.c \
	util.c \
	utf8.c \
	virt.c

noinst_HEADERS = \
	cgroup-util.h \
	conf-files.h \
	def.h \
	device-nodes.h \
	dev-setup.h \
	exit-status.h \
	fileio.h \
	hashmap.h \
	ioprio.h \
	label.h \
	list.h \
	log.h \
	macro.h \
	mempool.h \
	missing.h \
	mkdir.h \
	MurmurHash2.h \
	path-util.h \
	selinux-util.h \
	set.h \
	siphash24.h \
	smack-util.h \
	socket-util.h \
	sparse-endian.h \
	strbuf.h \
	strv.h \
	strxcpyx.h \
	time-util.h \
	util.h \
	utf8.h \
	udev-util.h \
	virt.h

libudev_shared_la_LDFLAGS = \
	$(AM_LDFLAGS)

noinst_LTLIBRARIES = \
	libudev_shared.la
