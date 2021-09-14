ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	$(LIBC_CPPFLAGS) \
	-DUDEV_ROOT_RUN=\"$(rootrundir)\" \
	-include $(top_builddir)/config.h

libudev_shared_la_SOURCES=\
	conf-files.c \
	device-nodes.c \
	dev-setup.c \
	efivars.c \
	factory-reset.c \
	gpt.c \
	fileio.c \
	hashmap.c \
	id128-util.c \
	json-util.c \
	json-writer.c \
	label.c \
	log.c \
	mempool.c \
	mkdir.c \
	mkdir-label.c \
	MurmurHash2.c \
	os-util.c \
	pager.c \
	path-util.c \
	process-util.c \
	random-util.c \
	selinux-util.c \
	siphash24.c \
	smack-util.c \
	socket-util.c \
	strbuf.c \
	strv.c \
	strxcpyx.c  \
	sysctl-util.c \
	terminal-util.c \
	time-util.c \
	util.c \
	utf8.c \
	virt.c

noinst_HEADERS = \
	build.h \
	conf-files.h \
	def.h \
	device-nodes.h \
	dev-setup.h \
	efivars.h \
	factory-reset.h \
	fileio.h \
	formats-util.h \
	gpt.h \
	hashmap.h \
	id128-util.h \
	json-util.h \
	json-writer.h \
	label.h \
	list.h \
	log.h \
	macro.h \
	main-func.h \
	mempool.h \
	missing.h \
	missing_ioprio.h \
	mkdir.h \
	MurmurHash2.h \
	os-util.h \
	pager.h \
	path-util.h \
	process-util.h \
	random-util.h \
	selinux-util.h \
	set.h \
	siphash24.h \
	smack-util.h \
	socket-util.h \
	sparse-endian.h \
	strbuf.h \
	strv.h \
	strxcpyx.h \
	sysctl-util.h \
	terminal-util.h \
	time-util.h \
	util.h \
	utf8.h \
	udev-util.h \
	virt.h \
	unaligned.h

libudev_shared_la_LDFLAGS = \
	$(AM_LDFLAGS)

noinst_LTLIBRARIES = \
	libudev_shared.la
