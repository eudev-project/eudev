ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	shared \
	libudev

PROGRAMS_SUBDIRS = \
	udev

# Helper programs
PROGRAMS_SUBDIRS += \
	ata_id \
	cdrom_id \
	collect \
	dmi_memory_id \
	fido_id \
	scsi_id \
	v4l_id

if ENABLE_MTD_PROBE
PROGRAMS_SUBDIRS += \
	mtd_probe
endif

if ENABLE_PROGRAMS
SUBDIRS += $(PROGRAMS_SUBDIRS)
endif

# the wrappers of glibc's headers, see LIBC_CPPFLAGS in configure.ac, and eudev's copy of the Linux
# header with the input event codes, from which src/udev/Makefile.am generates the key names; like
# the other headers in src/include/uapi/linux/ of systemd, it is copied verbatim from systemd and
# updated on every sync with systemd
EXTRA_DIST = \
	include/glibc/stdio.h \
	include/glibc/stdlib.h \
	include/uapi/linux/input-event-codes.h
