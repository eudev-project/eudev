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
	scsi_id \
	v4l_id

if ENABLE_MTD_PROBE
PROGRAMS_SUBDIRS += \
	mtd_probe
endif

if ENABLE_PROGRAMS
SUBDIRS += $(PROGRAMS_SUBDIRS)
endif
