ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	shared \
	libudev \
	udev

# Helper programs
SUBDIRS += \
	ata_id \
	cdrom_id \
	collect \
	scsi_id \
	v4l_id

if ENABLE_MTD_PROBE
SUBDIRS += \
	mtd_probe
endif
