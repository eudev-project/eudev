ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	libudev \
	udev \
	gudev \
	test

# Helper programs
SUBDIRS += \
	accelerometer \
	ata_id \
	cdrom_id \
	collect \
	mtd_probe \
	scsi_id \
	v4l_id

if ENABLE_KEYMAP
SUBDIRS += \
        keymap
endif
