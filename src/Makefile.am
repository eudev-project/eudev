ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	libudev \
	udev

# Helper programs
SUBDIRS += \
	accelerometer \
	ata_id \
	cdrom_id \
	collect \
	mtd_probe \
	scsi_id \
	v4l_id

if ENABLE_GUDEV
SUBDIRS += \
	gudev
endif

if ENABLE_KEYMAP
SUBDIRS += \
        keymap
endif

if ENABLE_LEGACYLIB
SUBDIRS += \
	libudev-legacy
endif
