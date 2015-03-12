ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

dist_udevrules_DATA = \
	42-usb-hid-pm.rules \
	50-udev-default.rules \
	60-cdrom_id.rules \
	60-block.rules \
	60-drm.rules \
	60-keyboard.rules \
	60-persistent-alsa.rules \
	60-persistent-input.rules \
	60-persistent-serial.rules \
	60-persistent-storage-tape.rules \
	60-persistent-v4l.rules \
	61-accelerometer.rules \
	64-btrfs.rules \
	70-mouse.rules \
	70-touchpad.rules \
	75-net-description.rules \
	75-probe_mtd.rules \
	75-tty-description.rules \
	78-sound-card.rules \
	80-net-name-slot.rules \
	95-udev-late.rules

if HAVE_BLKID
dist_udevrules_DATA += \
	60-persistent-storage.rules
endif

if HAVE_KMOD
dist_udevrules_DATA += \
	80-drivers.rules
endif

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(udevconfdir)/rules.d
