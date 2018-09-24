ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

EXTRA_DIST = \
	64-btrfs.rules.in

dist_udevrules_DATA = \
	50-udev-default.rules \
	60-block.rules \
	60-cdrom_id.rules \
	60-drm.rules \
	60-evdev.rules \
	60-input-id.rules \
	60-persistent-alsa.rules \
	60-persistent-input.rules \
	60-persistent-storage-tape.rules \
	60-persistent-v4l.rules \
	60-sensor.rules \
	60-serial.rules \
	64-btrfs.rules \
	70-joystick.rules \
	70-mouse.rules \
	70-touchpad.rules \
	75-net-description.rules \
	78-sound-card.rules

if !ENABLE_RULE_GENERATOR
dist_udevrules_DATA += \
	80-net-name-slot.rules
endif

if HAVE_BLKID
dist_udevrules_DATA += \
	60-persistent-storage.rules
endif

if HAVE_KMOD
dist_udevrules_DATA += \
	80-drivers.rules
endif

if ENABLE_MTD_PROBE
dist_udevrules_DATA += \
	75-probe_mtd.rules
endif

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(udevconfdir)/rules.d
