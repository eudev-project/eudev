ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

dist_udevhwdb_DATA = \
	20-acpi-vendor.hwdb \
	20-bluetooth-vendor-product.hwdb \
	20-dmi-id.hwdb \
	20-net-ifname.hwdb \
	20-OUI.hwdb \
	20-pci-classes.hwdb \
	20-pci-vendor-model.hwdb \
	20-sdio-classes.hwdb \
	20-sdio-vendor-model.hwdb \
	20-usb-classes.hwdb \
	20-usb-vendor-model.hwdb \
	20-vmbus-class.hwdb \
	60-autosuspend-chromiumos.hwdb \
	60-autosuspend-fingerprint-reader.hwdb \
	60-autosuspend.hwdb \
	60-evdev.hwdb \
	60-input-id.hwdb \
	60-keyboard.hwdb \
	60-seat.hwdb \
	60-sensor.hwdb \
	60-tpm2.hwdb \
	70-analyzers.hwdb \
	70-av-production.hwdb \
	70-cameras.hwdb \
	70-debug-appliance.hwdb \
	70-hardware-wallets.hwdb \
	70-joystick.hwdb \
	70-lights.hwdb \
	70-maker-tools.hwdb \
	70-mouse.hwdb \
	70-pointingstick.hwdb \
	70-pda.hwdb \
	70-software-radio.hwdb \
	70-sound-card.hwdb \
	70-touchpad.hwdb \
	80-ieee1394-unit-function.hwdb

# ------------------------------------------------------------------------------
# The sources and tools of the generated 20-*.hwdb files, and the hwdb checker, from systemd's hwdb.d. They
# are not used by the build, see README.

EXTRA_DIST = \
	README \
	20-acpi-vendor.hwdb.patch \
	acpi-update.py \
	acpi_id_registry.csv \
	dedup-hwdb.py \
	ids_parser.py \
	ma-large.txt \
	ma-medium.txt \
	ma-small.txt \
	parse_hwdb.py \
	pci.ids \
	pnp_id_registry.csv \
	sdio.ids \
	usb.ids

PYTHON3 = python3

# Regenerates the 20-*.hwdb files that are generated from the sources above, in the source directory, as
# tools/update-hwdb.sh of systemd does without downloading the sources first (-n), but without updating
# 20-acpi-vendor.hwdb.patch. The entries of this hand-made patch override registry entries of the same ids,
# so those are dropped.
regenerate-hwdb:
	cd $(srcdir) && \
	$(PYTHON3) ./ids_parser.py && \
	$(PYTHON3) ./acpi-update.py > 20-acpi-vendor.hwdb.base && \
	patch -p0 -o 20-acpi-vendor.hwdb.patched 20-acpi-vendor.hwdb.base < 20-acpi-vendor.hwdb.patch && \
	$(PYTHON3) ./dedup-hwdb.py < 20-acpi-vendor.hwdb.patched > 20-acpi-vendor.hwdb.new && \
	mv 20-acpi-vendor.hwdb.new 20-acpi-vendor.hwdb && \
	rm -f 20-acpi-vendor.hwdb.base 20-acpi-vendor.hwdb.patched

# Checks the hwdb files with parse_hwdb.py, as the parse-hwdb test of systemd does: 20-dmi-id.hwdb,
# 20-net-ifname.hwdb and the 60-*, 70-* and 80-* files. Its grammar does not cover the other 20-*.hwdb files.
# The keycodes are checked only if the evdev module of Python is installed.
parse-hwdb:
	$(PYTHON3) $(srcdir)/parse_hwdb.py

.PHONY: regenerate-hwdb parse-hwdb
