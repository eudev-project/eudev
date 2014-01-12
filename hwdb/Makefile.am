ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

dist_udevhwdb_DATA = \
	20-acpi-vendor.hwdb \
	20-bluetooth-vendor-product.hwdb \
	20-OUI.hwdb \
	20-pci-classes.hwdb \
	20-pci-vendor-model.hwdb \
	20-sdio-classes.hwdb \
	20-sdio-vendor-model.hwdb \
	20-usb-classes.hwdb \
	20-usb-vendor-model.hwdb

if ENABLE_KEYMAP
dist_udevhwdb_DATA += \
	60-keyboard.hwdb
endif
