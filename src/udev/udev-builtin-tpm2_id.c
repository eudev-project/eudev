/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "udev.h"
#include "unaligned.h"

/* Instead of going through the TSS2 libraries like systemd, the TPM2_GetCapability() command is sent
 * directly to the kernel's TPM character device. The constants are from the TCG TPM 2.0 Library
 * specification, part 2 (structures). */
#define TPM2_ST_NO_SESSIONS             UINT16_C(0x8001)
#define TPM2_CC_GET_CAPABILITY          UINT32_C(0x0000017A)
#define TPM2_CAP_TPM_PROPERTIES         UINT32_C(0x00000006)
#define TPM2_RC_SUCCESS                 UINT32_C(0x000)
#define TPM2_RC_FMT1                    UINT32_C(0x080)
#define TPM2_RC_FMT1_ERROR_MASK         UINT32_C(0x03F) /* format one codes carry the parameter number in the upper bits */
#define TPM2_RC_VALUE                   UINT32_C(0x084)

#define TPM2_PT_FAMILY_INDICATOR        UINT32_C(0x100)
#define TPM2_PT_LEVEL                   UINT32_C(0x101)
#define TPM2_PT_REVISION                UINT32_C(0x102)
#define TPM2_PT_DAY_OF_YEAR             UINT32_C(0x103)
#define TPM2_PT_YEAR                    UINT32_C(0x104)
#define TPM2_PT_MANUFACTURER            UINT32_C(0x105)
#define TPM2_PT_VENDOR_STRING_1         UINT32_C(0x106)
#define TPM2_PT_VENDOR_STRING_2         UINT32_C(0x107)
#define TPM2_PT_VENDOR_STRING_3         UINT32_C(0x108)
#define TPM2_PT_VENDOR_STRING_4         UINT32_C(0x109)
#define TPM2_PT_VENDOR_TPM_TYPE         UINT32_C(0x10A)
#define TPM2_PT_FIRMWARE_VERSION_1      UINT32_C(0x10B)
#define TPM2_PT_FIRMWARE_VERSION_2      UINT32_C(0x10C)

#define TPM2_HEADER_SIZE                10
#define TPM2_RESPONSE_MAX               4096

typedef struct Tpm2VendorInfo {
        uint32_t level;
        uint32_t revision_major;
        uint32_t revision_minor;
        uint32_t day_of_year;
        uint32_t year;
        uint32_t vendor_tpm_type;
        uint16_t firmware_version_major;
        uint16_t firmware_version_minor;
        uint32_t firmware_version2;
        char family_indicator[4+1];
        char manufacturer[4+1];
        char vendor_string[4*4+1];
} Tpm2VendorInfo;

static int tpm2_vendor_info_to_modalias(const Tpm2VendorInfo *info, char **ret) {
        char *m;

        assert(info);
        assert(ret);

        /* Closely inspired by kernel modalias strings, this distills information from the TPM vendor data
         * into a string suitable for matching hwdb */

        if (asprintf(&m,
                     "fi%s:"
                     "lv%" PRIu32 ":"
                     "rv%" PRIu32 ".%" PRIu32 ":"
                     "sy%" PRIu32 ":"
                     "sd%" PRIu32 ":"
                     "mf%s:"
                     "vs%s:"
                     "ty%" PRIx32 ":"
                     "fw%" PRIu16 ".%" PRIu16 ".%" PRIu32 ":",
                     info->family_indicator,
                     info->level,
                     info->revision_major,
                     info->revision_minor,
                     info->year,
                     info->day_of_year,
                     info->manufacturer,
                     info->vendor_string,
                     info->vendor_tpm_type,
                     info->firmware_version_major,
                     info->firmware_version_minor,
                     info->firmware_version2) < 0)
                return -ENOMEM;

        *ret = m;
        return 0;
}

static char *mangle_vendor_chars(char *c, size_t n) {
        char *end = c, *x;

        assert(c || n == 0);

        /* Suppress all control characters, whitespace and non-ASCII bytes */
        for (x = c; x < c + n; x++) {
                if (!IN_SET(*x, ' ', 0))
                        end = x + 1;

                if ((unsigned char) *x <= (unsigned char) ' ' ||
                    (unsigned char) *x >= 127)
                        *x = '_';
        }

        /* Drop trailing spaces and NUL bytes */
        *end = 0;
        return c;
}

/* Sends TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, property, count) and returns the TPML_TAGGED_TPM_PROPERTY
 * list from the response in ret_list (pointing into buf) with ret_count entries. */
static int tpm2_get_capability_properties(
                int fd,
                uint32_t property,
                uint32_t count,
                uint8_t buf[static TPM2_RESPONSE_MAX],
                const uint8_t **ret_list,
                uint32_t *ret_count) {

        uint8_t cmd[TPM2_HEADER_SIZE + 12];
        uint32_t size, rc, n;
        ssize_t l;

        assert(fd >= 0);
        assert(ret_list);
        assert(ret_count);

        unaligned_write_be16(cmd + 0, TPM2_ST_NO_SESSIONS);
        unaligned_write_be32(cmd + 2, sizeof(cmd));
        unaligned_write_be32(cmd + 6, TPM2_CC_GET_CAPABILITY);
        unaligned_write_be32(cmd + 10, TPM2_CAP_TPM_PROPERTIES);
        unaligned_write_be32(cmd + 14, property);
        unaligned_write_be32(cmd + 18, count);

        log_debug("Getting TPM2 capability 0x%04" PRIx32 " property 0x%04" PRIx32 " count %" PRIu32 ".",
                  TPM2_CAP_TPM_PROPERTIES, property, count);

        l = write(fd, cmd, sizeof(cmd));
        if (l < 0)
                return log_debug_errno(errno, "Failed to send TPM2 command: %m");
        if ((size_t) l != sizeof(cmd))
                return log_debug_errno(EIO, "Short write while sending TPM2 command.");

        l = read(fd, buf, TPM2_RESPONSE_MAX);
        if (l < 0)
                return log_debug_errno(errno, "Failed to read TPM2 response: %m");
        if (l < TPM2_HEADER_SIZE)
                return log_debug_errno(EBADMSG, "TPM2 response too short.");

        size = unaligned_read_be32(buf + 2);
        if (size != (size_t) l)
                return log_debug_errno(EBADMSG, "TPM2 response size field does not match response length.");

        rc = unaligned_read_be32(buf + 6);
        if ((rc & TPM2_RC_FMT1) && (rc & TPM2_RC_FMT1_ERROR_MASK) == (TPM2_RC_VALUE & TPM2_RC_FMT1_ERROR_MASK))
                return log_debug_errno(ENXIO, "Requested TPM2 capability 0x%04" PRIx32 " property 0x%04" PRIx32 " apparently doesn't exist: 0x%" PRIx32,
                                       TPM2_CAP_TPM_PROPERTIES, property, rc);
        if (rc != TPM2_RC_SUCCESS)
                return log_debug_errno(ENOTRECOVERABLE, "Failed to get TPM2 capability 0x%04" PRIx32 " property 0x%04" PRIx32 ": TPM2 error 0x%" PRIx32,
                                       TPM2_CAP_TPM_PROPERTIES, property, rc);

        /* TPMI_YES_NO moreData, TPM_CAP capability, UINT32 count */
        if (size < TPM2_HEADER_SIZE + 1 + 4 + 4)
                return log_debug_errno(EBADMSG, "TPM2 response too short.");

        if (unaligned_read_be32(buf + TPM2_HEADER_SIZE + 1) != TPM2_CAP_TPM_PROPERTIES)
                return log_debug_errno(ENOTRECOVERABLE, "TPM provided wrong capability: 0x%04" PRIx32 " instead of 0x%04" PRIx32 ".",
                                       unaligned_read_be32(buf + TPM2_HEADER_SIZE + 1), TPM2_CAP_TPM_PROPERTIES);

        n = unaligned_read_be32(buf + TPM2_HEADER_SIZE + 5);
        if (n > (size - (TPM2_HEADER_SIZE + 9)) / 8)
                return log_debug_errno(EBADMSG, "TPM2 response too short for %" PRIu32 " properties.", n);

        *ret_list = buf + TPM2_HEADER_SIZE + 9;
        *ret_count = n;
        return 0;
}

static int tpm2_get_vendor_info(int fd, Tpm2VendorInfo *ret) {
        uint8_t buf[TPM2_RESPONSE_MAX];
        Tpm2VendorInfo info = {};
        const uint8_t *list = NULL;
        uint32_t n = 0, i;
        int r;

        assert(fd >= 0);
        assert(ret);

        r = tpm2_get_capability_properties(
                        fd,
                        TPM2_PT_FAMILY_INDICATOR,
                        TPM2_PT_FIRMWARE_VERSION_2 - TPM2_PT_FAMILY_INDICATOR + 1, /* get all relevant fields at once */
                        buf,
                        &list,
                        &n);
        if (r < 0)
                return r;

        for (i = 0; i < n; i++) {
                uint32_t property = unaligned_read_be32(list + i * 8);
                uint32_t value = unaligned_read_be32(list + i * 8 + 4);

                switch (property) {

                case TPM2_PT_FAMILY_INDICATOR:
                        unaligned_write_be32(info.family_indicator, value);
                        mangle_vendor_chars(info.family_indicator, sizeof(info.family_indicator));
                        break;

                case TPM2_PT_LEVEL:
                        info.level = value;
                        break;

                case TPM2_PT_REVISION:
                        info.revision_major = value / 100;
                        info.revision_minor = value % 100;
                        break;

                case TPM2_PT_DAY_OF_YEAR:
                        info.day_of_year = value;
                        break;

                case TPM2_PT_YEAR:
                        info.year = value;
                        break;

                case TPM2_PT_MANUFACTURER:
                        unaligned_write_be32(info.manufacturer, value);
                        mangle_vendor_chars(info.manufacturer, sizeof(info.manufacturer));
                        break;

                case TPM2_PT_VENDOR_STRING_1:
                        unaligned_write_be32(info.vendor_string+0, value);
                        break;

                case TPM2_PT_VENDOR_STRING_2:
                        unaligned_write_be32(info.vendor_string+4, value);
                        break;

                case TPM2_PT_VENDOR_STRING_3:
                        unaligned_write_be32(info.vendor_string+8, value);
                        break;

                case TPM2_PT_VENDOR_STRING_4:
                        unaligned_write_be32(info.vendor_string+12, value);
                        break;

                case TPM2_PT_VENDOR_TPM_TYPE:
                        info.vendor_tpm_type = value;
                        break;

                case TPM2_PT_FIRMWARE_VERSION_1:
                        info.firmware_version_major = value >> 16;
                        info.firmware_version_minor = value & 0xFFFFU;
                        break;

                case TPM2_PT_FIRMWARE_VERSION_2:
                        info.firmware_version2 = value;
                        break;
                }
        }

        mangle_vendor_chars(info.vendor_string, sizeof(info.vendor_string));
        *ret = info;
        return 0;
}

static int builtin_tpm2_id(struct udev_device *dev, int argc, char *argv[], enum udev_event_mode mode) {
        _cleanup_free_ char *m = NULL;
        _cleanup_close_ int fd = -1;
        Tpm2VendorInfo info;
        const char *dn;
        int r;

        if (argc != 2 || !streq(argv[1], "identify")) {
                log_error("%s: expected: identify", argv[0]);
                return EXIT_FAILURE;
        }

        dn = udev_device_get_devnode(dev);
        if (!dn) {
                log_error("%s: Failed to get device node for device", udev_device_get_sysname(dev));
                return EXIT_FAILURE;
        }

        fd = open(dn, O_RDWR|O_CLOEXEC|O_NOCTTY);
        if (fd < 0) {
                log_error_errno(errno, "Failed to open device node '%s': %m", dn);
                return EXIT_FAILURE;
        }

        r = tpm2_get_vendor_info(fd, &info);
        if (r < 0) {
                log_error_errno(r, "%s: Failed to acquire TPM2 vendor information: %m", dn);
                return EXIT_FAILURE;
        }

        if (!isempty(info.manufacturer))
                udev_builtin_add_property(dev, mode, "ID_TPM2_MANUFACTURER", info.manufacturer);

        if (!isempty(info.vendor_string))
                udev_builtin_add_property(dev, mode, "ID_TPM2_VENDOR_STRING", info.vendor_string);

        r = tpm2_vendor_info_to_modalias(&info, &m);
        if (r < 0) {
                log_error_errno(r, "%s: Failed to get modalias string for TPM2 device: %m", dn);
                return EXIT_FAILURE;
        }

        udev_builtin_add_property(dev, mode, "ID_TPM2_MODALIAS", m);

        return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_tpm2_id = {
        .name = "tpm2_id",
        .cmd = builtin_tpm2_id,
        .help = "Identify TPM2 chips",
        .run_once = true,
};
