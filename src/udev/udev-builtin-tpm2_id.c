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

/* Instead of going through the TSS2 libraries like systemd, the TPM2 commands are sent directly to the
 * kernel's TPM character device. The builtin sends the same commands as tpm2_context_new() and
 * tpm2_get_vendor_info() of systemd do: TPM2_Startup(), the capability queries of
 * tpm2_cache_capabilities(), the check for AES-128-CFB, which systemd requires for session encryption, and
 * the query of the vendor properties. The constants are from the TCG TPM 2.0 Library specification, part 2
 * (structures), and the TSS2 headers. */
#define TPM2_ST_NO_SESSIONS             UINT16_C(0x8001)
#define TPM2_CC_STARTUP                 UINT32_C(0x00000144)
#define TPM2_CC_GET_CAPABILITY          UINT32_C(0x0000017A)
#define TPM2_CC_TEST_PARMS              UINT32_C(0x0000018A)
#define TPM2_SU_CLEAR                   UINT16_C(0x0000)

#define TPM2_CAP_ALGS                   UINT32_C(0x00000000)
#define TPM2_CAP_COMMANDS               UINT32_C(0x00000002)
#define TPM2_CAP_PCRS                   UINT32_C(0x00000005)
#define TPM2_CAP_TPM_PROPERTIES         UINT32_C(0x00000006)
#define TPM2_CAP_ECC_CURVES             UINT32_C(0x00000008)

/* The maximum number of entries of the lists in TPMS_CAPABILITY_DATA (TPM2_MAX_CAP_BUFFER is 1024 bytes),
 * which are also the counts that systemd asks for */
#define TPM2_MAX_CAP_ALGS               UINT32_C(127)
#define TPM2_MAX_CAP_CC                 UINT32_C(256)
#define TPM2_MAX_ECC_CURVES             UINT32_C(508)
#define TPM2_MAX_TPM_PROPERTIES         UINT32_C(127)
#define TPM2_NUM_PCR_BANKS              UINT32_C(16)
#define TPM2_PCR_SELECT_MAX             4

#define TPM2_ALG_FIRST                  UINT16_C(0x0001)
#define TPM2_ALG_AES                    UINT16_C(0x0006)
#define TPM2_ALG_SYMCIPHER              UINT16_C(0x0025)
#define TPM2_ALG_CFB                    UINT16_C(0x0043)
#define TPM2_CC_FIRST                   UINT32_C(0x0000011F)
#define TPMA_CC_COMMANDINDEX_MASK       UINT32_C(0x0000FFFF)
#define TPM2_ECC_NONE                   UINT16_C(0x0000)

#define TPM2_RC_SUCCESS                 UINT32_C(0x000)
#define TPM2_RC_INITIALIZE              UINT32_C(0x100)
#define TPM2_RC_VALUE                   UINT32_C(0x084)
#define TPM2_RC_YIELDED                 UINT32_C(0x908)
#define TPM2_RC_TESTING                 UINT32_C(0x90A)
#define TPM2_RC_RETRY                   UINT32_C(0x922)

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
#define TPM2_PT_NV_BUFFER_MAX           UINT32_C(0x12C)

#define TPM2_HEADER_SIZE                10
#define TPM2_RESPONSE_MAX               4096

/* Like the ESAPI of tpm2-tss (ESYS_MAX_SUBMISSIONS), a command is sent at most this many times while the
 * TPM asks for it to be sent again. */
#define TPM2_MAX_SUBMISSIONS            5

/* The size systemd assumes if the TPM reports no or an implausible TPM_PT_NV_BUFFER_MAX */
#define FALLBACK_MAX_NV_BUFFER_SIZE     UINT32_C(512)

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

/* The errors that systemd's builtin takes as "full TPM2 support is not available" (ERRNO_IS_NOT_SUPPORTED()) */
static bool errno_is_not_supported(int r) {
        return IN_SET(abs(r), EOPNOTSUPP, ENOTTY, ENOSYS, EAFNOSUPPORT, EPFNOSUPPORT, EPROTONOSUPPORT,
                      ESOCKTNOSUPPORT, ENOPROTOOPT);
}

static void tpm2_command_header(uint8_t *cmd, size_t size, uint32_t cc) {
        unaligned_write_be16(cmd + 0, TPM2_ST_NO_SESSIONS);
        unaligned_write_be32(cmd + 2, size);
        unaligned_write_be32(cmd + 6, cc);
}

/* Sends a command and reads the response into buf. Like the ESAPI of tpm2-tss, which systemd uses, the
 * command is sent again while the TPM responds with TPM_RC_RETRY, TPM_RC_TESTING or TPM_RC_YIELDED, at most
 * TPM2_MAX_SUBMISSIONS times in total. Returns the size of the response, with its response code in
 * *ret_rc, or a negative errno. */
static int tpm2_transmit(int fd, const uint8_t *cmd, size_t cmd_size, uint8_t buf[static TPM2_RESPONSE_MAX], uint32_t *ret_rc) {
        unsigned submission;

        assert(fd >= 0);
        assert(cmd);
        assert(ret_rc);

        for (submission = 1;; submission++) {
                size_t n = 0, size = TPM2_RESPONSE_MAX;
                uint32_t rc;
                ssize_t l;

                l = write(fd, cmd, cmd_size);
                if (l < 0)
                        return log_debug_errno(errno, "Failed to send TPM2 command: %m");
                if ((size_t) l != cmd_size)
                        return log_debug_errno(EIO, "Short write while sending TPM2 command.");

                /* The TPM character device returns the whole response with one read(); only read more if
                 * something else is behind the device node and returns it in pieces. */
                while (n < size) {
                        l = read(fd, buf + n, TPM2_RESPONSE_MAX - n);
                        if (l < 0) {
                                if (errno == EINTR)
                                        continue;
                                return log_debug_errno(errno, "Failed to read TPM2 response: %m");
                        }
                        if (l == 0)
                                return log_debug_errno(EBADMSG, "TPM2 response too short.");
                        n += l;

                        if (n >= TPM2_HEADER_SIZE) {
                                size = unaligned_read_be32(buf + 2);
                                if (size < TPM2_HEADER_SIZE || size > TPM2_RESPONSE_MAX)
                                        return log_debug_errno(EBADMSG, "TPM2 response has an invalid size.");
                        }
                }
                if (n != size)
                        return log_debug_errno(EBADMSG, "TPM2 response size field does not match response length.");

                rc = unaligned_read_be32(buf + 6);
                if (IN_SET(rc, TPM2_RC_RETRY, TPM2_RC_TESTING, TPM2_RC_YIELDED) && submission < TPM2_MAX_SUBMISSIONS) {
                        log_debug("TPM returned RETRY, TESTING or YIELDED, sending the command again: 0x%" PRIx32, rc);
                        continue;
                }

                *ret_rc = rc;
                return (int) size;
        }
}

/* Sends TPM2_GetCapability(capability, property, count). Like tpm2_get_capability() of systemd, returns 1 if
 * the TPM has more data of this capability and 0 if not. *ret_data points to the data following the
 * TPM_CAP field of the response in buf, which is *ret_size bytes long. */
static int tpm2_get_capability(
                int fd,
                uint32_t capability,
                uint32_t property,
                uint32_t count,
                uint8_t buf[static TPM2_RESPONSE_MAX],
                const uint8_t **ret_data,
                size_t *ret_size) {

        uint8_t cmd[TPM2_HEADER_SIZE + 12];
        uint32_t rc;
        int size;

        assert(ret_data);
        assert(ret_size);

        tpm2_command_header(cmd, sizeof(cmd), TPM2_CC_GET_CAPABILITY);
        unaligned_write_be32(cmd + 10, capability);
        unaligned_write_be32(cmd + 14, property);
        unaligned_write_be32(cmd + 18, count);

        log_debug("Getting TPM2 capability 0x%04" PRIx32 " property 0x%04" PRIx32 " count %" PRIu32 ".",
                  capability, property, count);

        size = tpm2_transmit(fd, cmd, sizeof(cmd), buf, &rc);
        if (size < 0)
                return size;
        if (rc == TPM2_RC_VALUE)
                return log_debug_errno(ENXIO, "Requested TPM2 capability 0x%04" PRIx32 " property 0x%04" PRIx32 " apparently doesn't exist: TPM2 error 0x%" PRIx32,
                                       capability, property, rc);
        if (rc != TPM2_RC_SUCCESS)
                return log_debug_errno(ENOTRECOVERABLE, "Failed to get TPM2 capability 0x%04" PRIx32 " property 0x%04" PRIx32 ": TPM2 error 0x%" PRIx32,
                                       capability, property, rc);

        /* TPMI_YES_NO moreData, TPM_CAP capability */
        if ((size_t) size < TPM2_HEADER_SIZE + 1 + 4)
                return log_debug_errno(EBADMSG, "TPM2 response too short.");

        if (unaligned_read_be32(buf + TPM2_HEADER_SIZE + 1) != capability)
                return log_debug_errno(ENOTRECOVERABLE, "TPM provided wrong capability: 0x%04" PRIx32 " instead of 0x%04" PRIx32 ".",
                                       unaligned_read_be32(buf + TPM2_HEADER_SIZE + 1), capability);

        *ret_data = buf + TPM2_HEADER_SIZE + 5;
        *ret_size = size - (TPM2_HEADER_SIZE + 5);
        return buf[TPM2_HEADER_SIZE] == 1; /* TPM_YES */
}

/* Checks a TPML list with entries of entry_size bytes like the TSS2 unmarshaller does, and returns the number
 * of entries, with *ret_entries pointing to the first one. */
static int tpm2_parse_list(const uint8_t *data, size_t size, size_t entry_size, uint32_t max, const uint8_t **ret_entries) {
        uint32_t n;

        assert(data);
        assert(ret_entries);

        if (size < 4)
                return log_debug_errno(EBADMSG, "TPM2 response too short.");

        n = unaligned_read_be32(data);
        if (n > max)
                return log_debug_errno(EBADMSG, "TPM2 response lists too many entries (%" PRIu32 ").", n);
        if (n > (size - 4) / entry_size)
                return log_debug_errno(EBADMSG, "TPM2 response too short for %" PRIu32 " entries.", n);

        *ret_entries = data + 4;
        return (int) n;
}

/* Checks a TPML_PCR_SELECTION like the TSS2 unmarshaller does. */
static int tpm2_check_pcr_selection(const uint8_t *data, size_t size) {
        size_t pos = 4;
        uint32_t n, i;

        assert(data);

        if (size < 4)
                return log_debug_errno(EBADMSG, "TPM2 response too short.");

        n = unaligned_read_be32(data);
        if (n > TPM2_NUM_PCR_BANKS)
                return log_debug_errno(EBADMSG, "TPM2 response lists too many PCR banks (%" PRIu32 ").", n);

        for (i = 0; i < n; i++) {
                uint8_t sizeof_select;

                /* TPMI_ALG_HASH hash, UINT8 sizeofSelect, BYTE pcrSelect[sizeofSelect] */
                if (size - pos < 3)
                        return log_debug_errno(EBADMSG, "TPM2 response too short.");
                sizeof_select = data[pos + 2];
                pos += 3;

                if (sizeof_select > TPM2_PCR_SELECT_MAX)
                        return log_debug_errno(EBADMSG, "TPM2 response has an invalid PCR selection size (%u).", sizeof_select);
                if (size - pos < sizeof_select)
                        return log_debug_errno(EBADMSG, "TPM2 response too short.");
                pos += sizeof_select;
        }

        return 0;
}

static int tpm2_startup(int fd) {
        uint8_t cmd[TPM2_HEADER_SIZE + 2], buf[TPM2_RESPONSE_MAX];
        uint32_t rc;
        int r;

        tpm2_command_header(cmd, sizeof(cmd), TPM2_CC_STARTUP);
        unaligned_write_be16(cmd + 10, TPM2_SU_CLEAR);

        r = tpm2_transmit(fd, cmd, sizeof(cmd), buf, &rc);
        if (r < 0)
                return r;
        if (rc == TPM2_RC_INITIALIZE)
                log_debug("TPM already started up.");
        else if (rc == TPM2_RC_SUCCESS)
                log_debug("TPM successfully started up.");
        else
                return log_debug_errno(ENOTRECOVERABLE, "Failed to start up TPM: TPM2 error 0x%" PRIx32, rc);

        return 0;
}

/* Queries the same capabilities as tpm2_cache_capabilities() of systemd, which fails if the TPM does not
 * answer these queries, and returns whether the TPM supports the AES and CFB algorithms. Where systemd would
 * trip over an assertion or loop forever on a TPM that lists no entries or does not advance through its
 * list, this fails with EBADMSG. */
static int tpm2_cache_capabilities(int fd, bool *ret_aes, bool *ret_cfb) {
        uint8_t buf[TPM2_RESPONSE_MAX];
        const uint8_t *data, *e;
        bool aes = false, cfb = false;
        uint32_t current_cc, next_cc, value;
        uint16_t current_alg, next_alg, current_ecc_curve, next_ecc_curve;
        size_t size;
        int r, n, i;

        assert(ret_aes);
        assert(ret_cfb);

        /* Algorithms */
        current_alg = TPM2_ALG_FIRST;
        for (;;) {
                r = tpm2_get_capability(fd, TPM2_CAP_ALGS, current_alg, TPM2_MAX_CAP_ALGS, buf, &data, &size);
                if (r < 0)
                        return r;

                /* TPMS_ALG_PROPERTY: TPM_ALG_ID alg, TPMA_ALGORITHM algProperties */
                n = tpm2_parse_list(data, size, 6, TPM2_MAX_CAP_ALGS, &e);
                if (n < 0)
                        return n;
                if (n == 0)
                        return log_debug_errno(EBADMSG, "TPM reported no algorithms.");

                for (i = 0; i < n; i++) {
                        uint16_t alg = unaligned_read_be16(e + i * 6);

                        if (alg == TPM2_ALG_AES)
                                aes = true;
                        else if (alg == TPM2_ALG_CFB)
                                cfb = true;
                }

                if (r == 0)
                        break;

                next_alg = unaligned_read_be16(e + (n - 1) * 6) + 1;
                if (next_alg <= current_alg)
                        return log_debug_errno(EBADMSG, "TPM does not advance through its list of algorithms.");
                current_alg = next_alg;
        }

        /* Commands */
        current_cc = TPM2_CC_FIRST;
        for (;;) {
                r = tpm2_get_capability(fd, TPM2_CAP_COMMANDS, current_cc, TPM2_MAX_CAP_CC, buf, &data, &size);
                if (r < 0)
                        return r;

                /* TPMA_CC */
                n = tpm2_parse_list(data, size, 4, TPM2_MAX_CAP_CC, &e);
                if (n < 0)
                        return n;
                if (n == 0)
                        return log_debug_errno(EBADMSG, "TPM reported no commands.");

                if (r == 0)
                        break;

                next_cc = (unaligned_read_be32(e + (n - 1) * 4) & TPMA_CC_COMMANDINDEX_MASK) + 1;
                if (next_cc <= current_cc)
                        return log_debug_errno(EBADMSG, "TPM does not advance through its list of commands.");
                current_cc = next_cc;
        }

        /* ECC curves, which are not required */
        current_ecc_curve = TPM2_ECC_NONE;
        for (;;) {
                r = tpm2_get_capability(fd, TPM2_CAP_ECC_CURVES, current_ecc_curve, TPM2_MAX_ECC_CURVES, buf, &data, &size);
                if (r == -ENXIO) /* If the TPM doesn't support ECC, it might return TPM2_RC_VALUE rather than no curves */
                        break;
                if (r < 0)
                        return r;

                /* TPM_ECC_CURVE */
                n = tpm2_parse_list(data, size, 2, TPM2_MAX_ECC_CURVES, &e);
                if (n < 0)
                        return n;
                if (n == 0)
                        break;

                if (r == 0)
                        break;

                next_ecc_curve = unaligned_read_be16(e + (n - 1) * 2) + 1;
                if (next_ecc_curve <= current_ecc_curve)
                        return log_debug_errno(EBADMSG, "TPM does not advance through its list of ECC curves.");
                current_ecc_curve = next_ecc_curve;
        }

        /* PCR banks */
        r = tpm2_get_capability(fd, TPM2_CAP_PCRS, 0, 1, buf, &data, &size);
        if (r < 0)
                return r;
        n = tpm2_check_pcr_selection(data, size);
        if (n < 0)
                return n;
        if (r == 1)
                log_debug("TPM bug: reported multiple PCR sets; using only first set.");

        /* TPM_PT_NV_BUFFER_MAX */
        r = tpm2_get_capability(fd, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_NV_BUFFER_MAX, 1, buf, &data, &size);
        if (r < 0)
                return r;

        /* TPMS_TAGGED_PROPERTY: TPM_PT property, UINT32 value */
        n = tpm2_parse_list(data, size, 8, TPM2_MAX_TPM_PROPERTIES, &e);
        if (n < 0)
                return n;
        if (n == 0 || unaligned_read_be32(e) != TPM2_PT_NV_BUFFER_MAX)
                log_debug("TPM bug: didn't report a value for TPM_PT_NV_BUFFER_MAX; using %" PRIu32 ".", FALLBACK_MAX_NV_BUFFER_SIZE);
        else {
                value = unaligned_read_be32(e + 4);
                if (value == 0 || value > UINT16_MAX)
                        log_debug("TPM bug: reported implausible value for TPM_PT_NV_BUFFER_MAX; using %" PRIu32 ".", FALLBACK_MAX_NV_BUFFER_SIZE);
        }

        *ret_aes = aes;
        *ret_cfb = cfb;
        return 0;
}

/* Sends TPM2_TestParms() for a symmetric cipher object with AES-128 in CFB mode. Like tpm2_test_parms() of
 * systemd, any failure means that the TPM does not support it. */
static bool tpm2_supports_aes_128_cfb(int fd) {
        uint8_t cmd[TPM2_HEADER_SIZE + 8], buf[TPM2_RESPONSE_MAX];
        uint32_t rc;
        int r;

        tpm2_command_header(cmd, sizeof(cmd), TPM2_CC_TEST_PARMS);
        /* TPMT_PUBLIC_PARMS: TPMI_ALG_PUBLIC type, TPMS_SYMCIPHER_PARMS (TPMT_SYM_DEF_OBJECT algorithm,
         * keyBits, mode) */
        unaligned_write_be16(cmd + 10, TPM2_ALG_SYMCIPHER);
        unaligned_write_be16(cmd + 12, TPM2_ALG_AES);
        unaligned_write_be16(cmd + 14, 128);
        unaligned_write_be16(cmd + 16, TPM2_ALG_CFB);

        r = tpm2_transmit(fd, cmd, sizeof(cmd), buf, &rc);
        if (r < 0)
                return false;
        if (rc != TPM2_RC_SUCCESS) {
                log_debug("TPM does not support tested parms: TPM2 error 0x%" PRIx32, rc);
                return false;
        }

        return true;
}

/* Like tpm2_context_new() of systemd, once the device is open: start up the TPM, query its capabilities
 * and require AES-128-CFB, returning -EOPNOTSUPP if it is missing. */
static int tpm2_context_new(int fd) {
        bool aes, cfb;
        int r;

        r = tpm2_startup(fd);
        if (r < 0)
                return r;

        r = tpm2_cache_capabilities(fd, &aes, &cfb);
        if (r < 0)
                return log_debug_errno(r, "Failed to cache TPM capabilities: %m");

        /* We require AES and CFB support for session encryption. */
        if (!aes)
                return log_debug_errno(EOPNOTSUPP, "TPM does not support AES.");

        if (!cfb)
                return log_debug_errno(EOPNOTSUPP, "TPM does not support CFB.");

        if (!tpm2_supports_aes_128_cfb(fd))
                return log_debug_errno(EOPNOTSUPP, "TPM does not support AES-128-CFB.");

        return 0;
}

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

static int tpm2_get_vendor_info(int fd, Tpm2VendorInfo *ret) {
        uint8_t buf[TPM2_RESPONSE_MAX];
        Tpm2VendorInfo info = {};
        const uint8_t *data, *list;
        size_t size;
        int r, n, i;

        assert(fd >= 0);
        assert(ret);

        r = tpm2_get_capability(
                        fd,
                        TPM2_CAP_TPM_PROPERTIES,
                        TPM2_PT_FAMILY_INDICATOR,
                        TPM2_PT_FIRMWARE_VERSION_2 - TPM2_PT_FAMILY_INDICATOR + 1, /* get all relevant fields at once */
                        buf,
                        &data,
                        &size);
        if (r < 0)
                return r;

        /* TPMS_TAGGED_PROPERTY: TPM_PT property, UINT32 value */
        n = tpm2_parse_list(data, size, 8, TPM2_MAX_TPM_PROPERTIES, &list);
        if (n < 0)
                return n;

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

        /* Like systemd, the errors are returned as negative error codes, with the reason. */
        if (argc != 2 || !streq(argv[1], "identify"))
                return log_error_errno(EINVAL, "%s: expected: identify", argv[0]);

        dn = udev_device_get_devnode(dev);
        if (!dn)
                return log_error_errno(ENOENT, "%s: Failed to get device node for device: %m", udev_device_get_sysname(dev));

        fd = open(dn, O_RDWR|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open device node '%s': %m", dn);

        r = tpm2_context_new(fd);
        if (errno_is_not_supported(r)) {
                log_debug_errno(r, "Full TPM2 support is not available, skipping identification of TPM2 device '%s'.", dn);
                return EXIT_SUCCESS;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open device node '%s': %m", dn);

        r = tpm2_get_vendor_info(fd, &info);
        if (r < 0)
                return log_error_errno(r, "%s: Failed to acquire TPM2 vendor information: %m", dn);

        if (!isempty(info.manufacturer)) {
                r = udev_builtin_add_property(dev, mode, "ID_TPM2_MANUFACTURER", info.manufacturer);
                if (r == -ENOMEM)
                        return log_oom();
        }

        if (!isempty(info.vendor_string)) {
                r = udev_builtin_add_property(dev, mode, "ID_TPM2_VENDOR_STRING", info.vendor_string);
                if (r == -ENOMEM)
                        return log_oom();
        }

        r = tpm2_vendor_info_to_modalias(&info, &m);
        if (r < 0)
                return log_error_errno(r, "%s: Failed to get modalias string for TPM2 device: %m", dn);

        r = udev_builtin_add_property(dev, mode, "ID_TPM2_MODALIAS", m);
        if (r == -ENOMEM)
                return log_oom();

        return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_tpm2_id = {
        .name = "tpm2_id",
        .cmd = builtin_tpm2_id,
        .help = "Identify TPM2 chips",
        .run_once = true,
};
