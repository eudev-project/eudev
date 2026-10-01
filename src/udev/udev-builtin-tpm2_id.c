/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "udev.h"
#include "unaligned.h"

/* Instead of going through the TSS2 libraries like systemd, the TPM2 commands are sent directly to the
 * kernel's TPM character device. The builtin sends the same commands as tpm2_context_new() and
 * tpm2_get_vendor_info() of systemd do: the TPM2_GetRandom() with which the device TCTI of tpm2-tss probes
 * the device, TPM2_Startup(), the capability queries of tpm2_cache_capabilities(), the check for
 * AES-128-CFB, which systemd requires for session encryption, and the query of the vendor properties. The
 * constants are from the TCG TPM 2.0 Library specification, part 2 (structures), and the TSS2 headers. */
#define TPM2_ST_RSP_COMMAND             UINT16_C(0x00C4) /* the tag of TPM 1.2 responses */
#define TPM2_ST_NO_SESSIONS             UINT16_C(0x8001)
#define TPM2_ST_SESSIONS                UINT16_C(0x8002)
#define TPM2_CC_STARTUP                 UINT32_C(0x00000144)
#define TPM2_CC_GET_CAPABILITY          UINT32_C(0x0000017A)
#define TPM2_CC_GET_RANDOM              UINT32_C(0x0000017B)
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
/* The size of the response buffer of tpm2-tss (TPM2_MAX_COMMAND_SIZE), the largest response it accepts */
#define TPM2_RESPONSE_MAX               4096

/* How long the device TCTI of tpm2-tss waits for each of the two parts of the response to its probe */
#define TPM2_PROBE_TIMEOUT_USEC         (1 * USEC_PER_SEC)

/* Like the ESAPI of tpm2-tss (ESYS_MAX_SUBMISSIONS), a command is sent at most this many times while the
 * TPM asks for it to be sent again. */
#define TPM2_MAX_SUBMISSIONS            5

/* The size systemd assumes if the TPM reports no or an implausible TPM_PT_NV_BUFFER_MAX */
#define FALLBACK_MAX_NV_BUFFER_SIZE     UINT32_C(512)

typedef struct Tpm2Device {
        const char *path;
        int fd;
        bool partial_read;      /* whether a response can be read in pieces */
} Tpm2Device;

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

static void tpm2_device_close(Tpm2Device *d) {
        assert(d);

        d->fd = safe_close(d->fd);
}

static int tpm2_open(const char *path) {
        /* Like the device TCTI of tpm2-tss, open the device in non-blocking mode, so that the kernel runs the
         * commands asynchronously and the probe can time out while waiting for the response. */
        return open(path, O_RDWR|O_NONBLOCK|O_CLOEXEC|O_NOCTTY);
}

/* Waits until the device is readable, and returns the poll events, or 0 on timeout. */
static int tpm2_wait(int fd, usec_t timeout) {
        int r;

        do
                r = fd_wait_for_event(fd, POLLIN, timeout);
        while (r == -EINTR);

        return r;
}

static ssize_t tpm2_read(int fd, void *buf, size_t size) {
        ssize_t l;

        do
                l = read(fd, buf, size);
        while (l < 0 && errno == EINTR);

        return l < 0 ? -errno : l;
}

/* Like Tss2_Tcti_Device_Init() of tpm2-tss, which systemd uses: send TPM2_GetRandom() for 8 bytes, and read
 * the header of the response, which must arrive within a second, and then the rest of it, again within a
 * second. If the rest does not arrive, the device cannot return a response in pieces (Linux supports this
 * since 4.20), and it is opened again, which drops the response. The response itself is not checked. As
 * with tpm2-tss, waiting for the rest costs a second on Linux 4.18 and 4.19, and whenever the TPM answers
 * with a bare header (an error code).
 *
 * Unlike tpm2-tss, which reads only if poll() returns exactly POLLIN, and then at most 20 bytes, the header
 * is read whenever POLLIN is set, and the rest as long as the size field of the header says, so that no
 * part of an unexpectedly long response is left for the next command to read. Neither matters with the TPM
 * devices of Linux, which report only POLLIN and drop an unread rest when the next command is written, but
 * it does with other devices. A normal response to the probe is 20 bytes long, and is read with the same
 * system calls as by tpm2-tss. */
static int tpm2_probe(Tpm2Device *d) {
        static const uint8_t cmd[] = {
                0x80, 0x01,                     /* TPM2_ST_NO_SESSIONS */
                0x00, 0x00, 0x00, 0x0c,         /* commandSize */
                0x00, 0x00, 0x01, 0x7b,         /* TPM2_CC_GetRandom */
                0x00, 0x08,                     /* bytesRequested */
        };
        uint8_t rsp[TPM2_RESPONSE_MAX];
        size_t rest = sizeof(rsp) - TPM2_HEADER_SIZE;
        ssize_t l;
        int r;

        assert(d);
        assert(unaligned_read_be32(cmd + 6) == TPM2_CC_GET_RANDOM);

        log_debug("Probing TPM2 device for partial response read support.");

        r = loop_write(d->fd, cmd, sizeof(cmd), false);
        if (r < 0)
                return log_debug_errno(r, "Could not probe TPM2 device for partial response read support: %m");

        r = tpm2_wait(d->fd, TPM2_PROBE_TIMEOUT_USEC);
        if (r < 0)
                return log_debug_errno(r, "Failed to wait for the response to the TPM2 probe: %m");
        if (r == 0)
                return log_debug_errno(ETIMEDOUT, "Timed out waiting for the response to the TPM2 probe.");
        if (r & POLLIN) {
                uint32_t size;

                l = tpm2_read(d->fd, rsp, TPM2_HEADER_SIZE);
                if (l < 0)
                        return log_debug_errno(l, "Failed to read the response header of the TPM2 probe: %m");
                if (l != TPM2_HEADER_SIZE)
                        return log_debug_errno(EIO, "Failed to read the response header of the TPM2 probe.");

                /* Without a plausible size, e.g. of a bare header, read as much as a response can have */
                size = unaligned_read_be32(rsp + 2);
                if (size > TPM2_HEADER_SIZE && size <= sizeof(rsp))
                        rest = size - TPM2_HEADER_SIZE;
        }

        l = 0;
        r = tpm2_wait(d->fd, TPM2_PROBE_TIMEOUT_USEC);
        if (r < 0)
                return log_debug_errno(r, "Failed to wait for the response to the TPM2 probe: %m");
        if (r & POLLIN) {
                l = tpm2_read(d->fd, rsp + TPM2_HEADER_SIZE, rest);
                if (l < 0)
                        log_debug_errno(l, "Failed to read the rest of the response to the TPM2 probe: %m");
        }

        if (l > 0) {
                log_debug("TPM2 device supports partial response reads.");
                d->partial_read = true;
                return 0;
        }

        log_debug("TPM2 device does not support partial response reads, opening it again.");
        d->partial_read = false;
        safe_close(d->fd);
        d->fd = tpm2_open(d->path);
        if (d->fd < 0)
                return log_debug_errno(errno, "Failed to open TPM2 device '%s' again: %m", d->path);

        return 0;
}

static void tpm2_command_header(uint8_t *cmd, size_t size, uint32_t cc) {
        unaligned_write_be16(cmd + 0, TPM2_ST_NO_SESSIONS);
        unaligned_write_be32(cmd + 2, size);
        unaligned_write_be32(cmd + 6, cc);
}

/* Reads a response into buf like tcti_device_receive() and Tss2_Sys_ExecuteFinish() of tpm2-tss: the
 * header first and then the rest if the device supports partial reads, otherwise all at once. As there,
 * the response must be at least a header and at most TPM2_RESPONSE_MAX bytes long, and have the tag of a
 * TPM 2.0 response. Unlike there, it is read whenever poll() sets POLLIN, also together with other events
 * (which the TPM devices of Linux do not report), as by the probe, and a response that is shorter than its
 * size field says is refused instead of being used with whatever follows it in the buffer. Returns the size
 * of the response. */
static int tpm2_receive(Tpm2Device *d, uint8_t buf[static TPM2_RESPONSE_MAX]) {
        uint32_t size;
        uint16_t tag;
        ssize_t l = 0;
        int r;

        assert(d);

        r = tpm2_wait(d->fd, USEC_INFINITY);
        if (r < 0)
                return log_debug_errno(r, "Failed to wait for the TPM2 response: %m");

        if (d->partial_read) {
                if (!(r & POLLIN))
                        return log_debug_errno(EIO, "TPM2 response header could not be received.");

                l = tpm2_read(d->fd, buf, TPM2_HEADER_SIZE);
                if (l < 0)
                        return log_debug_errno(l, "Failed to read TPM2 response header: %m");
                if (l != TPM2_HEADER_SIZE)
                        return log_debug_errno(EIO, "Failed to read TPM2 response header.");

                size = unaligned_read_be32(buf + 2);
                if (size < TPM2_HEADER_SIZE)
                        return log_debug_errno(EBADMSG, "TPM2 response size %" PRIu32 " is too small for a response header.", size);
                if (size > TPM2_RESPONSE_MAX)
                        return log_debug_errno(EBADMSG, "TPM2 response size %" PRIu32 " is too large.", size);

                if (size > TPM2_HEADER_SIZE) {
                        r = tpm2_wait(d->fd, USEC_INFINITY);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to wait for the TPM2 response: %m");
                        l = 0;
                        if (r & POLLIN) {
                                l = tpm2_read(d->fd, buf + TPM2_HEADER_SIZE, size - TPM2_HEADER_SIZE);
                                if (l < 0)
                                        return log_debug_errno(l, "Failed to read TPM2 response: %m");
                        }
                        if (l == 0)
                                return log_debug_errno(EIO, "Got EOF instead of the rest of the TPM2 response.");
                        l += TPM2_HEADER_SIZE;
                }
        } else {
                if (r & POLLIN) {
                        l = tpm2_read(d->fd, buf, TPM2_RESPONSE_MAX);
                        if (l < 0)
                                return log_debug_errno(l, "Failed to read TPM2 response: %m");
                }
                if (l == 0)
                        return log_debug_errno(EIO, "Got EOF instead of the TPM2 response.");
                if (l < TPM2_HEADER_SIZE)
                        return log_debug_errno(EBADMSG, "Received %zi bytes, not enough for a TPM2 response header.", l);

                size = unaligned_read_be32(buf + 2);
                if (size < TPM2_HEADER_SIZE)
                        return log_debug_errno(EBADMSG, "TPM2 response size %" PRIu32 " is too small for a response header.", size);
                if (size > TPM2_RESPONSE_MAX)
                        return log_debug_errno(EBADMSG, "TPM2 response size %" PRIu32 " is too large.", size);
        }

        if ((size_t) l != size)
                return log_debug_errno(EBADMSG, "TPM2 response size %" PRIu32 " does not match the %zi bytes received.", size, l);

        tag = unaligned_read_be16(buf);
        if (tag == TPM2_ST_RSP_COMMAND)
                return log_debug_errno(EBADMSG, "Unsupported device, the device is a TPM 1.2.");
        if (!IN_SET(tag, TPM2_ST_NO_SESSIONS, TPM2_ST_SESSIONS))
                return log_debug_errno(EBADMSG, "Malformed TPM2 response, invalid tag 0x%04" PRIx16 " in the response header.", tag);

        return (int) size;
}

/* Sends a command and reads the response into buf. Like the ESAPI of tpm2-tss, which systemd uses, the
 * command is sent again while the TPM responds with TPM_RC_RETRY, TPM_RC_TESTING or TPM_RC_YIELDED, at most
 * TPM2_MAX_SUBMISSIONS times in total. Returns the size of the response, with its response code in *ret_rc
 * and the offset of its parameters in *ret_params, or a negative errno. */
static int tpm2_transmit(Tpm2Device *d, const uint8_t *cmd, size_t cmd_size, uint8_t buf[static TPM2_RESPONSE_MAX], uint32_t *ret_rc, size_t *ret_params) {
        unsigned submission;

        assert(d);
        assert(cmd);
        assert(ret_rc);

        for (submission = 1;; submission++) {
                size_t params = TPM2_HEADER_SIZE;
                uint32_t rc;
                int size, r;

                r = loop_write(d->fd, cmd, cmd_size, false);
                if (r < 0)
                        return log_debug_errno(r, "Failed to send TPM2 command: %m");

                size = tpm2_receive(d, buf);
                if (size < 0)
                        return size;

                rc = unaligned_read_be32(buf + 6);
                if (IN_SET(rc, TPM2_RC_RETRY, TPM2_RC_TESTING, TPM2_RC_YIELDED) && submission < TPM2_MAX_SUBMISSIONS) {
                        log_debug("TPM returned RETRY, TESTING or YIELDED, sending the command again: 0x%" PRIx32, rc);
                        continue;
                }

                /* A response with sessions has the size of its parameters in front of them (none of the
                 * commands sent here return handles). The commands are sent without sessions, but the SAPI
                 * of tpm2-tss skips that field anyway if a successful response has sessions. */
                if (rc == TPM2_RC_SUCCESS && unaligned_read_be16(buf) == TPM2_ST_SESSIONS) {
                        if ((size_t) size < TPM2_HEADER_SIZE + 4)
                                return log_debug_errno(EBADMSG, "TPM2 response too short.");
                        params += 4;
                }

                *ret_rc = rc;
                if (ret_params)
                        *ret_params = params;
                return size;
        }
}

/* Sends TPM2_GetCapability(capability, property, count). Like tpm2_get_capability() of systemd, returns 1 if
 * the TPM has more data of this capability and 0 if not. *ret_data points to the data following the
 * TPM_CAP field of the response in buf, which is *ret_size bytes long. */
static int tpm2_get_capability(
                Tpm2Device *d,
                uint32_t capability,
                uint32_t property,
                uint32_t count,
                uint8_t buf[static TPM2_RESPONSE_MAX],
                const uint8_t **ret_data,
                size_t *ret_size) {

        uint8_t cmd[TPM2_HEADER_SIZE + 12];
        size_t params;
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

        size = tpm2_transmit(d, cmd, sizeof(cmd), buf, &rc, &params);
        if (size < 0)
                return size;
        if (rc == TPM2_RC_VALUE)
                return log_debug_errno(ENXIO, "Requested TPM2 capability 0x%04" PRIx32 " property 0x%04" PRIx32 " apparently doesn't exist: TPM2 error 0x%" PRIx32,
                                       capability, property, rc);
        if (rc != TPM2_RC_SUCCESS)
                return log_debug_errno(ENOTRECOVERABLE, "Failed to get TPM2 capability 0x%04" PRIx32 " property 0x%04" PRIx32 ": TPM2 error 0x%" PRIx32,
                                       capability, property, rc);

        /* TPMI_YES_NO moreData, TPM_CAP capability */
        if ((size_t) size < params + 1 + 4)
                return log_debug_errno(EBADMSG, "TPM2 response too short.");

        if (unaligned_read_be32(buf + params + 1) != capability)
                return log_debug_errno(ENOTRECOVERABLE, "TPM provided wrong capability: 0x%04" PRIx32 " instead of 0x%04" PRIx32 ".",
                                       unaligned_read_be32(buf + params + 1), capability);

        *ret_data = buf + params + 5;
        *ret_size = size - (params + 5);
        return buf[params] == 1; /* TPM_YES */
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

static int tpm2_startup(Tpm2Device *d) {
        uint8_t cmd[TPM2_HEADER_SIZE + 2], buf[TPM2_RESPONSE_MAX];
        uint32_t rc;
        int r;

        tpm2_command_header(cmd, sizeof(cmd), TPM2_CC_STARTUP);
        unaligned_write_be16(cmd + 10, TPM2_SU_CLEAR);

        r = tpm2_transmit(d, cmd, sizeof(cmd), buf, &rc, NULL);
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
static int tpm2_cache_capabilities(Tpm2Device *d, bool *ret_aes, bool *ret_cfb) {
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
                r = tpm2_get_capability(d, TPM2_CAP_ALGS, current_alg, TPM2_MAX_CAP_ALGS, buf, &data, &size);
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
                r = tpm2_get_capability(d, TPM2_CAP_COMMANDS, current_cc, TPM2_MAX_CAP_CC, buf, &data, &size);
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
                r = tpm2_get_capability(d, TPM2_CAP_ECC_CURVES, current_ecc_curve, TPM2_MAX_ECC_CURVES, buf, &data, &size);
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
        r = tpm2_get_capability(d, TPM2_CAP_PCRS, 0, 1, buf, &data, &size);
        if (r < 0)
                return r;
        n = tpm2_check_pcr_selection(data, size);
        if (n < 0)
                return n;
        if (r == 1)
                log_debug("TPM bug: reported multiple PCR sets; using only first set.");

        /* TPM_PT_NV_BUFFER_MAX */
        r = tpm2_get_capability(d, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_NV_BUFFER_MAX, 1, buf, &data, &size);
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
static bool tpm2_supports_aes_128_cfb(Tpm2Device *d) {
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

        r = tpm2_transmit(d, cmd, sizeof(cmd), buf, &rc, NULL);
        if (r < 0)
                return false;
        if (rc != TPM2_RC_SUCCESS) {
                log_debug("TPM does not support tested parms: TPM2 error 0x%" PRIx32, rc);
                return false;
        }

        return true;
}

/* Like tpm2_context_new() of systemd, once the device is open: probe it like the device TCTI of tpm2-tss,
 * start up the TPM, query its capabilities and require AES-128-CFB, returning -EOPNOTSUPP if it is
 * missing. */
static int tpm2_context_new(Tpm2Device *d) {
        bool aes, cfb;
        int r;

        assert(d);

        r = tpm2_probe(d);
        if (r < 0)
                return r;

        r = tpm2_startup(d);
        if (r < 0)
                return r;

        r = tpm2_cache_capabilities(d, &aes, &cfb);
        if (r < 0)
                return log_debug_errno(r, "Failed to cache TPM capabilities: %m");

        /* We require AES and CFB support for session encryption. */
        if (!aes)
                return log_debug_errno(EOPNOTSUPP, "TPM does not support AES.");

        if (!cfb)
                return log_debug_errno(EOPNOTSUPP, "TPM does not support CFB.");

        if (!tpm2_supports_aes_128_cfb(d))
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

static int tpm2_get_vendor_info(Tpm2Device *d, Tpm2VendorInfo *ret) {
        uint8_t buf[TPM2_RESPONSE_MAX];
        Tpm2VendorInfo info = {};
        const uint8_t *data, *list;
        size_t size;
        int r, n, i;

        assert(d);
        assert(ret);

        r = tpm2_get_capability(
                        d,
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
        _cleanup_(tpm2_device_close) Tpm2Device d = { .fd = -1 };
        _cleanup_free_ char *m = NULL;
        Tpm2VendorInfo info;
        const char *dn;
        int r;

        /* Like systemd, the errors are returned as negative error codes, with the reason. */
        if (argc != 2 || !streq(argv[1], "identify"))
                return log_device_error_errno(dev, EINVAL, "%s: expected: identify", argv[0]);

        dn = udev_device_get_devnode(dev);
        if (!dn)
                return log_device_error_errno(dev, ENOENT, "Failed to get device node for device: %m");

        d.path = dn;
        d.fd = tpm2_open(dn);
        if (d.fd < 0)
                return log_device_error_errno(dev, errno, "Failed to open device node '%s': %m", dn);

        r = tpm2_context_new(&d);
        if (errno_is_not_supported(r)) {
                log_device_debug_errno(dev, r, "Full TPM2 support is not available, skipping identification of TPM2 device '%s'.", dn);
                return EXIT_SUCCESS;
        }
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to open device node '%s': %m", dn);

        r = tpm2_get_vendor_info(&d, &info);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to acquire TPM2 vendor information: %m");

        if (!isempty(info.manufacturer)) {
                r = udev_builtin_add_property(dev, mode, "ID_TPM2_MANUFACTURER", info.manufacturer);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        log_device_warning_errno(dev, r, "Failed to set ID_TPM2_MANUFACTURER property, ignoring: %m");
        }

        if (!isempty(info.vendor_string)) {
                r = udev_builtin_add_property(dev, mode, "ID_TPM2_VENDOR_STRING", info.vendor_string);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        log_device_warning_errno(dev, r, "Failed to set ID_TPM2_VENDOR_STRING property, ignoring: %m");
        }

        r = tpm2_vendor_info_to_modalias(&info, &m);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get modalias string for TPM2 device: %m");

        r = udev_builtin_add_property(dev, mode, "ID_TPM2_MODALIAS", m);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                log_device_warning_errno(dev, r, "Failed to set ID_TPM2_MODALIAS property, ignoring: %m");

        return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_tpm2_id = {
        .name = "tpm2_id",
        .cmd = builtin_tpm2_id,
        .help = "Identify TPM2 chips",
        .run_once = true,
};
