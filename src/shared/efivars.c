/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include "efivars.h"
#include "log.h"
#include "utf8.h"
#include "util.h"
#include "virt.h"

/* Reads from efivarfs sometimes fail with EINTR. Retry that many times. */
#define EFI_N_RETRIES_NO_DELAY 20
#define EFI_N_RETRIES_TOTAL 25
#define EFI_RETRY_DELAY_USEC (50 * USEC_PER_MSEC)

#define EFI_VARIABLE_SIZE_MAX (4U * 1024U * 1024U)

int efi_get_variable(
                const char *variable,
                uint32_t *ret_attribute,
                void **ret_value,
                size_t *ret_size) {

        _cleanup_close_ int fd = -1;
        _cleanup_free_ char *buf = NULL;
        const char *p;
        uint32_t attr;
        unsigned try;
        ssize_t n;
        size_t value_size;

        assert(variable);

        p = strjoina("/sys/firmware/efi/efivars/", variable);

        log_debug("Reading EFI variable %s.", p);

        fd = open(p, O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return log_debug_errno(errno, "open(\"%s\") failed: %m", p);

        /* The kernel ratelimits reads from the efivarfs because EFI is inefficient, and we'll occasionally
         * fail with EINTR here. A slowdown is better than a failure for us, so retry a few times and
         * eventually fail with -EBUSY.
         *
         * The variable may also be overwritten between the stat and read. If we find out that the new
         * contents are longer, try again. */
        for (try = 0;; try++) {
                struct stat st;
                size_t file_size, read_size;
                struct iovec iov[2];

                if (fstat(fd, &st) < 0)
                        return log_debug_errno(errno, "fstat(\"%s\") failed: %m", p);

                if (!S_ISREG(st.st_mode))
                        return log_debug_errno(EBADFD, "EFI variable '%s' is not a regular file, refusing.", p);

                if (st.st_size == 0) /* for uncommitted variables, see below */
                        return log_debug_errno(ENOENT, "EFI variable '%s' is uncommitted", p);
                if ((uint64_t) st.st_size < sizeof(attr))
                        return log_debug_errno(ENODATA, "EFI variable '%s' is shorter than %zu bytes, refusing.", p, sizeof(attr));
                if ((uint64_t) st.st_size > sizeof(attr) + EFI_VARIABLE_SIZE_MAX)
                        return log_debug_errno(E2BIG, "EFI variable '%s' is ridiculously large, refusing.", p);

                file_size = (size_t) st.st_size;

                if (!ret_attribute && !ret_value) {
                        /* No need to read anything, return the reported size. */
                        n = file_size;
                        break;
                }

                /* We want +1 for the read call, and +3 for the additional terminating bytes added below. */
                read_size = file_size - sizeof(attr) + 1;

                free(buf);
                buf = malloc(read_size + 3);
                if (!buf)
                        return -ENOMEM;

                iov[0] = (struct iovec) { &attr, sizeof(attr) };
                iov[1] = (struct iovec) { buf, read_size };

                n = readv(fd, iov, 2);
                if (n < 0) {
                        if (errno != EINTR)
                                return log_debug_errno(errno, "Reading from '%s' failed: %m", p);

                        log_debug("Reading from '%s' failed with EINTR, retrying.", p);
                } else if ((size_t) n == file_size + 1)
                        /* We need to try again with a bigger buffer, the variable was apparently changed concurrently? */
                        log_debug("EFI variable '%s' larger than expected, retrying.", p);
                else
                        break;

                if (try >= EFI_N_RETRIES_TOTAL)
                        return log_debug_errno(EBUSY, "Reading EFI variable '%s' failed even after %u tries, giving up.", p, try);
                if (try >= EFI_N_RETRIES_NO_DELAY)
                        (void) usleep(EFI_RETRY_DELAY_USEC);

                /* Start from the beginning */
                (void) lseek(fd, 0, SEEK_SET);
        }

        /* The kernel reports EOF if there's an inconsistency between efivarfs var list and what's actually
         * stored in firmware. A zero size variable is not allowed in EFI and hence the variable doesn't
         * really exist in the backing store as long as it is zero sized, and the kernel calls this
         * "uncommitted". Hence we translate EOF back to ENOENT here. */
        if (n == 0)
                return log_debug_errno(ENOENT, "EFI variable %s is uncommitted", p);
        if ((size_t) n < sizeof(attr))
                return log_debug_errno(EIO, "Read %zi bytes from EFI variable %s, expected >= %zu", n, p, sizeof(attr));
        value_size = n - sizeof(attr);

        if (ret_attribute)
                *ret_attribute = attr;

        if (ret_value) {
                assert(buf);
                /* Always NUL-terminate (3 bytes, to properly protect UTF-16, even if truncated in
                 * the middle of a character) */
                buf[value_size] = 0;
                buf[value_size + 1] = 0;
                buf[value_size + 2] = 0;
                *ret_value = buf;
                buf = NULL;
        }

        if (ret_size)
                *ret_size = value_size;

        return 0;
}

int efi_get_variable_string(const char *variable, char **ret) {
        _cleanup_free_ void *s = NULL;
        size_t ss = 0;
        char *x;
        int r;

        assert(variable);

        r = efi_get_variable(variable, NULL, &s, &ss);
        if (r < 0)
                return r;

        x = utf16_to_utf8(s, ss);
        if (!x)
                return -ENOMEM;

        if (ret)
                *ret = x;
        else
                free(x);

        return 0;
}

int efi_get_variable_id128(const char *variable, id128_t *ret) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(variable);

        r = efi_get_variable_string(variable, &p);
        if (r < 0)
                return r;

        return id128_from_string(p, ret);
}

bool is_efi_boot(void) {
        static int cache = -1;

        if (cache >= 0)
                return cache;

        if (detect_container(NULL) > 0)
                return (cache = false);

        if (access("/sys/firmware/efi/", F_OK) < 0) {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Unable to test whether /sys/firmware/efi/ exists, assuming EFI not available: %m");
                return (cache = false);
        }

        return (cache = true);
}

int efi_loader_get_device_part_uuid(id128_t *ret) {
        if (!is_efi_boot())
                return -EOPNOTSUPP;

        return efi_get_variable_id128(EFI_LOADER_VARIABLE_STR("LoaderDevicePartUUID"), ret);
}
