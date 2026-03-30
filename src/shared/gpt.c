/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gpt.h"
#include "util.h"

bool gpt_header_has_signature(const GptHeader *p) {
        assert(p);

        if (memcmp(p->signature, (const char[8]) { 'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T' }, 8) != 0)
                return false;

        if (le32toh(p->revision) != UINT32_C(0x00010000)) /* the only known revision of the spec: 1.0 */
                return false;

        if (le32toh(p->header_size) < sizeof(GptHeader))
                return false;

        if (le32toh(p->header_size) > 4096) /* larger than a sector? something is off… */
                return false;

        if (le64toh(p->my_lba) != 1) /* this sector must claim to be at sector offset 1 */
                return false;

        return true;
}

ssize_t gpt_probe(
                int fd,
                GptHeader *ret_header,
                void **ret_entries,
                uint32_t *ret_n_entries,
                uint32_t *ret_entry_size) {

        /* We expect a sector size in the range 512…4096. The GPT header is located in the second
         * sector. Hence it could be at byte 512 at the earliest, and at byte 4096 at the latest. And we must
         * read with granularity of the largest sector size we care about. Which means 8K. */
        uint8_t sectors[2 * 4096];
        const GptHeader *h;
        uint32_t found = 0, sz, entry_sz, entry_count;
        ssize_t n;

        assert(fd >= 0);

        /* Disk images might be for 512B or for 4096 sector sizes, let's try to auto-detect that by searching
         * for the GPT headers at the relevant byte offsets. */

        assert_cc(sizeof(GptHeader) == 92);

        n = pread(fd, sectors, sizeof(sectors), 0);
        if (n < 0)
                return -errno;
        if ((size_t) n < sizeof(sectors))
                return 0; /* too short */

        /* Let's see if we find the GPT partition header with various expected sector sizes */
        for (sz = 512; sz <= 4096; sz <<= 1) {
                const GptHeader *p = (const GptHeader *) (sectors + sz);

                if (!gpt_header_has_signature(p))
                        continue;

                if (found != 0)
                        return -ENOTUNIQ;

                found = sz;
        }

        if (found == 0)
                return 0;

        h = (const GptHeader *) (sectors + found);

        entry_sz = le32toh(h->size_of_partition_entry);
        entry_count = le32toh(h->number_of_partition_entries);

        if (ret_entries) {
                _cleanup_free_ void *entries = NULL;
                uint64_t entry_lba = le64toh(h->partition_entry_lba), entry_offset;
                size_t entries_size;

                if (entry_lba > (uint64_t) INT64_MAX / found)
                        return -EBADMSG;

                entry_offset = entry_lba * found;

                if (entry_sz < sizeof(GptPartitionEntry) || entry_count == 0 || entry_count > 1024)
                        return -EBADMSG;
                if (entry_sz > SIZE_MAX / entry_count)
                        return -EBADMSG;

                entries_size = (size_t) entry_sz * entry_count;
                entries = malloc(entries_size);
                if (!entries)
                        return -ENOMEM;

                n = pread(fd, entries, entries_size, entry_offset);
                if (n < 0)
                        return -errno;
                if ((size_t) n < entries_size)
                        return -EBADMSG;

                *ret_entries = TAKE_PTR(entries);
        }

        if (ret_header)
                *ret_header = *h;
        if (ret_n_entries)
                *ret_n_entries = entry_count;
        if (ret_entry_size)
                *ret_entry_size = entry_sz;

        return found; /* sector size */
}
