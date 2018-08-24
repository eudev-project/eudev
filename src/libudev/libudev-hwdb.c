/***
  This file is part of systemd.

  Copyright 2012 Kay Sievers <kay@vrfy.org>
  Copyright 2008 Alan Jenkins <alan.christopher.jenkins@googlemail.com>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <ctype.h>
#include <stdlib.h>
#include <fnmatch.h>
#include <getopt.h>
#include <sys/mman.h>

#include "libudev-private.h"
#include "libudev-hwdb-def.h"

/**
 * SECTION:libudev-hwdb
 * @short_description: retrieve properties from the hardware database
 *
 * Libudev hardware database interface.
 */

/**
 * udev_hwdb:
 *
 * Opaque object representing the hardware database.
 */
struct udev_hwdb {
        struct udev *udev;
        int refcount;

        char *bin_paths;
        FILE *f;
        struct stat st;
        union {
                struct trie_header_f *head;
                const char *map;
        };

        struct udev_list properties_list;
};

struct linebuf {
        char bytes[LINE_MAX];
        size_t size;
        size_t len;
};

static void linebuf_init(struct linebuf *buf) {
        buf->size = 0;
        buf->len = 0;
}

static const char *linebuf_get(struct linebuf *buf) {
        if (buf->len + 1 >= sizeof(buf->bytes))
                return NULL;
        buf->bytes[buf->len] = '\0';
        return buf->bytes;
}

static bool linebuf_add(struct linebuf *buf, const char *s, size_t len) {
        if (buf->len + len >= sizeof(buf->bytes))
                return false;
        memcpy(buf->bytes + buf->len, s, len);
        buf->len += len;
        return true;
}

static bool linebuf_add_char(struct linebuf *buf, char c)
{
        if (buf->len + 1 >= sizeof(buf->bytes))
                return false;
        buf->bytes[buf->len++] = c;
        return true;
}

static void linebuf_rem(struct linebuf *buf, size_t count) {
        assert(buf->len >= count);
        buf->len -= count;
}

static void linebuf_rem_char(struct linebuf *buf) {
        linebuf_rem(buf, 1);
}

static const struct trie_child_entry_f *trie_node_child(struct udev_hwdb *hwdb, const struct trie_node_f *node, size_t idx) {
        const char *base = (const char *)node;

        base += le64toh(hwdb->head->node_size);
        base += idx * le64toh(hwdb->head->child_entry_size);
        return (const struct trie_child_entry_f *)base;
}

static const struct trie_value_entry_f *trie_node_value(struct udev_hwdb *hwdb, const struct trie_node_f *node, size_t idx) {
        const char *base = (const char *)node;

        base += le64toh(hwdb->head->node_size);
        base += node->children_count * le64toh(hwdb->head->child_entry_size);
        base += idx * le64toh(hwdb->head->value_entry_size);
        return (const struct trie_value_entry_f *)base;
}

static const void *hwdb_at(struct udev_hwdb *hwdb, uint64_t off, uint64_t size) {
        uint64_t file_size = hwdb->st.st_size;

        /* off == file_size is rejected too: a read at EOF is always OOB, and this keeps the
         * boundary unambiguous even for a size == 0 caller (which would otherwise get a
         * one-past-the-end pointer). */
        if (off >= file_size)
                return NULL;
        if (file_size - off < size)
                return NULL;

        return (const uint8_t *) hwdb->map + off;
}

static const struct trie_node_f *trie_node_from_off(struct udev_hwdb *hwdb, le64_t off) {
        uint64_t offset = le64toh(off);
        uint64_t node_size = le64toh(hwdb->head->node_size);
        uint64_t child_entry_size = le64toh(hwdb->head->child_entry_size);
        uint64_t value_entry_size = le64toh(hwdb->head->value_entry_size);
        uint64_t children_bytes, values_bytes, values_count, total;
        const struct trie_node_f *node;

        if (node_size < sizeof(struct trie_node_f))
                return NULL;
        if (child_entry_size < sizeof(struct trie_child_entry_f))
                return NULL;
        if (value_entry_size < sizeof(struct trie_value_entry_f))
                return NULL;

        node = hwdb_at(hwdb, offset, node_size);
        if (!node)
                return NULL;

        /* make sure that the arrays of children and values appended to the node are within the file */
        children_bytes = (uint64_t) node->children_count * child_entry_size;
        values_count = le64toh(node->values_count);
        if (value_entry_size != 0 && values_count > UINT64_MAX / value_entry_size)
                return NULL;
        values_bytes = values_count * value_entry_size;
        if (children_bytes > UINT64_MAX - node_size)
                return NULL;
        total = node_size + children_bytes;
        if (values_bytes > UINT64_MAX - total)
                return NULL;
        total += values_bytes;

        if (!hwdb_at(hwdb, offset, total))
                return NULL;

        return node;
}

static const char *trie_string(struct udev_hwdb *hwdb, le64_t off) {
        uint64_t file_size = hwdb->st.st_size;
        uint64_t offset = le64toh(off);
        const char *p;
        size_t avail;

        p = hwdb_at(hwdb, offset, 1);
        if (!p)
                return NULL;

        /* Clamp to SIZE_MAX so memchr()'s size_t arg cannot truncate on 32-bit. */
        avail = (size_t) MIN(file_size - offset, (uint64_t) SIZE_MAX);
        if (!memchr(p, '\0', avail))
                return NULL;

        return p;
}

static int trie_children_cmp_f(const void *v1, const void *v2) {
        const struct trie_child_entry_f *n1 = v1;
        const struct trie_child_entry_f *n2 = v2;

        return n1->c - n2->c;
}

static const struct trie_node_f *node_lookup_f(struct udev_hwdb *hwdb, const struct trie_node_f *node, uint8_t c) {
        struct trie_child_entry_f *child;
        struct trie_child_entry_f search;

        search.c = c;
        child = bsearch(&search, (const char *)node + le64toh(hwdb->head->node_size), node->children_count,
                        le64toh(hwdb->head->child_entry_size), trie_children_cmp_f);
        if (child)
                /* Treat corrupt child offsets like lookup misses. */
                return trie_node_from_off(hwdb, child->child_off);
        return NULL;
}

static int hwdb_add_property(struct udev_hwdb *hwdb, const struct trie_value_entry_f *entry) {
        struct udev_list_entry *list_entry;
        const char *key, *value;
        size_t entry_off;

        key = trie_string(hwdb, entry->key_off);
        if (!key)
                return -EBADMSG;

        /*
         * Silently ignore all properties which do not start with a
         * space; future extensions might use additional prefixes.
         */
        if (key[0] != ' ')
                return 0;

        key++;

        /* the offset of the entry is remembered in the list entry, to be
         * able to compare the origin of duplicate properties */
        entry_off = (const char *)entry - hwdb->map;

        if (le64toh(hwdb->head->value_entry_size) >= sizeof(struct trie_value_entry2_f) &&
            entry_off <= INT_MAX) {
                const struct trie_value_entry2_f *old, *entry2;

                entry2 = (const struct trie_value_entry2_f *)entry;
                list_entry = udev_list_entry_get_by_name(udev_list_get_entry(&hwdb->properties_list), key);
                if (list_entry && udev_list_entry_get_num(list_entry) > 0) {
                        /* On duplicates, we order by filename priority and line-number.
                         *
                         * v2 of the format had 64 bits for the line number.
                         * v3 reuses top 32 bits of line_number to store the priority.
                         * We check the top bits — if they are zero we have v2 format.
                         * This means that v2 clients will print wrong line numbers with
                         * v3 data.
                         *
                         * For v3 data: we compare the priority (of the source file)
                         * and the line number.
                         *
                         * For v2 data: we rely on the fact that the filenames in the hwdb
                         * are added in the order of priority (higher later), because they
                         * are *processed* in the order of priority. So we compare the
                         * indices to determine which file had higher priority. Comparing
                         * the strings alphabetically would be useless, because those are
                         * full paths, and e.g. /usr/lib would sort after /etc, even
                         * though it has lower priority. This is not reliable because of
                         * suffix compression, but should work for the most common case of
                         * /usr/lib/udev/hwbd.d and /etc/udev/hwdb.d, and is better than
                         * not doing the comparison at all.
                         */
                        bool lower;

                        old = (const struct trie_value_entry2_f *)(hwdb->map + udev_list_entry_get_num(list_entry));
                        if (le16toh(entry2->file_priority) == 0)
                                lower = le64toh(entry2->filename_off) < le64toh(old->filename_off) ||
                                        (entry2->filename_off == old->filename_off &&
                                         le32toh(entry2->line_number) < le32toh(old->line_number));
                        else
                                lower = le16toh(entry2->file_priority) < le16toh(old->file_priority) ||
                                        (entry2->file_priority == old->file_priority &&
                                         le32toh(entry2->line_number) < le32toh(old->line_number));
                        if (lower)
                                return 0;
                }
        }

        value = trie_string(hwdb, entry->value_off);
        if (!value)
                return -EBADMSG;

        list_entry = udev_list_entry_add(&hwdb->properties_list, key, value);
        if (list_entry == NULL)
                return -ENOMEM;
        udev_list_entry_set_num(list_entry, entry_off <= INT_MAX ? (int)entry_off : 0);
        return 0;
}

/* Cap recursion depth so a corrupt hwdb.bin whose children offsets form a
 * cycle (or just a deep linear chain) cannot exhaust the stack. Real-world
 * hwdb files do not approach this; the deepest legitimate trie key is well
 * under a kilobyte. */
#define HWDB_RECURSION_MAX 2048U

static int trie_fnmatch_f(struct udev_hwdb *hwdb, const struct trie_node_f *node, size_t p,
                          struct linebuf *buf, const char *search, unsigned depth) {
        size_t len;
        size_t i;
        const char *prefix;
        int err;

        if (depth >= HWDB_RECURSION_MAX)
                return -EBADMSG;

        prefix = trie_string(hwdb, node->prefix_off);
        if (!prefix)
                return -EBADMSG;

        len = strlen(prefix);
        if (p > len)
                return -EBADMSG;
        len -= p;

        if (!linebuf_add(buf, prefix + p, len))
                return -EINVAL;

        for (i = 0; i < node->children_count; i++) {
                const struct trie_child_entry_f *child = trie_node_child(hwdb, node, i);
                const struct trie_node_f *child_node;

                if (!linebuf_add_char(buf, child->c))
                        return -EINVAL;
                child_node = trie_node_from_off(hwdb, child->child_off);
                if (!child_node)
                        return -EBADMSG;

                err = trie_fnmatch_f(hwdb, child_node, 0, buf, search, depth + 1);
                if (err < 0)
                        return err;
                linebuf_rem_char(buf);
        }

        if (le64toh(node->values_count) != 0) {
                const char *line = linebuf_get(buf);
                if (!line)
                        return -EBADMSG;

                if (fnmatch(line, search, 0) == 0)
                        for (i = 0; i < le64toh(node->values_count); i++) {
                                err = hwdb_add_property(hwdb, trie_node_value(hwdb, node, i));
                                if (err < 0)
                                        return err;
                        }
        }

        linebuf_rem(buf, len);
        return 0;
}

static int trie_search_f(struct udev_hwdb *hwdb, const char *search) {
        struct linebuf buf;
        const struct trie_node_f *node;
        size_t i = 0;
        int err;

        linebuf_init(&buf);

        node = trie_node_from_off(hwdb, hwdb->head->nodes_root_off);
        if (!node)
                return -EBADMSG;

        while (node) {
                const struct trie_node_f *child;
                size_t p = 0;

                if (node->prefix_off) {
                        const char *prefix;
                        char c;

                        prefix = trie_string(hwdb, node->prefix_off);
                        if (!prefix)
                                return -EBADMSG;

                        for (; (c = prefix[p]); p++) {
                                if (c == '*' || c == '?' || c == '[')
                                        return trie_fnmatch_f(hwdb, node, p, &buf, search + i + p, 0);
                                if (c != search[i + p])
                                        return 0;
                        }
                        i += p;
                }

                child = node_lookup_f(hwdb, node, '*');
                if (child) {
                        linebuf_add_char(&buf, '*');
                        err = trie_fnmatch_f(hwdb, child, 0, &buf, search + i, 0);
                        if (err < 0)
                                return err;
                        linebuf_rem_char(&buf);
                }

                child = node_lookup_f(hwdb, node, '?');
                if (child) {
                        linebuf_add_char(&buf, '?');
                        err = trie_fnmatch_f(hwdb, child, 0, &buf, search + i, 0);
                        if (err < 0)
                                return err;
                        linebuf_rem_char(&buf);
                }

                child = node_lookup_f(hwdb, node, '[');
                if (child) {
                        linebuf_add_char(&buf, '[');
                        err = trie_fnmatch_f(hwdb, child, 0, &buf, search + i, 0);
                        if (err < 0)
                                return err;
                        linebuf_rem_char(&buf);
                }

                if (search[i] == '\0') {
                        size_t n;

                        for (n = 0; n < le64toh(node->values_count); n++) {
                                err = hwdb_add_property(hwdb, trie_node_value(hwdb, node, n));
                                if (err < 0)
                                        return err;
                        }
                        return 0;
                }

                child = node_lookup_f(hwdb, node, search[i]);
                node = child;
                i++;
        }
        return 0;
}

static char *get_hwdb_bin_paths (void) {
        static const char default_locations[] =
          "/etc/udev/hwdb.bin\0"
          UDEV_LIBEXEC_DIR "/hwdb.bin\0";
        const char *by_env = getenv("UDEV_HWDB_BIN");
        if (by_env != NULL) {
                char *path = malloc(strlen(by_env) + 1
                                    + sizeof (default_locations));
                if (path != NULL) {
                        memcpy(path, by_env, strlen(by_env) + 1);
                        memcpy(path + strlen(by_env) + 1,
                               default_locations,
                               sizeof (default_locations));
                }
                return path;
        }
        char *path = malloc(sizeof (default_locations));
        if (path != NULL) {
                memcpy(path, default_locations, sizeof (default_locations));
        }
        return path;
}

/**
 * udev_hwdb_new:
 * @udev: udev library context
 *
 * Create a hardware database context to query properties for devices.
 *
 * Returns: a hwdb context.
 **/
_public_ struct udev_hwdb *udev_hwdb_new(struct udev *udev) {
        struct udev_hwdb *hwdb;
        const char *hwdb_bin_path;
        const char sig[] = HWDB_SIG;

        hwdb = new0(struct udev_hwdb, 1);
        if (!hwdb)
                return NULL;

        hwdb->refcount = 1;
        udev_list_init(udev, &hwdb->properties_list, true);

        /* find hwdb.bin in hwdb_bin_paths */
        hwdb->bin_paths = get_hwdb_bin_paths();
        if (hwdb->bin_paths == NULL) {
                udev_hwdb_unref(hwdb);
                return NULL;
        }
        NULSTR_FOREACH(hwdb_bin_path, hwdb->bin_paths) {
                hwdb->f = fopen(hwdb_bin_path, "re");
                if (hwdb->f)
                        break;
                else if (errno == ENOENT)
                        continue;
                else {
                        log_debug("error reading %s", hwdb_bin_path);
                        udev_hwdb_unref(hwdb);
                        return NULL;
                }
        }

        if (!hwdb->f) {
                log_debug("%s does not exist, please run udevadm hwdb --update", hwdb_bin_path);
                udev_hwdb_unref(hwdb);
                return NULL;
        }

        if (fstat(fileno(hwdb->f), &hwdb->st) < 0 ||
            (size_t)hwdb->st.st_size < offsetof(struct trie_header_f, strings_len) + 8) {
                log_debug_errno(errno, "error reading %s: %m", hwdb_bin_path);
                udev_hwdb_unref(hwdb);
                return NULL;
        }

        hwdb->map = mmap(0, hwdb->st.st_size, PROT_READ, MAP_SHARED, fileno(hwdb->f), 0);
        if (hwdb->map == MAP_FAILED) {
                log_debug_errno(errno, "error mapping %s: %m", hwdb_bin_path);
                udev_hwdb_unref(hwdb);
                return NULL;
        }

        if (memcmp(hwdb->map, sig, sizeof(hwdb->head->signature)) != 0 ||
            (size_t)hwdb->st.st_size != le64toh(hwdb->head->file_size)) {
                log_debug("error recognizing the format of %s", hwdb_bin_path);
                udev_hwdb_unref(hwdb);
                return NULL;
        }

        log_debug("=== trie on-disk ===");
        log_debug("tool version:          %"PRIu64, le64toh(hwdb->head->tool_version));
        log_debug("file size:        %8"PRIu64" bytes", hwdb->st.st_size);
        log_debug("header size       %8"PRIu64" bytes", le64toh(hwdb->head->header_size));
        log_debug("strings           %8"PRIu64" bytes", le64toh(hwdb->head->strings_len));
        log_debug("nodes             %8"PRIu64" bytes", le64toh(hwdb->head->nodes_len));
        return hwdb;
}

/**
 * udev_hwdb_ref:
 * @hwdb: context
 *
 * Take a reference of a hwdb context.
 *
 * Returns: the passed enumeration context
 **/
_public_ struct udev_hwdb *udev_hwdb_ref(struct udev_hwdb *hwdb) {
        if (!hwdb)
                return NULL;
        hwdb->refcount++;
        return hwdb;
}

/**
 * udev_hwdb_unref:
 * @hwdb: context
 *
 * Drop a reference of a hwdb context. If the refcount reaches zero,
 * all resources of the hwdb context will be released.
 *
 * Returns: #NULL
 **/
_public_ struct udev_hwdb *udev_hwdb_unref(struct udev_hwdb *hwdb) {
        if (!hwdb)
                return NULL;
        hwdb->refcount--;
        if (hwdb->refcount > 0)
                return NULL;
        if (hwdb->map)
                munmap((void *)hwdb->map, hwdb->st.st_size);
        free(hwdb->bin_paths);
        if (hwdb->f)
                fclose(hwdb->f);
        udev_list_cleanup(&hwdb->properties_list);
        free(hwdb);
        return NULL;
}

bool udev_hwdb_validate(struct udev_hwdb *hwdb) {
        bool found = false;
        const char* p;
        struct stat st;

        if (!hwdb)
                return false;
        if (!hwdb->f)
                return false;

        /* if hwdb.bin doesn't exist anywhere, we need to update */
        NULSTR_FOREACH(p, hwdb->bin_paths) {
                if (stat(p, &st) >= 0) {
                        found = true;
                        break;
                }
        }

        if (!found)
                return true;

        if (timespec_load(&hwdb->st.st_mtim) != timespec_load(&st.st_mtim))
                return true;
        return false;
}

/**
 * udev_hwdb_get_properties_list_entry:
 * @hwdb: context
 * @modalias: modalias string
 * @flags: (unused)
 *
 * Lookup a matching device in the hardware database. The lookup key is a
 * modalias string, whose formats are defined for the Linux kernel modules.
 * Examples are: pci:v00008086d00001C2D*, usb:v04F2pB221*. The first entry
 * of a list of retrieved properties is returned.
 *
 * Returns: a udev_list_entry.
 */
_public_ struct udev_list_entry *udev_hwdb_get_properties_list_entry(struct udev_hwdb *hwdb, const char *modalias, unsigned int flags __attribute__((unused))) {
        int err;

        if (!hwdb || !hwdb->f || !modalias) {
                errno = EINVAL;
                return NULL;
        }

        udev_list_cleanup(&hwdb->properties_list);
        err = trie_search_f(hwdb, modalias);
        if (err < 0) {
                errno = -err;
                return NULL;
        }
        return udev_list_get_entry(&hwdb->properties_list);
}
