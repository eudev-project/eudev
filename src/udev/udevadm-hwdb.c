/***
  This file is part of systemd.

  Copyright 2012 Kay Sievers <kay@vrfy.org>

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

#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#include "util.h"
#include "strbuf.h"
#include "conf-files.h"

#include "udev.h"
#include "libudev-hwdb-def.h"

/*
 * Generic udev properties, key/value database based on modalias strings.
 * Uses a Patricia/radix trie to index all matches for efficient lookup.
 */

static const char * const conf_file_dirs[] = {
        UDEV_HWDB_DIR,
        UDEV_LIBEXEC_DIR "/hwdb.d",
        NULL
};

/* in-memory trie objects */
struct trie {
        struct trie_node *root;
        struct strbuf *strings;

        size_t nodes_count;
        size_t children_count;
        size_t values_count;
};

struct trie_node {
        /* prefix, common part for all children of this node */
        size_t prefix_off;

        /* sorted array of pointers to children nodes */
        struct trie_child_entry *children;
        uint8_t children_count;

        /* sorted array of key/value pairs */
        struct trie_value_entry *values;
        size_t values_count;
};

/* children array item with char (0-255) index */
struct trie_child_entry {
        uint8_t c;
        struct trie_node *child;
};

/* value array item with key/value pairs */
struct trie_value_entry {
        size_t key_off;
        size_t value_off;
};

static int trie_children_cmp(const void *v1, const void *v2) {
        const struct trie_child_entry *n1 = v1;
        const struct trie_child_entry *n2 = v2;

        return n1->c - n2->c;
}

static int node_add_child(struct trie *trie, struct trie_node *node, struct trie_node *node_child, uint8_t c) {
        struct trie_child_entry *child;
        int err = 0;

        /* extend array, add new entry, sort for bisection */
        child = realloc(node->children, (node->children_count + 1) * sizeof(struct trie_child_entry));
        if (!child) {
                err = -ENOMEM;
                goto out;
        }
        node->children = child;
        trie->children_count++;
        node->children[node->children_count].c = c;
        node->children[node->children_count].child = node_child;
        node->children_count++;
        qsort(node->children, node->children_count, sizeof(struct trie_child_entry), trie_children_cmp);
        trie->nodes_count++;
out:
        return err;
}

static struct trie_node *node_lookup(const struct trie_node *node, uint8_t c) {
        struct trie_child_entry *child;
        struct trie_child_entry search;

        search.c = c;
        child = bsearch(&search, node->children, node->children_count, sizeof(struct trie_child_entry), trie_children_cmp);
        if (child)
                return child->child;
        return NULL;
}

static void trie_node_cleanup(struct trie_node *node) {
        size_t i;

        for (i = 0; i < node->children_count; i++)
                trie_node_cleanup(node->children[i].child);
        free(node->children);
        free(node->values);
        free(node);
}

static int trie_values_cmp(const void *v1, const void *v2, void *arg) {
        const struct trie_value_entry *val1 = v1;
        const struct trie_value_entry *val2 = v2;
        struct trie *trie = arg;

        return strcmp(trie->strings->buf + val1->key_off,
                      trie->strings->buf + val2->key_off);
}

static int trie_node_add_value(struct trie *trie, struct trie_node *node,
                          const char *key, const char *value) {
        ssize_t k, v;
        struct trie_value_entry *val;

        k = strbuf_add_string(trie->strings, key, strlen(key));
        if (k < 0)
                return k;
        v = strbuf_add_string(trie->strings, value, strlen(value));
        if (v < 0)
                return v;

        if (node->values_count) {
                struct trie_value_entry search = {
                        .key_off = k,
                        .value_off = v,
                };

                val = xbsearch_r(&search, node->values, node->values_count, sizeof(struct trie_value_entry), trie_values_cmp, trie);
                if (val) {
                        /* replace existing earlier key with new value */
                        val->value_off = v;
                        return 0;
                }
        }

        /* extend array, add new entry, sort for bisection */
        val = realloc(node->values, (node->values_count + 1) * sizeof(struct trie_value_entry));
        if (!val)
                return -ENOMEM;
        trie->values_count++;
        node->values = val;
        node->values[node->values_count].key_off = k;
        node->values[node->values_count].value_off = v;
        node->values_count++;
        qsort_r(node->values, node->values_count, sizeof(struct trie_value_entry), trie_values_cmp, trie);
        return 0;
}

static int trie_insert(struct trie *trie, struct trie_node *node, const char *search,
                       const char *key, const char *value) {
        size_t i = 0;
        int err = 0;

        for (;;) {
                size_t p;
                uint8_t c;
                struct trie_node *child;

                for (p = 0; (c = trie->strings->buf[node->prefix_off + p]); p++) {
                        char *s;
                        ssize_t off;

                        if (c == search[i + p])
                                continue;

                        /* split node */
                        child = calloc(sizeof(struct trie_node), 1);
                        if (!child) {
                                err = -ENOMEM;
                                goto out;
                        }

                        /* move values from parent to child */
                        child->prefix_off = node->prefix_off + p+1;
                        child->children = node->children;
                        child->children_count = node->children_count;
                        child->values = node->values;
                        child->values_count = node->values_count;

                        /* update parent; use strdup() because the source gets realloc()d */
                        s = strndup(trie->strings->buf + node->prefix_off, p);
                        if (!s) {
                                err = -ENOMEM;
                                goto out;
                        }
                        off = strbuf_add_string(trie->strings, s, p);
                        free(s);
                        if (off < 0) {
                                err = off;
                                goto out;
                        }
                        node->prefix_off = off;
                        node->children = NULL;
                        node->children_count = 0;
                        node->values = NULL;
                        node->values_count = 0;
                        err = node_add_child(trie, node, child, c);
                        if (err)
                                goto out;
                        break;
                }
                i += p;

                c = search[i];
                if (c == '\0')
                        return trie_node_add_value(trie, node, key, value);

                child = node_lookup(node, c);
                if (!child) {
                        ssize_t off;

                        /* new child */
                        child = calloc(sizeof(struct trie_node), 1);
                        if (!child) {
                                err = -ENOMEM;
                                goto out;
                        }
                        off = strbuf_add_string(trie->strings, search + i+1, strlen(search + i+1));
                        if (off < 0) {
                                err = off;
                                goto out;
                        }
                        child->prefix_off = off;
                        err = node_add_child(trie, node, child, c);
                        if (err)
                                goto out;
                        return trie_node_add_value(trie, child, key, value);
                }

                node = child;
                i++;
        }
out:
        return err;
}

struct trie_f {
        FILE *f;
        struct trie *trie;
        uint64_t strings_off;

        uint64_t nodes_count;
        uint64_t children_count;
        uint64_t values_count;
};

/* calculate the storage space for the nodes, children arrays, value arrays */
static void trie_store_nodes_size(struct trie_f *trie, struct trie_node *node) {
        uint64_t i;

        for (i = 0; i < node->children_count; i++)
                trie_store_nodes_size(trie, node->children[i].child);

        trie->strings_off += sizeof(struct trie_node_f);
        for (i = 0; i < node->children_count; i++)
                trie->strings_off += sizeof(struct trie_child_entry_f);
        for (i = 0; i < node->values_count; i++)
                trie->strings_off += sizeof(struct trie_value_entry_f);
}

static int64_t trie_store_nodes(struct trie_f *trie, struct trie_node *node) {
        uint64_t i;
        struct trie_node_f n = {
                .prefix_off = htole64(trie->strings_off + node->prefix_off),
                .children_count = node->children_count,
                .values_count = htole64(node->values_count),
        };
        struct trie_child_entry_f *children = NULL;
        int64_t node_off;

        if (node->children_count) {
                children = new0(struct trie_child_entry_f, node->children_count);
                if (!children)
                        return -ENOMEM;
        }

        /* post-order recursion */
        for (i = 0; i < node->children_count; i++) {
                int64_t child_off;

                child_off = trie_store_nodes(trie, node->children[i].child);
                if (child_off < 0)
                        return child_off;
                children[i].c = node->children[i].c;
                children[i].child_off = htole64(child_off);
        }

        /* write node */
        node_off = ftello(trie->f);
        if (fwrite(&n, sizeof(struct trie_node_f), 1, trie->f) != 1)
                log_error("Failed to write sizeof struct trie_node_f to n in %s\n", "[udevadm-hwdb.c:trie_store_nodes]");
        trie->nodes_count++;

        /* append children array */
        if (node->children_count) {
                if (fwrite(children, sizeof(struct trie_child_entry_f), node->children_count, trie->f) != node->children_count)
                        log_error("Failed to write children_count in %s\n", "[udevadm-hwdb.c:trie_store_nodes]");
                trie->children_count += node->children_count;
                free(children);
        }

        /* append values array */
        for (i = 0; i < node->values_count; i++) {
                struct trie_value_entry_f v = {
                        .key_off = htole64(trie->strings_off + node->values[i].key_off),
                        .value_off = htole64(trie->strings_off + node->values[i].value_off),
                };

                if (fwrite(&v, sizeof(struct trie_value_entry_f), 1, trie->f) != 1)
                        log_error("Failed to write sizeof trie_value_entry_f to v in %s\n", "[udevadm-hwdb.c:trie_store_nodes]");
                trie->values_count++;
        }

        return node_off;
}

static int trie_store(struct trie *trie, const char *filename) {
        struct trie_f t = {
                .trie = trie,
        };
        char *filename_tmp;
        int64_t pos;
        int64_t root_off;
        int64_t size;
        struct trie_header_f h = {
                .signature = HWDB_SIG,
                .tool_version = htole64(atoi(VERSION)),
                .header_size = htole64(sizeof(struct trie_header_f)),
                .node_size = htole64(sizeof(struct trie_node_f)),
                .child_entry_size = htole64(sizeof(struct trie_child_entry_f)),
                .value_entry_size = htole64(sizeof(struct trie_value_entry_f)),
        };
        int err;

        /* calculate size of header, nodes, children entries, value entries */
        t.strings_off = sizeof(struct trie_header_f);
        trie_store_nodes_size(&t, trie->root);

        err = fopen_temporary(filename , &t.f, &filename_tmp);
        if (err < 0)
                return err;
        fchmod(fileno(t.f), 0444);

        /* write nodes */
        fseeko(t.f, sizeof(struct trie_header_f), SEEK_SET);
        root_off = trie_store_nodes(&t, trie->root);
        h.nodes_root_off = htole64(root_off);
        pos = ftello(t.f);
        h.nodes_len = htole64(pos - sizeof(struct trie_header_f));

        /* write string buffer */
        if (fwrite(trie->strings->buf, trie->strings->len, 1, t.f) != 1)
                log_error("Failed to write into trie->strings->buf in %s\n", "[udevadm-hwdb.c:trie_store]");
        h.strings_len = htole64(trie->strings->len);

        /* write header */
        size = ftello(t.f);
        h.file_size = htole64(size);
        fseeko(t.f, 0, SEEK_SET);
        if (fwrite(&h, sizeof(struct trie_header_f), 1, t.f) != 1)
                log_error("Failed to write into h in %s\n", "[udevadm-hwdb.c:trie_store]");
        err = ferror(t.f);
        if (err)
                err = -errno;
        fclose(t.f);
        if (err < 0 || rename(filename_tmp, filename) < 0) {
                unlink(filename_tmp);
                goto out;
        }

        log_debug("=== trie on-disk ===\n");
        log_debug("size:             %8llu bytes\n", (unsigned long long)size);
        log_debug("header:           %8zu bytes\n", sizeof(struct trie_header_f));
        log_debug("nodes:            %8llu bytes (%8llu)\n",
                  (unsigned long long)t.nodes_count * sizeof(struct trie_node_f), (unsigned long long)t.nodes_count);
        log_debug("child pointers:   %8llu bytes (%8llu)\n",
                  (unsigned long long)t.children_count * sizeof(struct trie_child_entry_f), (unsigned long long)t.children_count);
        log_debug("value pointers:   %8llu bytes (%8llu)\n",
                  (unsigned long long)t.values_count * sizeof(struct trie_value_entry_f), (unsigned long long)t.values_count);
        log_debug("string store:     %8llu bytes\n", (unsigned long long)trie->strings->len);
        log_debug("strings start:    %8llu\n", (unsigned long long) t.strings_off);
out:
        free(filename_tmp);
        return err;
}

static int import_file(struct trie *trie, const char *filename) {
        FILE *f;
        char line[LINE_MAX];
        char match[LINE_MAX];
        char cond[LINE_MAX];

        f = fopen(filename, "re");
        if (f == NULL)
                return -errno;

        match[0] = '\0';
        cond[0] = '\0';
        while (fgets(line, sizeof(line), f)) {
                size_t len;

                if (line[0] == '#')
                        continue;

                /* new line, new record */
                if (line[0] == '\n') {
                        match[0] = '\0';
                        cond[0] = '\0';
                        continue;
                }

                /* remove newline */
                len = strlen(line);
                if (len < 2)
                        continue;
                line[len-1] = '\0';

                /* start of new record */
                if (match[0] == '\0') {
                        strcpy(match, line);
                        cond[0] = '\0';
                        continue;
                }

                if (line[0] == '+') {
                        strcpy(cond, line);
                        continue;
                }

                /* TODO: support +; skip the entire record until we support it */
                if (cond[0] != '\0')
                        continue;

                /* value lines */
                if (line[0] == ' ') {
                        char *value;

                        value = strchr(line, '=');
                        if (!value)
                                continue;
                        value[0] = '\0';
                        value++;
                        trie_insert(trie, trie->root, match, line, value);
                }
        }
        fclose(f);
        return 0;
}

static void help(void) {
        printf("Usage: udevadm hwdb [--create] [--help] [--root <root_path>]\n"
               "  --update            update the hardware database\n"
               "  --test <modalias>   query database and print result\n"
               "  --help\n\n");
}

static int adm_hwdb(struct udev *udev, int argc, char *argv[]) {
        static const struct option options[] = {
                { "update", no_argument, NULL, 'u' },
                { "root", required_argument, NULL, 'r' },
                { "test", required_argument, NULL, 't' },
                { "help", no_argument, NULL, 'h' },
                {}
        };
        const char *test = NULL, *root_path = NULL;
        char *udev_hwdb_path = UDEV_HWDB_BIN;
        bool update = false;
        struct trie *trie = NULL;
        int err;
        int rc = EXIT_SUCCESS;

        for (;;) {
                int option;

                option = getopt_long(argc, argv, "ut:r:h", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 'u':
                        update = true;
                        break;
                case 't':
                        test = optarg;
                        break;
                case 'r':
                        root_path = optarg;
                        break;
                case 'h':
                        help();
                        return EXIT_SUCCESS;
                }
        }

        if (!update && !test) {
                help();
                return EXIT_SUCCESS;
        }

        if (update) {
                char **files, **f;

                trie = calloc(sizeof(struct trie), 1);
                if (!trie) {
                        rc = EXIT_FAILURE;
                        goto out;
                }

                /* string store */
                trie->strings = strbuf_new();
                if (!trie->strings) {
                        rc = EXIT_FAILURE;
                        goto out;
                }

                /* index */
                trie->root = calloc(sizeof(struct trie_node), 1);
                if (!trie->root) {
                        rc = EXIT_FAILURE;
                        goto out;
                }
                trie->nodes_count++;

                err = conf_files_list_strv(&files, root_path, ".hwdb", (const char **)conf_file_dirs);
                if (err < 0) {
                        log_error("failed to enumerate hwdb files: %s\n", strerror(-err));
                        rc = EXIT_FAILURE;
                        goto out;
                }
                STRV_FOREACH(f, files) {
                        log_debug("reading file '%s'", *f);
                        import_file(trie, *f);
                }
                strv_free(files);

                strbuf_complete(trie->strings);

                log_debug("=== trie in-memory ===\n");
                log_debug("nodes:            %8zu bytes (%8zu)\n",
                          trie->nodes_count * sizeof(struct trie_node), trie->nodes_count);
                log_debug("children arrays:  %8zu bytes (%8zu)\n",
                          trie->children_count * sizeof(struct trie_child_entry), trie->children_count);
                log_debug("values arrays:    %8zu bytes (%8zu)\n",
                          trie->values_count * sizeof(struct trie_value_entry), trie->values_count);
                log_debug("strings:          %8zu bytes\n",
                          trie->strings->len);
                log_debug("strings incoming: %8zu bytes (%8zu)\n",
                          trie->strings->in_len, trie->strings->in_count);
                log_debug("strings dedup'ed: %8zu bytes (%8zu)\n",
                          trie->strings->dedup_len, trie->strings->dedup_count);

                if (root_path) {
                    if (asprintf(&udev_hwdb_path,
                                 "%s/%s", root_path, udev_hwdb_path) < 0) {
                        rc = EXIT_FAILURE;
                        goto out;
                    }
                }

                mkdir_parents(udev_hwdb_path, 0755);
                err = trie_store(trie, udev_hwdb_path);

                if (root_path) {
                    free(udev_hwdb_path);
                }

                if (err < 0) {
                        log_error("Failure writing hardware database '%s': %s",
                        udev_hwdb_path, strerror(-err));
                        rc = EXIT_FAILURE;
                }
        }

        if (test) {
                struct udev_hwdb *hwdb = udev_hwdb_new(udev);

                if (hwdb) {
                        struct udev_list_entry *entry;

                        udev_list_entry_foreach(entry, udev_hwdb_get_properties_list_entry(hwdb, test, 0))
                                printf("%s=%s\n", udev_list_entry_get_name(entry), udev_list_entry_get_value(entry));
                        hwdb = udev_hwdb_unref(hwdb);
                }
        }
out:
        if (trie) {
                if (trie->root)
                        trie_node_cleanup(trie->root);
                strbuf_cleanup(trie->strings);
                free(trie);
        }
        return rc;
}

const struct udevadm_cmd udevadm_hwdb = {
        .name = "hwdb",
        .cmd = adm_hwdb,
        .help = "maintain the hardware database index",
};
