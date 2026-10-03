/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Tests of the helper program collect: the parsing of its checkpoint file by checkout(), and the refusal of
 * a too long path of the checkpoint file by prepare().
 *
 * A NUL byte after a separator made checkout() move its pointer before the start of its buffer and read
 * there (heap-buffer-overflow with AddressSanitizer), and a NUL byte after a word made it drop the rest of
 * the file. When the buffer grew for a long ID, the IDs before it were added twice.
 */

/* the functions of collect, which are static, with its main() renamed */
#define main collect_main
#include "../src/collect/collect.c"
#undef main

static int test_checkout(const char *name, const char *content, size_t size, const char *expected) {
        _cleanup_free_ char *words = NULL;
        struct udev_list_node *him_node;
        FILE *f;
        int r;

        udev_list_node_init(&bunch);
        bufsize = BUFSIZE;

        f = tmpfile();
        if (!f || fwrite(content, 1, size, f) != size || fflush(f) != 0 || lseek(fileno(f), 0, SEEK_SET) < 0) {
                fprintf(stderr, "%s: cannot write the checkpoint file: %m\n", name);
                return -1;
        }

        r = checkout(fileno(f));
        fclose(f);
        if (r < 0) {
                fprintf(stderr, "%s: checkout() failed: %s\n", name, strerror(-r));
                kickall();
                return -1;
        }

        words = strdup("");
        if (!words)
                return log_oom();
        udev_list_node_foreach(him_node, &bunch) {
                struct _mate *him = node_to_mate(him_node);
                char *s;

                s = strjoin(words, *words ? " " : "", him->name, NULL);
                if (!s)
                        return log_oom();
                free(words);
                words = s;
        }
        kickall();

        if (!streq(words, expected)) {
                fprintf(stderr, "%s: got \"%s\", expected \"%s\"\n", name, words, expected);
                return -1;
        }

        printf("%s: \"%s\"\n", name, words);
        return 0;
}

#define TEST_CHECKOUT(name, content, expected) test_checkout(name, content, sizeof(content) - 1, expected)

int main(void) {
        char dir[] = "/tmp/test-collect.XXXXXX";
        char longname[UTIL_PATH_SIZE + 1];
        int r = 0, fd;

        r |= TEST_CHECKOUT("empty", "", "");
        r |= TEST_CHECKOUT("plain", "aaaa bbbb cccc\n", "aaaa bbbb cccc");
        r |= TEST_CHECKOUT("separators", " \t aaaa\n\nbbbb\r\ncccc  ", "aaaa bbbb cccc");
        r |= TEST_CHECKOUT("long word after short ones, the buffer grows",
                           "aa bb cccccccccccccccccccccccccccccccccccccccc dd\n",
                           "aa bb cccccccccccccccccccccccccccccccccccccccc dd");
        r |= TEST_CHECKOUT("word longer than the buffer",
                           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bb cc\n",
                           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bb cc");
        /* the files of the static analysis that showed the bug */
        r |= TEST_CHECKOUT("NUL after a separator",
                           "aaa bb \0ccc ddd eee fff ggg hhh iii jjj kkk lll\n",
                           "aaa bb ccc ddd eee fff ggg hhh iii jjj kkk lll");
        r |= TEST_CHECKOUT("NUL after a word",
                           "aaaa bbbb cccc dd\0eeeeeeee ffff gggg hhhh iiii jjjj\n",
                           "aaaa bbbb cccc dd eeeeeeee ffff gggg hhhh iiii jjjj");
        r |= TEST_CHECKOUT("NUL bytes only", "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", "");
        r |= TEST_CHECKOUT("NUL bytes at every position", "a\0b\0\0cc\0\0\0ddd\0\0\0\0eeee\0", "a b cc ddd eeee");

        /* prepare() refuses a path that does not fit, with a message */
        if (!mkdtemp(dir)) {
                fprintf(stderr, "cannot create a directory: %m\n");
                return EXIT_FAILURE;
        }
        memset(longname, 'x', sizeof(longname) - 1);
        longname[sizeof(longname) - 1] = '\0';
        fd = prepare(dir, longname);
        if (fd >= 0) {
                fprintf(stderr, "prepare() accepted a path of %zu characters\n", strlen(dir) + 1 + strlen(longname));
                close(fd);
                r = -1;
        } else
                printf("too long path: refused\n");
        fd = prepare(dir, (char *) "checkpoint");
        if (fd < 0) {
                fprintf(stderr, "prepare() refused a short path\n");
                r = -1;
        } else {
                printf("short path: accepted\n");
                close(fd);
        }
        (void) unlinkat(AT_FDCWD, strjoina(dir, "/checkpoint"), 0);
        (void) rmdir(dir);

        return r ? EXIT_FAILURE : EXIT_SUCCESS;
}
