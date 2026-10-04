/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Tests of the helper program collect: the parsing of its checkpoint file by checkout(), the refusal of a
 * too long path of the checkpoint file by prepare(), and runs of its main() with their exit codes and
 * output.
 *
 * A NUL byte after a separator made checkout() move its pointer before the start of its buffer and read
 * there (heap-buffer-overflow with AddressSanitizer), and a NUL byte after a word made it drop the rest of
 * the file. When the buffer grew for a long ID, the IDs before it were added twice.
 *
 * Everything happens in a work directory below $TMPDIR (or /tmp), which is also the current directory, and
 * collect's main() keeps its checkpoint files in run/udev/collect/ of it instead of below /run.
 */

/* the functions of collect, which are static, with its main() renamed */
#undef UDEV_ROOT_RUN
#define UDEV_ROOT_RUN "run"
#define main collect_main
#include "../src/collect/collect.c"
#undef main

#include <ftw.h>

static int test_checkout(const char *name, const char *content, size_t size, const char *expected) {
        _cleanup_free_ char *words = NULL;
        struct udev_list_node *him_node;
        FILE *f;
        int r;

        udev_list_node_init(&bunch);
        bufsize = BUFSIZE;

        f = fopen("checkout", "w+e");
        if (!f || fwrite(content, 1, size, f) != size || fflush(f) != 0 || lseek(fileno(f), 0, SEEK_SET) < 0) {
                fprintf(stderr, "%s: cannot write the checkpoint file: %m\n", name);
                if (f)
                        fclose(f);
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

/* checkout() must return the error of read() or lseek(), not take it as the end of the file */
static int test_checkout_error(const char *name, int fd, int expected) {
        int r;

        udev_list_node_init(&bunch);
        bufsize = BUFSIZE;

        r = checkout(fd);
        kickall();
        if (r != expected) {
                fprintf(stderr, "%s: checkout() returned %i (%s), expected %i (%s)\n",
                        name, r, r < 0 ? strerror(-r) : "-", expected, strerror(-expected));
                return -1;
        }

        printf("%s: %s\n", name, strerror(-r));
        return 0;
}

static int read_file(const char *path, char *buf, size_t size) {
        _cleanup_close_ int fd = -1;
        ssize_t n;

        fd = open(path, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;
        n = read(fd, buf, size - 1);
        if (n < 0)
                return -errno;
        buf[n] = '\0';
        return 0;
}

/* Runs collect's main() with the arguments, which end with NULL, and compares its exit code, its standard
 * output and its messages with the expected ones: the messages must contain the expected text, or be empty
 * for "". It must not leave a file descriptor open. */
static int test_collect(const char *name, int expected_rc, const char *expected_out, const char *expected_err, ...) {
        char *argv[16] = { (char *) "collect" };
        char out[4096], err[4096];
        int argc = 1, fd_out, fd_err, saved_out, saved_err, next_fd, rc;
        va_list ap;

        va_start(ap, expected_err);
        while (argc < (int) ELEMENTSOF(argv) - 1 && (argv[argc] = va_arg(ap, char *)))
                argc++;
        va_end(ap);
        argv[argc] = NULL;

        fflush(stdout);
        fflush(stderr);
        fd_out = open("stdout", O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);
        fd_err = open("stderr", O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);
        saved_out = dup(STDOUT_FILENO);
        saved_err = dup(STDERR_FILENO);
        if (fd_out < 0 || fd_err < 0 || saved_out < 0 || saved_err < 0 ||
            dup2(fd_out, STDOUT_FILENO) < 0 || dup2(fd_err, STDERR_FILENO) < 0) {
                fprintf(stderr, "%s: cannot redirect the output: %m\n", name);
                return -1;
        }
        close(fd_out);
        close(fd_err);

        /* the lowest free file descriptor, which collect gets for the checkpoint file */
        next_fd = dup(STDIN_FILENO);
        if (next_fd >= 0)
                close(next_fd);

        optind = 0;
        rc = collect_main(argc, argv);

        fflush(stdout);
        fflush(stderr);
        dup2(saved_out, STDOUT_FILENO);
        dup2(saved_err, STDERR_FILENO);
        close(saved_out);
        close(saved_err);

        if (read_file("stdout", out, sizeof(out)) < 0 || read_file("stderr", err, sizeof(err)) < 0) {
                fprintf(stderr, "%s: cannot read the output: %m\n", name);
                return -1;
        }

        if (rc != expected_rc) {
                fprintf(stderr, "%s: exit code %i, expected %i; output \"%s\", messages \"%s\"\n",
                        name, rc, expected_rc, out, err);
                return -1;
        }
        if (!streq(out, expected_out)) {
                fprintf(stderr, "%s: output \"%s\", expected \"%s\"\n", name, out, expected_out);
                return -1;
        }
        if (expected_err && (*expected_err ? !strstr(err, expected_err) : *err != '\0')) {
                fprintf(stderr, "%s: messages \"%s\", expected \"%s\"\n", name, err, expected_err);
                return -1;
        }
        if (next_fd >= 0 && fcntl(next_fd, F_GETFD) >= 0) {
                fprintf(stderr, "%s: file descriptor %i was left open\n", name, next_fd);
                close(next_fd);
                return -1;
        }

        /* shown without the newline at the end, and long messages cut */
        delete_trailing_chars(out, "\n");
        delete_trailing_chars(err, "\n");
        printf("%s: exit code %i, output \"%s\"%s%.160s%s\n", name, rc, out,
               *err ? ", messages: " : "", err, strlen(err) > 160 ? "..." : "");
        return 0;
}

static int remove_entry(const char *path, const struct stat *st, int flag, struct FTW *ftw) {
        return remove(path);
}

int main(void) {
        char longname[UTIL_PATH_SIZE + 1];
        const char *tmp;
        char *dir;
        int r = 0, fd;

        tmp = getenv("TMPDIR");
        dir = strjoina(isempty(tmp) ? "/tmp" : tmp, "/test-collect.XXXXXX");
        if (!mkdtemp(dir) || chdir(dir) < 0) {
                fprintf(stderr, "cannot create a work directory: %m\n");
                return EXIT_FAILURE;
        }

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

        /* read() fails on a file that is open only for writing */
        fd = open("checkout", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);
        if (fd < 0 || write(fd, "aa bb\n", 6) != 6) {
                fprintf(stderr, "cannot write the checkpoint file: %m\n");
                r = -1;
        } else
                r |= test_checkout_error("read error", fd, -EBADF);
        if (fd >= 0)
                close(fd);
        /* lseek() fails on a pipe, when checkout() reads the file again for a long ID */
        {
                static const char content[] = "aa bb cccccccccccccccccccccccccccccccccccccccc dd\n";
                int p[2];

                if (pipe2(p, O_CLOEXEC) < 0 || write(p[1], content, sizeof(content) - 1) != sizeof(content) - 1) {
                        fprintf(stderr, "cannot write into a pipe: %m\n");
                        r = -1;
                } else {
                        close(p[1]);
                        r |= test_checkout_error("lseek error", p[0], -ESPIPE);
                        close(p[0]);
                }
        }

        /* prepare() refuses a path that does not fit, with a message */
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

        /* main() */
        r |= test_collect("no run/udev", 3, "", "Cannot create run/udev/collect: No such file or directory",
                          "cp", "a", "a", "b", NULL);
        if (mkdir("run", 0700) < 0 || mkdir("run/udev", 0700) < 0) {
                fprintf(stderr, "cannot create run/udev: %m\n");
                r = -1;
        }
        r |= test_collect("first of two IDs", 1, "COLLECT_cp=1\n", "", "cp", "a", "a", "b", NULL);
        r |= test_collect("second of two IDs", 0, "COLLECT_cp=0\n", "", "cp", "b", "a", "b", NULL);
        r |= test_collect("an ID removed", 1, "COLLECT_cp=1\n", "", "--remove", "cp", "a", "a", "b", NULL);
        r |= test_collect("an ID added again", 0, "COLLECT_cp=0\n", "", "--add", "cp", "a", "a", "b", NULL);
        r |= test_collect("missing parameters", 1, "Missing parameter(s)\n", "", "cp", NULL);
        r |= test_collect("unknown option", 1, "", NULL, "--bogus", "cp", "a", "a", NULL);
        r |= test_collect("too long checkpoint name", 3, "", "is too long", longname, "a", "a", NULL);

        if (chdir("/") < 0 || nftw(dir, remove_entry, 16, FTW_DEPTH|FTW_PHYS) < 0) {
                fprintf(stderr, "cannot remove %s: %m\n", dir);
                r = -1;
        }

        return r ? EXIT_FAILURE : EXIT_SUCCESS;
}
