/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Tests of the configuration file parser of the helper program scsi_id, get_file_options(): white space
 * after the commas of a line is allowed as in udev 3.2.x, and the error messages name the file and the
 * right line.
 *
 * Also runs of scsi_id's main() with a fake disk: the global options come from the config file that
 * -f/--config names, the command line overrides them, --help and --version work with a broken default
 * config file, and, like systemd, an invalid option in the line of the device, or an error in the file
 * found when it is searched for that line, fails.
 */

/* the functions of scsi_id, which are static, with its main() renamed */
#define main scsi_id_main
#include "../src/scsi_id/scsi_id.c"
#undef main

#include <sys/wait.h>

/* scsi_id's main() calls these functions of scsi_serial.c; instead of sending SCSI commands, they describe a
 * fake disk: vendor "ATA", model "QEMU HARDDISK", and a serial that names the device and the page code that
 * scsi_id asks for, so that the tests see which -p option applies */
int scsi_std_inquiry(struct udev *udev, struct scsi_id_device *dev_scsi, const char *devname) {
        strscpy(dev_scsi->vendor, sizeof(dev_scsi->vendor), "ATA");
        strscpy(dev_scsi->model, sizeof(dev_scsi->model), "QEMU HARDDISK");
        strscpy(dev_scsi->revision, sizeof(dev_scsi->revision), "2.5+");
        dev_scsi->type = 0;
        return 0;
}

int scsi_get_serial(struct udev *udev, struct scsi_id_device *dev_scsi, const char *devname,
                    int page_code, int len) {
        snprintf(dev_scsi->serial, len, "1ATA_%.200s_page_%s", devname,
                 page_code == PAGE_80 ? "0x80" :
                 page_code == PAGE_83 ? "0x83" :
                 page_code == PAGE_83_PRE_SPC3 ? "pre-spc3-83" : "unspecified");
        return 0;
}

static char *dir;

/* Writes the configuration file, calls get_file_options() with the vendor and the model, and compares
 * the result with the expected one: the options found ("" for a match without options), "-" for no match,
 * or "!" for an error, whose message must contain the expected text. */
static int test_config(const char *name, const char *content, size_t size, const char *vendor, const char *model,
                       const char *expected, const char *message) {
        _cleanup_strv_free_ char **argv = NULL;
        _cleanup_free_ char *options = NULL;
        const char *conf, *errfile;
        char err[4096] = "";
        int argc = 0, fd, saved, r, i;
        ssize_t n;
        FILE *f;

        conf = strjoina(dir, "/scsi_id.config");
        f = fopen(conf, "we");
        if (!f || fwrite(content, 1, size, f) != size || fclose(f) != 0) {
                fprintf(stderr, "%s: cannot write the configuration file: %m\n", name);
                return -1;
        }
        strscpy(config_file, sizeof(config_file), conf);

        /* the messages of get_file_options() go to a file */
        errfile = strjoina(dir, "/stderr");
        fd = open(errfile, O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);
        saved = dup(STDERR_FILENO);
        if (fd < 0 || saved < 0 || dup2(fd, STDERR_FILENO) < 0) {
                fprintf(stderr, "%s: cannot redirect stderr: %m\n", name);
                return -1;
        }
        r = get_file_options(NULL, vendor, model, &argc, &argv);
        fflush(stderr);
        dup2(saved, STDERR_FILENO);
        close(saved);
        n = pread(fd, err, sizeof(err) - 1, 0);
        close(fd);
        if (n > 0)
                err[n] = '\0';

        if (r < 0)
                options = strdup("!");
        else if (r > 0)
                options = strdup("-");
        else if (argc < 1 || strv_length(argv) != (unsigned) argc)
                options = strdup("(wrong argument count)");
        else {
                options = strdup("");
                for (i = 1; options && i < argc; i++) {
                        char *s;

                        s = strjoin(options, i > 1 ? " " : "", argv[i], NULL);
                        free(options);
                        options = s;
                }
        }
        if (!options)
                return log_oom();

        if (!streq(options, expected)) {
                fprintf(stderr, "%s: got \"%s\", expected \"%s\"; messages: %s\n", name, options, expected, err);
                return -1;
        }
        if (message && !strstr(err, message)) {
                fprintf(stderr, "%s: got the messages \"%s\", expected \"%s\"\n", name, err, message);
                return -1;
        }

        printf("%s: \"%s\"%s%s", name, options, *err ? ", " : "\n", err);
        return 0;
}

#define TEST_CONFIG(name, content, vendor, model, expected, message) \
        test_config(name, content, sizeof(content) - 1, vendor, model, expected, message)

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

static int write_file(const char *path, const char *content) {
        FILE *f;

        if (!content)
                return unlink(path) < 0 && errno != ENOENT ? -errno : 0;
        f = fopen(path, "we");
        if (!f)
                return -errno;
        if (fputs(content, f) < 0 || fclose(f) != 0)
                return -EIO;
        return 0;
}

/* Runs scsi_id's main() in a child process, with the arguments, which end with NULL; "FILE" stands for the path
 * of a config file with the content f_content. The default config file, /etc/scsi_id.config in scsi_id, is a
 * file of the test with the content default_content (NULL: it does not exist), so that the one of the system
 * does not matter. Compares the exit code, the output and the messages with the expected ones: they must
 * contain the expected text, or be empty for "", or are not compared for NULL. */
static int test_main(const char *name, const char *default_content, const char *f_content,
                     int expected_rc, const char *expected_out, const char *expected_err, ...) {
        char *argv[16] = { (char *) "scsi_id" };
        const char *default_conf, *f_conf, *outfile, *errfile;
        char out[4096], err[4096];
        int argc = 1, status, rc;
        va_list ap;
        pid_t pid;

        default_conf = strjoina(dir, "/default.config");
        f_conf = strjoina(dir, "/f.config");
        outfile = strjoina(dir, "/stdout");
        errfile = strjoina(dir, "/stderr");

        va_start(ap, expected_err);
        while (argc < (int) ELEMENTSOF(argv) - 1 && (argv[argc] = va_arg(ap, char *))) {
                if (streq(argv[argc], "FILE"))
                        argv[argc] = (char *) f_conf;
                argc++;
        }
        va_end(ap);
        argv[argc] = NULL;

        if (write_file(default_conf, default_content) < 0 || write_file(f_conf, f_content) < 0) {
                fprintf(stderr, "%s: cannot write the config files: %m\n", name);
                return -1;
        }

        fflush(stdout);
        fflush(stderr);
        pid = fork();
        if (pid < 0) {
                fprintf(stderr, "%s: cannot fork: %m\n", name);
                return -1;
        }
        if (pid == 0) {
                int fd_out, fd_err;

                fd_out = open(outfile, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);
                fd_err = open(errfile, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);
                if (fd_out < 0 || fd_err < 0 || dup2(fd_out, STDOUT_FILENO) < 0 || dup2(fd_err, STDERR_FILENO) < 0)
                        _exit(EXIT_FAILURE);
                strscpy(config_file, sizeof(config_file), default_conf);
                exit(scsi_id_main(argc, argv));
        }
        if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) {
                fprintf(stderr, "%s: the child process failed\n", name);
                return -1;
        }
        rc = WEXITSTATUS(status);

        if (read_file(outfile, out, sizeof(out)) < 0 || read_file(errfile, err, sizeof(err)) < 0) {
                fprintf(stderr, "%s: cannot read the output: %m\n", name);
                return -1;
        }

        if (rc != expected_rc) {
                fprintf(stderr, "%s: exit code %i, expected %i; output \"%s\", messages \"%s\"\n",
                        name, rc, expected_rc, out, err);
                return -1;
        }
        if (expected_out && (*expected_out ? !strstr(out, expected_out) : *out != '\0')) {
                fprintf(stderr, "%s: output \"%s\", expected \"%s\"\n", name, out, expected_out);
                return -1;
        }
        if (expected_err && (*expected_err ? !strstr(err, expected_err) : *err != '\0')) {
                fprintf(stderr, "%s: messages \"%s\", expected \"%s\"\n", name, err, expected_err);
                return -1;
        }

        /* shown without the newline at the end, and long output cut */
        delete_trailing_chars(out, "\n");
        delete_trailing_chars(err, "\n");
        printf("%s: exit code %i, output \"%.60s%s\"%s%.160s\n", name, rc, out, strlen(out) > 60 ? "..." : "",
               *err ? ", messages: " : "", err);
        return 0;
}

int main(void) {
        char longline[300];
        const char *tmp;
        int r = 0;

        log_set_target(LOG_TARGET_CONSOLE);
        log_open();

        tmp = getenv("TMPDIR");
        dir = strjoina(isempty(tmp) ? "/tmp" : tmp, "/test-scsi_id.XXXXXX");
        if (!mkdtemp(dir)) {
                fprintf(stderr, "cannot create a directory: %m\n");
                return EXIT_FAILURE;
        }

        r |= TEST_CONFIG("global options", "OPTIONS=-g\n", NULL, NULL, "-g", NULL);
        r |= TEST_CONFIG("vendor and model", "vendor=\"ATA\",model=\"Samsung\",options=\"-p 0x80\"\nOPTIONS=-g\n",
                         "ATA     ", "Samsung SSD 860", "-p 0x80", NULL);
        r |= TEST_CONFIG("vendor and model, other model", "vendor=\"ATA\",model=\"WDC\",options=\"-p 0x80\"\nvendor=\"ATA\",options=-g\n",
                         "ATA     ", "Samsung SSD 860", "-g", NULL);
        r |= TEST_CONFIG("no match", "vendor=\"ATA\",options=-b\n", "SEAGATE ", "ST4000NM", "-", NULL);

        /* white space after the commas, as udev 3.2.x and before allowed */
        r |= TEST_CONFIG("space after the comma", "vendor=\"ATA\", options=-b\nOPTIONS=-g\n",
                         "ATA     ", "Samsung SSD 860", "-b", NULL);
        r |= TEST_CONFIG("space after the comma, global options on the next line",
                         "vendor=\"ATA\", options=-b\nOPTIONS=-g\n", NULL, NULL, "-g", NULL);
        r |= TEST_CONFIG("spaces after both commas", "vendor=\"ATA\", model=\"Samsung\", options=\"-g -p 0x83\"\n",
                         "ATA     ", "Samsung SSD 860", "-g -p 0x83", NULL);
        r |= TEST_CONFIG("tabs after both commas", "VENDOR=\"ATA\",\tMODEL=\"Samsung\",\t\tOPTIONS=-g\n",
                         "ATA     ", "Samsung SSD 860", "-g", NULL);
        r |= TEST_CONFIG("unquoted values, spaces after the commas", "vendor=ATA, model=Samsung, options=-g\n",
                         "ATA     ", "Samsung SSD 860", "-g", NULL);
        r |= TEST_CONFIG("space after the comma, other model", "vendor=\"ATA\", model=\"WDC\", options=-b\nvendor=\"ATA\", options=-g\n",
                         "ATA     ", "Samsung SSD 860", "-g", NULL);
        r |= TEST_CONFIG("space after the comma, vendor without options", "vendor=\"ATA\", \nOPTIONS=-g\n",
                         "ATA     ", "Samsung SSD 860", "!", "/scsi_id.config line 1 'vendor=\"ATA\", '");
        r |= TEST_CONFIG("space before the equal sign", "vendor =\"ATA\",options=-g\n",
                         "ATA     ", "Samsung SSD 860", "!", "/scsi_id.config line 1 'vendor =\"ATA\",options=-g'");

        /* the error messages name the file and the line */
        r |= TEST_CONFIG("error on line 3", "# comment\n\nvendor=\"ATA\"\nOPTIONS=-g\n",
                         "ATA     ", "Samsung SSD 860", "!", "Error parsing config file /");
        r |= TEST_CONFIG("error on line 3, the line", "# comment\n\nvendor=\"ATA\"\nOPTIONS=-g\n",
                         "ATA     ", "Samsung SSD 860", "!", "/scsi_id.config line 3 'vendor=\"ATA\"'");
        memset(longline, 'x', sizeof(longline));
        memcpy(longline, "OPTIONS=", 8);
        longline[sizeof(longline) - 1] = '\n';
        r |= test_config("too long line 1", longline, sizeof(longline), NULL, NULL, "!", "read_line() on line 1 of ");
        memcpy(longline, "# a\n\n", 5);
        r |= test_config("too long line 3", longline, sizeof(longline), NULL, NULL, "!", "read_line() on line 3 of ");

        /* main(): the global options come from the config file given with -f */
        r |= test_main("global options of the -f file", NULL, "options=-g\n",
                       0, "1ATA_/dev/sda_page_unspecified\n", NULL, "-f", "FILE", "-d", "/dev/sda", NULL);
        r |= test_main("global options of the -f file, --config=", NULL, "options=-g\n",
                       0, "1ATA_/dev/sda_page_unspecified\n", NULL, "--config", "FILE", "/dev/sda", NULL);
        r |= test_main("no global options from the default file with -f", "options=-g\n", "",
                       1, "", NULL, "-f", "FILE", "-d", "/dev/sda", NULL);
        r |= test_main("-f names a missing file", "options=-g\n", NULL,
                       1, "", NULL, "-f", "FILE", "-d", "/dev/sda", NULL);
        r |= test_main("global options of the default file without -f", "options=\"-g -p 0x83\"\n", NULL,
                       0, "1ATA_/dev/sda_page_0x83\n", NULL, "-d", "/dev/sda", NULL);
        r |= test_main("per-device options of the -f file", NULL, "vendor=\"ATA\",options=\"-g -p 0x80\"\n",
                       0, "1ATA_/dev/sda_page_0x80\n", NULL, "-f", "FILE", "-d", "/dev/sda", NULL);
        r |= test_main("per-device options of the -f file override its global ones", NULL,
                       "vendor=\"ATA\",options=\"-p 0x80\"\noptions=\"-g -p 0x83\"\n",
                       0, "1ATA_/dev/sda_page_0x80\n", NULL, "-f", "FILE", "/dev/sda", NULL);

        /* main(): the command line overrides the global options of the config file */
        r |= test_main("-p on the command line", NULL, "options=\"-g -p 0x80\"\n",
                       0, "1ATA_/dev/sda_page_0x83\n", NULL, "-f", "FILE", "-p", "0x83", "-d", "/dev/sda", NULL);
        r |= test_main("-b on the command line", NULL, "options=-g\n",
                       1, "", NULL, "-f", "FILE", "-b", "-d", "/dev/sda", NULL);
        r |= test_main("-g on the command line", NULL, "options=-b\n",
                       0, "1ATA_/dev/sdb_page_unspecified\n", NULL, "-f", "FILE", "-g", "/dev/sdb", NULL);
        r |= test_main("-d in the global options beats a positional device", NULL, "options=\"-g -d /dev/sdc\"\n",
                       0, "1ATA_/dev/sdc_page_unspecified\n", NULL, "-f", "FILE", "/dev/sda", NULL);
        r |= test_main("-d on the command line beats -d in the global options", NULL, "options=\"-g -d /dev/sdc\"\n",
                       0, "1ATA_/dev/sda_page_unspecified\n", NULL, "-f", "FILE", "-d", "/dev/sda", NULL);

        /* main(): a broken default config file does not matter with -f, --help or --version */
        r |= test_main("broken default file, -f", "garbage\n", "options=-g\n",
                       0, "1ATA_/dev/sda_page_unspecified\n", NULL, "-f", "FILE", "-d", "/dev/sda", NULL);
        r |= test_main("broken default file, --help", "garbage\n", NULL,
                       0, " [OPTION…] [DEVICE]\n\nIdentify SCSI devices.\n\nOptions:\n  -h --help ", NULL, "--help", NULL);
        r |= test_main("broken default file, --version", "garbage\n", NULL,
                       0, UDEV_VERSION "\n", NULL, "--version", NULL);
        r |= test_main("broken default file", "garbage\n", NULL,
                       1, "", "Error parsing config file /", "-d", "/dev/sda", NULL);
        r |= test_main("broken default file, the file and the line", "garbage\n", NULL,
                       1, "", "/default.config line 1 'garbage'", "-d", "/dev/sda", NULL);

        /* main(): errors */
        r |= test_main("bad page code in the global options", NULL, "options=\"-p 0x99\"\n",
                       2, "", "Unknown page code '0x99'", "-f", "FILE", "-d", "/dev/sda", NULL);
        r |= test_main("bad page code on the command line, broken default file", "garbage\n", NULL,
                       1, "", "Unknown page code '0x88'", "-p", "0x88", "-d", "/dev/sda", NULL);
        r |= test_main("no device", NULL, "options=-g\n",
                       1, "", "No device specified.", "-f", "FILE", NULL);

        /* scsi_id(): like systemd, an invalid option in the line of the device fails, with no output */
        r |= test_main("per-device options: unknown option", NULL, "vendor=\"ATA\",options=\"-g --bogus\"\n",
                       1, "", "unrecognized option '--bogus'", "-f", "FILE", "-d", "/dev/sda", NULL);
        r |= test_main("per-device options: unknown short option", NULL, "vendor=\"ATA\",options=\"-g -Z\"\n",
                       1, "", "unrecognized option '-Z'", "-f", "FILE", "-d", "/dev/sda", NULL);
        r |= test_main("per-device options: missing argument", NULL, "vendor=\"ATA\",options=\"-g -p\"\n",
                       1, "", "option '-p' requires an argument", "-f", "FILE", "-d", "/dev/sda", NULL);
        r |= test_main("per-device options: bad page code", NULL, "vendor=\"ATA\",options=\"-g -p 0x99\"\n",
                       1, "", "Unknown page code '0x99'", "-f", "FILE", "-d", "/dev/sda", NULL);
        r |= test_main("per-device options: option not allowed", NULL, "vendor=\"ATA\",options=\"-g -x\"\n",
                       1, "", "Option -x/--export not supported in the config file.", "-f", "FILE", "/dev/sda", NULL);
        r |= test_main("per-device options: long option not allowed", NULL,
                       "options=-g\nvendor=\"ATA\",model=\"QEMU\",options=\"--device /dev/sdb\"\n",
                       1, "", "Option -d/--device not supported in the config file.", "-f", "FILE", "/dev/sda", NULL);
        r |= test_main("per-device options: invalid line of another device", NULL,
                       "vendor=\"SEAGATE\",options=\"--bogus\"\nvendor=\"ATA\",model=\"WDC\",options=-x\n"
                       "vendor=\"ATA\",options=\"-g -p 0x80\"\n",
                       0, "1ATA_/dev/sda_page_0x80\n", "", "-f", "FILE", "/dev/sda", NULL);
        r |= test_main("per-device options: error in the file after the global options", NULL, "options=-g\ngarbage\n",
                       1, "", "/f.config line 2 'garbage'", "-f", "FILE", "/dev/sda", NULL);
        r |= test_main("per-device options: error in the file after the line of the device", NULL,
                       "options=-b\nvendor=\"ATA\",options=-g\ngarbage\n",
                       0, "1ATA_/dev/sda_page_unspecified\n", "", "-f", "FILE", "/dev/sda", NULL);

        (void) unlink(strjoina(dir, "/scsi_id.config"));
        (void) unlink(strjoina(dir, "/default.config"));
        (void) unlink(strjoina(dir, "/f.config"));
        (void) unlink(strjoina(dir, "/stdout"));
        (void) unlink(strjoina(dir, "/stderr"));
        (void) rmdir(dir);

        return r ? EXIT_FAILURE : EXIT_SUCCESS;
}
