/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Tests of the configuration file parser of the helper program scsi_id, get_file_options(): white space
 * after the commas of a line is allowed as in udev 3.2.x, and the error messages name the right line.
 */

/* the functions of scsi_id, which are static, with its main() renamed */
#define main scsi_id_main
#include "../src/scsi_id/scsi_id.c"
#undef main

/* scsi_id's main() calls these functions of scsi_serial.c, which the tests do not need */
int scsi_std_inquiry(struct udev *udev, struct scsi_id_device *dev_scsi, const char *devname) {
        return -ENOSYS;
}

int scsi_get_serial(struct udev *udev, struct scsi_id_device *dev_scsi, const char *devname,
                    int page_code, int len) {
        return -ENOSYS;
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
                         "ATA     ", "Samsung SSD 860", "!", "Error parsing config file line 1 ");
        r |= TEST_CONFIG("space before the equal sign", "vendor =\"ATA\",options=-g\n",
                         "ATA     ", "Samsung SSD 860", "!", "Error parsing config file line 1 ");

        /* the error messages name the line */
        r |= TEST_CONFIG("error on line 3", "# comment\n\nvendor=\"ATA\"\nOPTIONS=-g\n",
                         "ATA     ", "Samsung SSD 860", "!", "Error parsing config file line 3 ");
        memset(longline, 'x', sizeof(longline));
        memcpy(longline, "OPTIONS=", 8);
        longline[sizeof(longline) - 1] = '\n';
        r |= test_config("too long line 1", longline, sizeof(longline), NULL, NULL, "!", "read_line() on line 1 of ");
        memcpy(longline, "# a\n\n", 5);
        r |= test_config("too long line 3", longline, sizeof(longline), NULL, NULL, "!", "read_line() on line 3 of ");

        (void) unlink(strjoina(dir, "/scsi_id.config"));
        (void) unlink(strjoina(dir, "/stderr"));
        (void) rmdir(dir);

        return r ? EXIT_FAILURE : EXIT_SUCCESS;
}
