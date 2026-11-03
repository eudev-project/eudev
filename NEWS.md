# eudev 3.3.0 (2026-11-03)

This release completes the sync with systemd-udev at systemd a446e8ff2c (v262+) that 3.2.15 started.
3.2.15 brought the hardware database, the rules, the builtins and the helper programs to that level;
this release does the same for udevd, udevadm, the rules engine and libudev. A few later systemd
changes are included too: hwdb data, the caller information of triggered uevents and the fixes of
systemd v262.1 that apply to eudev. The main additions are systemd's network interface naming
schemes and alternative interface names, sticky tags, the reworked device node symlink handling,
postponing the events of locked block devices, ID_PROCESSING, trace logging, udev.conf drop-ins,
systemd's log settings (`$SYSTEMD_LOG_LEVEL` and the like), the `udevadm verify`, `cat`, `wait` and
`lock` commands, the `systemd-hwdb` tool, the `tpm2_id` and `factory_reset` builtins and GPT root
partition discovery. The rules parser is now as strict as systemd's, so please read "Before
upgrading" first.

`UDEV_VERSION` is now 262. The libudev ABI is unchanged: no symbol was added or removed, and the
soname stays `libudev.so.1`. The library file becomes `libudev.so.1.7.15`, the same version as
systemd v262's libudev: 3.2.14 added `udev_device_has_current_tag()` and
`udev_device_get_current_tags_list_entry()` without raising the library version.

In the notes below, "(deviation: ...)" marks a place where eudev deliberately differs from
systemd a446e8ff2c.

## Changes that may need attention

The list names the changes that most often need an adjustment; "Before upgrading" and the sections
after it have the details.

- Workers are named "(udev-worker)", the child that re-reads a partition table "(udev-synth)" and the
  processes of the programs that rules run "(spawn)", as in systemd: the messages of the workers and
  of that child in the kernel log and syslog are tagged "(udev-worker)" and "(udev-synth)" instead of
  "udevd", so log filters that match "udevd" miss them.
- `$<NAME>_PATH` in udevd's environment, e.g. `$SCSI_ID_PATH`, replaces the program of the same name
  that a rule runs, as in systemd.
- `IMPORT{program}`, `IMPORT{file}`, `IMPORT{db}`, `IMPORT{cmdline}`, `IMPORT{parent}` and hwdb
  entries no longer set the properties that `ENV{}` cannot set (`DEVNAME`, `ACTION`, `DEVPATH`,
  ...): e.g. `IMPORT{db}=="DEVNAME"` is now always false, and `udevadm verify` warns about such
  names and fails (deviation).
- Device names, paths and the arguments of udevadm are escaped in messages (control characters and
  invalid UTF-8 as `\xNN`; deviation); the data that `udevadm info`, `monitor` and `trigger
  --verbose` print is unchanged.
- `udevadm trigger` and `info` check their match options like systemd, and `trigger`, `control`,
  `settle` and `monitor` check all their options before they look for a chroot, so `--help`,
  `--version` and invalid options work in a chroot (deviation: systemd's `trigger` and `control`
  look for the chroot first).
- `--attr-match=` and `--attr-nomatch=` of `udevadm trigger` and `info` take attribute paths
  relative to the device, also with `..`, e.g. `queue/rotational` (deviation).
- `udevadm test -D` fails for a directory that does not exist; invalid tag names are refused by
  `udevadm trigger`/`info --tag-match=` and `udev_enumerate_add_match_tag()`.
- The release tarball no longer contains the generated `rules/64-btrfs.rules` and
  `rule_generator/write_net_rules` (GitHub #301), and `make check` does not change the timestamps
  of the build machine's device nodes.
- New configure option `--with-net-ifnames-default=yes|no` for what happens without `net.ifnames=`
  on the kernel command line.
- Builds with `--enable-rule-generator` no longer write rules for interfaces that the kernel did not
  name by enumeration, for the interfaces of more virtual machines, for User-mode Linux and mac80211
  monitor interfaces, or for an interface without a MAC address or bus id (also with
  `INTERFACE_NAME`), and udevd no longer moves an interface without a new name of its own to a
  temporary name such as `eth126` (see "Rule generator").
- `/run/udev/queue` is created once when events are queued and removed when the queue is empty, as in
  systemd: when something else removes it while events are queued, udevd does not create it again
  until the queue has emptied, so `udevadm settle` returns early then.
- With the default `hwdb_format=1`, it is undefined which value a device gets when several hwdb
  records set the same key, as before; hwdb(7) now says so, and some entries, e.g. the new one for the
  lid keys of the HP Pavilion Gaming 15-dk0, work only with `hwdb_format=2` in udev.conf (see "hwdb").
- The library file is `libudev.so.1.7.15` (the soname stays `libudev.so.1`).

## Before upgrading

### Packagers

- **Create the groups that the shipped rules use:** audio, cdrom, clock, dialout, disk, input, kmem,
  kvm, lp, render, sgx, tape, tty and video. A `GROUP=` (or `OWNER=`) that names a group (or user)
  that does not exist is now ignored with an error such as "Failed to resolve group 'clock',
  ignoring: Unknown group" every time the rules are loaded, and the device node keeps its group; the
  rest of the rule line (`MODE=`, `SYMLINK+=`, ...) still applies. Before, eudev used root instead.

- **New `clock` group:** rtc devices get `GROUP="clock", MODE="0660"` and ptp devices
  `GROUP="clock", MODE="0664"` (systemd af96ccfc24 and 1e6854e112), so that e.g. linuxptp can open
  them without root. Read access to `/dev/ptp*` for everybody relies on the PTP file mode checks of
  Linux b4e53b15c04e, which was backported to the maintained stable kernels. Nothing creates the
  `clock` group on systems without systemd-sysusers (e.g. Alpine, Gentoo, Void).
- **`$(sbindir)/udevadm` is gone:** `make install` no longer creates the `/sbin/udevadm` (or
  `/usr/sbin/udevadm`) compatibility symlink that existed since 2013. Packages and scripts that call
  udevadm by that path must provide the link themselves.
- **The shipped hwdb files moved** to `$(udevlibexecdir)/hwdb.d` (e.g. `/usr/lib/udev/hwdb.d`), as in
  systemd; `$(sysconfdir)/udev/hwdb.d` is left to the administrator, and its files override shipped
  files of the same name. **Remove copies of the shipped hwdb files that an older package left in
  /etc/udev/hwdb.d**, or they override the new data with stale data. `hwdb.bin` is still written to
  `$(sysconfdir)/udev/hwdb.bin`, which now really follows `--sysconfdir` (it was hard-coded to
  /etc/udev). Builds with `--disable-programs` install no hwdb files and no man pages. The hwdb
  `README` is installed next to the hwdb files, like in systemd.
- **`udev.h` is no longer installed;** `libudev.h` is the only public header. udev.h was an internal
  header that included private ones. `udev_device_read_db()` is removed from `libudev.h`; it was never
  exported, so no program could have linked against it.
- **`UDEV_VERSION` is 262** in `udevadm --version`, `udevd --version`, the helpers' `--version`,
  `udev.pc` and `libudev.pc` (3.2.15 still reported 251). It says that the rules syntax, the hwdb, the
  builtins, the helpers and the libudev API match systemd-udev v262. It does not mean feature parity:
  eudev has, for example, no Varlink interface, no sd-device API, no `CONST{}` key, no
  `dissect_image`, `net_setup_link` or `uaccess` builtin and no `udevadm control --load-credentials`.
  Scripts should test for a feature (e.g. `udevadm lock --help`) rather than compare numbers.
  Distributions that hard-code the number must update it (Void: `_UDEV_VERSION="251"`). The package
  version is shown next to it, e.g. in udevd's start line "starting eudev-3.3.0 (udev 262)".

- **New configure options** that packagers may want to set: `--with-nobody-group=` (Debian and Devuan:
  `nogroup`), `--with-system-uid-max=`/`--with-system-gid-max=`, `--with-foreign-uid-base=`,
  `--with-net-ifnames-default=` (see "Network interface names"), `--disable-tpm2`,
  `--disable-systemd-hwdb` (`systemd-hwdb` is installed by default and clashes with systemd's own
  `/usr/bin/systemd-hwdb` where both packages can be installed), `--with-bashcompletiondir=`,
  `--with-zshcompletiondir=` and `--enable-smack`. See "Build and configuration".
- **udev.conf is looked up like in systemd:** the main file is the first `udev.conf` found in
  `$(sysconfdir)/udev`, `/run/udev`, `/usr/local/lib/udev` and `$(udevlibexecdir)` (with split-usr also
  `/lib/udev` and `/usr/lib/udev`), and `udev.conf.d/*.conf` drop-ins in the same directories are read
  after it (see "udevd"). An empty file or a symlink to `/dev/null` masks a file of the same name in
  the later directories. The shipped udev.conf lists the new keys as comments and writes
  `#udev_log=info` without quotes, so packages that patch it must be adjusted.
- **Release tarball and `make check`:** the tarball no longer contains the generated
  `rules/64-btrfs.rules` and `rule_generator/write_net_rules`, only their `.in` sources, from which
  the build makes them for its own directories (GitHub #301); `rule_generator.functions` is made the
  same way, for `--with-rootrundir=`. The installed files do not change, apart from the paths in the
  rule generator's scripts (see "Fixes"). The tarball now also contains `autogen.sh`, `man/make.sh`,
  `man/custom-man.xsl`, `BUILD`, `CONTRIBUTING`, `LEGACY` and `NOTES`. The new tests of `make check`
  that use the build machine's `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`,
  `/dev/tty` and `/dev/ptmx` bind them read-only, so they do not change their timestamps, also when
  they run as root (see "Build and configuration").

### Init scripts and service supervisors

- **udevd keeps its standard streams in the foreground:** it connects `/dev/null` to stdin, stdout
  and stderr only when it daemonizes and does not log at debug level (systemd 40e749b59b). Before, it
  did so unless `--debug` was given, also without `--daemon`.
- **Log level precedence** of udevd is now, from lowest to highest: the default, `systemd.log_level=`
  on the kernel command line, `$UDEV_LOG_LEVEL`/`$SYSTEMD_LOG_LEVEL`, `udev_log=` in udev.conf, udevd
  options (`--debug`), `udev.log_level=` on the kernel command line, `udevadm control`, as in systemd;
  udevd(8) documents it. Before, `--debug` overrode `udev.log-priority=` on the kernel command line.
  `--debug` still logs to the console, now from the start (see "udevd").
- **Kernel command line:** udevd accepts systemd's spellings `udev.log_level=` and
  `udev.log_priority=`, and `-` and `_` are equivalent in all its options (`udev.children_max=` is
  `udev.children-max=`); the old spellings keep working. `rd.*` options are honoured only in an initrd
  (see "Rules"). Unknown `udev.*` options, and unknown `rd.udev.*` options in an initrd, are ignored
  with systemd's warning "Unknown udev kernel command line option "…", ignoring." (before, without a
  message).
- **systemd's log settings:** udevd, udevadm and the helper programs read `$SYSTEMD_LOG_LEVEL`,
  `$SYSTEMD_LOG_TARGET`, `$SYSTEMD_LOG_COLOR`, `$SYSTEMD_LOG_LOCATION`, `$SYSTEMD_LOG_TIME`,
  `$SYSTEMD_LOG_TID` and `$SYSTEMD_LOG_RATELIMIT_KMSG` (each `$UDEV_LOG_*` variant first). Processes
  without a controlling terminal (udevd, the programs it runs, the commands of init scripts) also read
  `systemd.log_level=`, `systemd.log_target=`, `systemd.log_color`, `systemd.log_location`,
  `systemd.log_time`, `systemd.log_tid` and `systemd.log_ratelimit_kmsg` from the kernel command line;
  the environment overrides them. A bare `debug` on the kernel command line counts as
  `systemd.log_level=debug`, as in systemd (`rd.debug` only in an initrd). So
  `systemd.log_level=debug` or `debug` on the kernel command line now also makes
  `udevadm trigger`/`settle` in init scripts and every helper verbose on the boot console, and every
  helper run reads `/proc/cmdline`. Warnings about invalid log settings in the environment or on the
  kernel command line go to stderr, as in systemd. Like in systemd, a process closes the console once
  it logs to another target, e.g. /dev/kmsg. With `systemd.log_target=console`, a udevd started with
  `--daemon` writes to `/dev/console`, or to `/dev/kmsg` when that cannot be opened, e.g. in a
  container (deviation: systemd writes to `/dev/null` then). Messages to `/dev/kmsg` are limited to
  200 per 5 seconds per process, as in systemd; messages dropped by the limit are not written anywhere
  else.
- **Changed log messages:** log monitors and scripts that match udevd's messages must be adjusted. The
  slow and timeout messages are now systemd's: "Spawned process '…' [PID] is taking longer than … to
  complete.", "Spawned process '…' [PID] timed out after …, killing.", "Worker [PID] processing
  SEQNUM=N is taking a long time." and "Worker [PID] processing SEQNUM=N killed." (before: "slow:",
  "timeout: killing", "timeout; kill it", "seq N '…' killed"); "Delaying execution of "…" for …." was
  "delay execution of"; socket failures read "Failed to initialize udev control socket: …", "Failed to
  initialize device monitor: …", "Failed to bind udev control socket: …" and "Failed to listen udev
  control socket: …". The messages of the workers and of the child that re-reads a partition table are
  tagged "(udev-worker)" and "(udev-synth)" (see below). Programs are reported like in systemd:
  "Process '…' succeeded." at debug level (was "'…' [PID] exit with return code 0"), "Process '…'
  failed with exit code N." as a warning for `RUN` and at debug level for `PROGRAM` and
  `IMPORT{program}` (was "exit with return code N" at debug level), "Process '…' terminated by signal
  NAME." (was "terminated by signal N (Name)"), and a program that cannot be found or is not
  executable is reported before it is started: "Failed to find and pin callout binary "…": …" (was
  "failed to execute '…' '…': …"). Device names, paths and other values in messages are escaped (see
  "Logging"). See "udevd" and "Logging".
- **Process names:** workers rename themselves "(udev-worker)", the child that re-reads a partition
  table "(udev-synth)" and the processes of the programs that rules run "(spawn)", as in systemd, so
  they show under these names in `ps`, and the kernel log and syslog tag the messages of the workers
  "(udev-worker)" and those of the re-read child "(udev-synth)" instead of "udevd" (udevd's own
  messages keep its name): **log filters that match "udevd" miss the messages of the workers and of
  the re-read child.** The option errors of the builtins start with "(udev-worker):", and the uevents
  that a worker triggers carry `SYNTH_ARG_Comm=udevworker` (see "Caller information in triggered
  uevents"). The names are complete whatever the name udevd was started with.
- **`$<NAME>_PATH`:** like systemd-udevd, udevd honours `$<NAME>_PATH` from its environment, the file
  name of a program in upper case with `-` replaced by `_` and `_PATH` appended, e.g. `$SCSI_ID_PATH`
  for `scsi_id`: it names another file to run instead of that `RUN`, `PROGRAM` or `IMPORT{program}`
  program. Init scripts and supervisors that pass their environment to udevd should not set such
  variables by accident.

### Local rules

Run `udevadm verify` on local rules after upgrading: the parser now follows systemd, and lines that
older versions accepted silently may be dropped with an error.

- **Rules parser strictness:**
  - key names must be exact (`NAMEX` is not `NAME`, `TESTX` is not `TEST`);
  - a key that takes no attribute must not have one ("Invalid attribute for X."), and `ATTR`, `ATTRS`,
    `ENV`, `IMPORT`, `SECLABEL` and `SYSCTL` need a non-empty one; an attribute is everything up to
    `}`, so `ATTR{a b}` works, and text between `}` and the operator is an error;
  - `==` and `!=` are errors for `RUN`, `OWNER`, `GROUP`, `MODE` and `SECLABEL`; `LABEL` and `GOTO`
    take only `=`; `OPTIONS` refuses `==`, `!=` and `-=`, and `+=` acts as `=`;
  - a syntax error anywhere in a line drops the whole line (before, the keys parsed so far were kept);
    the message is "Invalid key/value pair, ignoring." without a character position; a line of a
    single character is such an error; a trailing comma is accepted;
  - an unknown builtin, an unknown `IMPORT{}` or `RUN{}` type, or `IMPORT` without a type drops the
    line (before, only that key); in builds without blkid or kmod, lines using them are dropped as in
    systemd; in `--disable-tpm2` builds `IMPORT{builtin}`, `IMPORT{program}`, `RUN{builtin}`,
    `RUN{program}` and `PROGRAM` naming `tpm2_id` are dropped with "... is not supported by this build
    of eudev (configured with --disable-tpm2), ignoring the rule.";
  - lines using what only systemd supports are dropped with a message saying so: the `CONST{}` key and
    the `dissect_image`, `net_setup_link` and `uaccess` builtins;
  - `OPTIONS` values must be exact known names (`nowatch` no longer also means `watch`); unknown
    values get a warning; an invalid `link_priority=` or `log_level=` value drops the line, and
    `link_priority=` takes systemd's number formats (before, "10x" meant 10 and "abc" meant 0);
    several values separated by commas in one `OPTIONS` key are still accepted (deviation: systemd
    takes one value per key; no systemd rule is affected);
  - `OWNER`/`GROUP`: an empty or invalid value (leading zeros, leading whitespace or a minus sign in
    a number, 65535, 4294967295, values that are too large) is an error and only that key is ignored,
    also with `OPTIONS+="static_node=..."` (deviation: systemd drops the line; before, eudev used
    root); `udevadm verify` reports a line that is left without effect by it; a value starting with
    `+` is looked up as a name; a numeric ID without an account is accepted only up to the highest
    system ID, for 0, for 65534 ("nobody") and in systemd's foreign range, otherwise it counts as an
    unknown user or group; see also "Packagers" above;
  - `MODE`: an invalid mode without substitutions (empty, `0999`, a sign, more than 07777, also with
    `MODE:=`) is an error when the rules are read, and only that key is ignored (deviation: systemd
    keeps the key, which then fails at every event); a mode produced by a substitution that is invalid
    is logged and leaves the mode unchanged (before, an empty result set mode 0000);
  - `NAME="%k"` and `NAME=""` drop the line, with systemd's message;
  - `TEST{mode}` with an invalid mode drops the line (before, it meant "no mode"), and so does
    `TEST{0}` ("Mode mask of TEST must not be zero, ignoring.") (deviation: in systemd `TEST{0}` never
    matches); a mask matches when any of its bits is set, as documented now;
  - `WAIT_FOR` and `WAIT_FOR_SYSFS` are removed (systemd f2b8052fb6) and now drop the line as unknown
    keys;
  - only the first `GOTO` of a line counts; later ones get "Contains multiple GOTO keys, ignoring
    GOTO=..." (before, a later `GOTO` could jump);
  - like in systemd, a line that cannot do anything for the event is not evaluated at all: one without
    an assignment, `GOTO`, `PROGRAM` or `IMPORT`, or whose only assignments are `NAME` on a device
    that is not a network interface, or `SYMLINK`, `OWNER`, `GROUP` or `MODE` on a device without a
    node or on a remove event; so a failing `TEST` or `SYSCTL{}` in such a line no longer stops the
    event, and `udevadm test` does not show it; a line whose `GOTO` has no `LABEL` and that has
    nothing else to do is dropped with "The line has no effect any more, dropping.";
  - a rule may have any number of keys (before, more than 64 keys crashed udevd).
- **Line continuation** is read like systemd: the leading whitespace of continuation lines is
  removed; comment lines inside a continued rule are skipped (before, they ended the rule, and the
  remaining lines became a separate rule without the earlier matches); a rule continued at the end of
  the file is ignored with "Unexpected EOF after line continuation, line ignored."; CRLF files work.
  A physical line longer than 16383 characters drops only that rule, with an error naming the line
  (deviation: systemd ignores the whole file).
- **Program arguments:** `RUN`, `PROGRAM` and `IMPORT{program}` command lines are split like systemd
  does, with the same splitter as the builtins: any whitespace (also tabs) separates arguments;
  single and double quotes group characters anywhere in a word and are removed (`a"b c"d` is one
  argument `ab cd`, and `'a b'c` is `a bc`; before: `a b` and `c`); a missing closing quote is
  accepted; backslashes are not special; a command given as `"prog"` runs `prog`. Builtin commands
  also skip leading whitespace and are no longer cut at 1024 bytes. None of the rules shipped by
  eudev, systemd, Devuan or Debian are affected; local rules that pass quotes inside a word, or tabs,
  must be adjusted.
- **Rules directory precedence** is now `/etc/udev/rules.d` > `/run/udev/rules.d` >
  `/usr/local/lib/udev/rules.d` > `/usr/lib/udev/rules.d` (and `/lib/udev/rules.d`), as in systemd.
  Before, `/lib` came before `/run`, and `/usr/local` came last. Each directory is read once, also
  when it has several paths, e.g. `/lib` and `/usr/lib` on a merged /usr, or a bind mount. A rules
  file that is not a regular file (a dangling symlink, a symlink to a directory, a FIFO) no longer
  hides the file of the same name in a lower-priority directory; this holds for udevd, `udevadm test`,
  `cat` and `verify`.
- **Properties are validated** wherever they come from (kernel events, rules, IMPORT, builtins, the
  database), as in systemd: names may contain only ASCII letters, digits, `_` and `.`; values must be
  valid UTF-8 without control characters. Invalid ones are ignored with a warning (rules) or a debug
  message, and processing continues; so programs or `IMPORT{cmdline}` keys that use e.g. `-` in
  property names lose those properties. An empty value removes the property, also from builtins
  (e.g. an empty USB serial) and `IMPORT` (`A=""`).
- **Errors stop the event** as in systemd: an `IMPORT{file}` that exists but cannot be opened, an
  unreadable kernel command line, an unreadable `SYSCTL{}` (other than a missing one), an unreadable
  directory for a `*` in `TEST`, failing to remove a property (e.g. `ENV{a-b}=""`), and running out of
  memory (e.g. "Failed to clone sd_device object: …" for the copy of the device with its database
  entry, before which eudev went on without that copy). No further rules are applied, the node,
  symlinks and database are not updated, `RUN` is not executed, and the event is still sent to
  listeners. A missing `IMPORT{file}` or a failing program is still only a false key. A database or
  tag index that cannot be written also fails the event (see "udevd").
- **`IMPORT` matches like systemd:** `IMPORT{parent}` is true only when at least one property was
  imported, and `IMPORT{...}!=` now matches only when the import failed (before, also when it
  succeeded). `IMPORT{db}` also finds the properties of the event itself, e.g. `PRODUCT` of a USB
  device whose database entry does not exist yet; when both have the property, the database value is
  imported, as in systemd.
- **`rd.*` options in `IMPORT{cmdline}`** are honoured only in an initrd again, as in systemd: since
  3.2.15, `IMPORT{cmdline}="rd.foo"` also matched on the real root. The initrd detection also
  recognises initrds without `/etc/initrd-release` (e.g. initramfs-tools), see "udevd".
- **Substitutions that do not fit** make a match fail (debug message) and an assignment be skipped
  (warning), instead of using a cut value. Invalid substitutions (`$attr`/`$env` without `{...}`, a
  missing `}`) stop the substitution with a warning. In `$result{N}`/`%c{N}` the parts are separated
  by any whitespace, leading whitespace is skipped, and a non-numeric N is an error, also in
  `udevadm verify`.
- **Private properties** (names starting with `.`) are now passed to `RUN`, `PROGRAM` and
  `IMPORT{program}` programs and to udev monitor listeners, as systemd has done since v220; they are
  still not stored in the database. `/bin/sh` (dash) drops such variables from the environment of
  the commands it runs.
- **`OWNER`/`GROUP` resolved at event time** (from substitutions) that cannot be resolved are logged
  and leave the owner or group unchanged (before, root). With `OPTIONS+="static_node=..."` an unknown
  user or group drops only that key, too.
- **`/etc/scsi_id.config`** is read with systemd's parser: a line that cannot be parsed, e.g. with
  `options=` and nothing after it, or one that is too long, makes `scsi_id` fail (exit status 1, no
  output) with an error naming the file and the line, e.g. "Error parsing config file
  /etc/scsi_id.config line 3 '…'" (deviation: systemd does not name the file), also when the line
  comes after the global `options=` line and is only found while the options of the device are looked
  up, and so does an option that a `vendor=` line may not set (see "scsi_id" under "Builtins and
  helper programs"); an unterminated quote is accepted; options are split on runs of spaces and tabs;
  the last line needs no newline; a NUL or CR ends a line. White space after a comma
  (`vendor="ATA", options=-g`) is still accepted, as in 3.2.x (deviation: systemd refuses it).

- **Protected properties in `IMPORT` and hwdb:** `IMPORT{program}`, `IMPORT{file}`, `IMPORT{db}`,
  `IMPORT{cmdline}`, `IMPORT{parent}` and hwdb entries no longer set the properties that `ENV{}`
  cannot set: `ACTION`, `SEQNUM`, `SYNTH_UUID`, `SYNTH_ARG_*`, `DEVPATH`, `DEVPATH_OLD`, `SUBSYSTEM`,
  `DEVTYPE`, `DRIVER`, `MODALIAS`, `DEVNAME`, `DEVMODE`, `DEVUID`, `DEVGID`, `MAJOR`, `MINOR`,
  `DISKSEQ`, `PARTN`, `IFINDEX`, `INTERFACE`, `INTERFACE_OLD`, `DEVLINKS`, `TAGS`, `CURRENT_TAGS`,
  `USEC_INITIALIZED` and `UDEV_DATABASE_VERSION`. They are skipped with a debug message ("Property "…"
  cannot be set, ignoring."; `IMPORT{parent}` skips them silently). Before, a program or file could
  make udevd send the event as another device, action or sequence number, and the database kept such
  values. So `IMPORT{db}=="DEVNAME"` and `IMPORT{cmdline}` with such a name are always false now, and
  `IMPORT{parent}` is false for a parent that has only such properties. Loading the rules and
  `udevadm verify` warn about such a name in `IMPORT{db}` or `IMPORT{cmdline}` ("IMPORT{db} property
  'DEVNAME' cannot be set, it is never imported."), the line is kept, and `udevadm verify` fails
  (deviation: systemd a446e8ff2c imports these properties). udev(7) and hwdb(7) document it, and
  udev(7) now says that `IMPORT{parent}` imports all properties of the parent, from its uevent and its
  database.
- **`IMPORT{program}` output** is split into lines like systemd: a line ends at every `\n` or `\r`,
  and backslashes and quotes are not special; only spaces, tabs and line breaks are removed around
  keys and values, also in `IMPORT{file}` (before, lines ended only at `\n`, and any white space, also
  `\v` and `\f`, was removed); of output that does not fit, everything after the last line break is
  dropped.

### Network interface names

- **Naming schemes:** the `net_id` builtin implements systemd's network interface naming schemes,
  v238 to v261, plus `eudev`, which generates exactly the names of eudev 3.2.15 and older, and
  `latest`, the default, which is v261 (systemd a446e8ff2c defines no v262 scheme). The scheme is
  exported as `ID_NET_NAMING_SCHEME`. **With the default, interfaces that `80-net-name-slot.rules`
  renames get different names than with 3.2.15**, for example:
  - virtio-net NICs: `ens<N>`/`enp0s<N>` instead of `enx<MAC>`;
  - NICs that report a port name (e.g. Intel X710/X722/E810, Mellanox mlx5, Broadcom bnxt): an
    `np<port>` suffix, e.g. `enp59s0f0np0`, `eno1np0`;
  - SR-IOV virtual functions are named after their PF (`eno1v0`), representors get `...r<vf>`;
  - firmware onboard indexes above 65535 (e.g. VMware's `eno16777736`) are ignored, so such NICs get
    slot or path names; an `acpi_index` of 0 gives `eno0`;
  - servers with ACPI `_SUN` get `ens<slot>[f<fn>]`; NPAR/ARI functions use the full function number;
  - IBM Z: `enc<busid>` without leading zeros instead of `enccw0.0.xxxx`, virtio-ccw gets
    `enc<busid>`, PCI slots are named by function_id;
  - newly named: IBM PowerVM VIO (`env<N>`), ARM64 ACPI platform NICs (`ena...`), DeviceTree boards
    (`end<N>`, WLAN `wld<N>`), USB NICs on SoC host controllers (`enu...`), InfiniBand (`ib...`),
    netdevsim, Xen netfront (`enX<N>`), MCTP (`mc...`) and mlx5 sub-functions (`...S<sfnum>`);
  - Azure MANA NICs drop the PCI domain; the hwdb properties `ID_NET_NAME_ALLOW*` and
    `ID_NET_NAME_INCLUDE_DOMAIN` are honoured.
- **Selecting the scheme:** `net.naming_scheme=` on the kernel command line, the new
  `net_naming_scheme=` key in udev.conf, or `$NET_NAMING_SCHEME`, which takes precedence unless it
  starts with `:`, in which case it is used only when neither of the others selects a scheme. To keep
  the names of 3.2.15, set `net_naming_scheme=eudev` in udev.conf. An unknown name is skipped with
  systemd's warning "Unknown interface naming scheme '…' requested, ignoring." and the next setting in
  that order is used (deviation: systemd uses the default, so a typo on the kernel command line would
  override the scheme pinned in udev.conf).
- **Renaming policy of 80-net-name-slot.rules, for every scheme** (the `eudev` scheme pins only the
  names `net_id` generates):
  - the name from the hwdb (`ID_NET_NAME_FROM_DATABASE`) comes first, as in systemd; today this
    renames only the Dell iDRAC virtual USB NIC, to `idrac`;
  - interfaces named by userspace, already renamed (e.g. in the initrd), or named predictably by the
    kernel (`name_assign_type` 2, 3 or 4) are not renamed, like systemd's "keep" and "kernel"
    policies, also on `udevadm trigger --action=add`; `NAME=` in earlier rules still applies;
  - a candidate that is not a valid interface name (systemd's `ifname_valid()`: longer than 15
    characters, only digits, `.`, `..`, `all`, `default`, `:`, `/`, `%`, whitespace or non-ASCII, or an
    interface index in another notation such as `0x10`, `+5`, `0b1`, `0o7`) is skipped and the next
    one is used; a MAC based name of an all-zero address is never used. The rules file, like
    `80-net-altnames.rules`, is generated by `tools/gen-net-naming-rules.py` (with `--help`).
- **`NAME=` on network interfaces:** a name longer than 15 characters is refused with an error
  (before, it was silently cut). With schemes v249 and later, invalid characters are replaced by `_`
  and a name that is still invalid is ignored with "Invalid network interface name, ignoring"; with
  older schemes, including `eudev`, such a rename fails. `NAME=` on any other device is ignored with
  "Only network interfaces can be renamed, ignoring." (see "Rules").
- **Alternative interface names:** on Linux 5.5 and later, udevd assigns the predictable names
  (`ID_NET_NAME_FROM_DATABASE`, `_ONBOARD`, `_SLOT`, `_PATH`, `_MAC`, also those longer than 15
  characters) as alternative names to new interfaces, like systemd's default
  `AlternativeNamesPolicy=`; `ip link` shows them and accepts them instead of the interface name. This
  is done by `OPTIONS+="net_altnames"` in the new `80-net-altnames.rules`, installed also with
  `--enable-rule-generator`, independent of `net.ifnames=`, unless eudev is built with
  `--with-net-ifnames-default=no` (see below). `net_altnames=no` in udev.conf disables it; an invalid
  or empty value is reported, with the value, by udevd and `udevadm test`. Existing interfaces get
  them at their next add event.
- **Default of `net.ifnames=`:** the new configure option `--with-net-ifnames-default=yes|no` sets
  what happens without `net.ifnames=` on the kernel command line. With `yes`, the default, nothing
  changes: `80-net-name-slot.rules` renames interfaces unless the kernel command line has
  `net.ifnames=0`, and alternative names are assigned either way. With `no`, interfaces keep the names
  the kernel gave them and get no alternative names unless the kernel command line has
  `net.ifnames=1`. The installed `80-net-name-slot.rules` and `80-net-altnames.rules`, the configure
  summary ("net.ifnames default:") and udev(7), udevd(8) and udev.conf(5) follow the option. With
  `--enable-rule-generator` and `yes`, the rule generator replaces `80-net-name-slot.rules`, which is
  not installed, and `net.ifnames=` changes nothing; with `no`, `80-net-name-slot.rules` is installed
  too, and with `net.ifnames=1` the rule generator records no names (see "Rule generator" below).

- **Rule generator** (`--enable-rule-generator`), with parts of Debian's generator, which Devuan
  ships: `75-persistent-net-generator.rules` records only interfaces that the kernel named by
  enumeration (`name_assign_type` 1, or unreadable as before Linux 3.17), not those of more virtual
  machines (VirtualBox, Xen by its MAC prefix, more VMware prefixes, Microsoft Azure, Ravello, old
  libvirt, Parallels, Oracle VM, Nutanix AHV, bhyve and Proxmox VE, as before for KVM, VMware and
  Hyper-V; the Azure prefixes are Microsoft's, so Microsoft hardware gets no rule either), of
  User-mode Linux and mac80211 monitor interfaces; `dev_id` is matched for every MAC address, not for
  S/390 devices; the comment of a rule names the driver of the nearest device that has one, e.g.
  "(r8152)" instead of "(usb)". `write_net_rules` writes no rule for an interface without a MAC
  address or bus id, also with `INTERFACE_NAME` (before, a rule that matched every interface of its
  type; an interface of KVM, VMware or Hyper-V now gets the warning below too when it has
  `INTERFACE_NAME`, where its rules ended silently before), and logs "no MAC address or bus id to
  match … with, writing no rule" and "Cannot lock …!" also to the kernel log, as warnings, when
  `/dev/kmsg` can be written. udevd renames an interface to a temporary name only when it gets a new
  name of its own: one without, e.g. of a virtual machine, keeps its name also when a stale rule
  gives that name to another interface (before, it became e.g. `eth126`); the other interface then
  keeps its own name; it waits for the name, up to 90 s but not beyond the event timeout, only while
  udevd has not handled the add event of the interface that has it (the handled ones are recorded in
  `/run/udev/net-added/`). udev(7) describes the generator in a new section.

### Persistent storage links

- **by-path names change** on these systems; update fstab, crypttab, LVM filters and scripts that use
  them:
  - **Hyper-V and Azure** guests (VMBus as an ACPI device): SCSI disks and DVDs are named after the
    controller's instance GUID and the LUN, e.g. `acpi-VMBUS:00-scsi-0:0:0:0` becomes
    `acpi-VMBUS:00-vmbus-f8b3781b1e824818a1c363d806ec15bb-lun-0`; before, LUNs on different
    controllers could share a name;
  - **IBM Z:** zfcp LUNs change from `ccw-<dev>-zfcp-<WWPN>:<LUN>` to `ccw-<dev>-fc-<WWPN>-lun-<LUN>`;
    SCSI devices below a CCW device (e.g. virtio-scsi) gain the SCSI address (`ccw-0.0.0005` becomes
    `ccw-0.0.0005-scsi-0:0:0:0`); qeth, AP and IUCV devices get `ccwgroup-...`, `ap-...` and
    `iucv-...` names; DASD and virtio-blk paths do not change;
  - **devices behind an SPI controller** get the chip select appended, e.g. `platform-fe204000.spi`
    becomes `platform-fe204000.spi-cs-1` (for ACPI-enumerated devices the ACPI instance number, e.g.
    `-cs-00`);
  - devices whose sysfs strings contain control characters or invalid UTF-8 get no `ID_PATH` instead
    of one with escape sequences in it;
  - the default SCSI path (`...-scsi-H:B:T:L`) prints numbers that do not fit a signed int as
    negative numbers, as systemd does (e.g. LUN 4294967295 gives `scsi-0:0:0:-1`);
  - SCSI LUNs of 2^32 and more (third and fourth addressing level) get their full 8-byte LUN,
    `lun-0x<16 hex digits>`, one link per LUN; 3.2.15 named them after their lower 32 bits (on 32-bit
    systems all of them `lun-0xffffffff00000000`), so different LUNs could share a link (deviation:
    systemd a446e8ff2c names them `...(null)`);
  - the old `...-ata-<port>` link and the `ID_PATH_ATA_COMPAT` property are given only to the device
    that owns the name alone: the one on bus 0, target 0 of the ATA port (a single SATA disk, a PATA
    master, the disk on port 0 of a port multiplier) or the only device of the port (a lone PATA or
    ATAPI slave, a lone disk behind a port multiplier); a slave next to a master and port-multiplier
    disks next to others no longer get it, so the link no longer points to whichever came last
    (deviation: systemd sets the property for every device). When the bus 0/target 0 device appears
    after a lone device of its port got the link, that device and its partitions get a change event
    and drop it (this can add change events during coldplug); when any device of the port is
    removed (also a PATA slave or a disk behind a port multiplier) and one device is left on the
    port, that device and its partitions get a change event and take the link, unless the device
    has it already (a new rule in `60-persistent-storage.rules` runs `path_id` for the remove event
    of every SCSI target).
- **by-id links:** partitions of host-managed zoned (ZAC) ATA disks get their
  `scsi-<serial>-part<N>` links again (deviation: systemd creates the link only for the whole disk).
  Tapes whose serial number contains C1 control characters get their `tape/by-id/scsi-*` links back,
  and a serial with a TAB is now refused, exactly as in systemd.

### Scripts that call udevadm

- **`udevadm test` no longer changes the system** (systemd 089bef6631 and follow-ups): it renames no
  interface, creates or changes no device node, permission, label or symlink, writes no database,
  tag, `ATTR{}` or `SYSCTL{}` value, loads no module, remaps no keys and issues no btrfs ioctl (as
  `udevadm test-builtin` already did; the rules test runner of `make check` now also skips the
  keyboard and btrfs builtins). It runs no program except the helpers
  `ata_id`, `cdrom_id`, `dmi_memory_id`, `fido_id`, `mtd_probe` and `scsi_id`, given by exact name or
  by their path in udev's helper directory (deviation: systemd matches any command line that starts
  with a helper name). `cdrom_id` gets the new `--dry-run` option there and does not lock or eject the
  media (deviation). So properties from other programs are missing, `PROGRAM` results are empty, and
  `RESULT==`, `%c` and `PROGRAM!=` behave accordingly; a renamed interface keeps its `INTERFACE=`. A
  value that `ATTR{}=` would write is seen by a later `ATTR{}==`.
- **`udevadm test` output format:** stdout carries only a result block of labelled sections (device,
  node owner/group/mode, symlinks, the would-be interface name and alternative names, `ATTR`/`SYSCTL`
  writes, tags, current tags, indented properties, queued commands as `RUN{program} : ...`); the
  banner and log messages go to stderr. Scripts that grep `^KEY=` or `run:` break; use the new
  `--json=`.
- **chroot:** `udevadm trigger`, `control`, `settle` and `monitor` do nothing in a chroot: they log
  "Running in chroot, ignoring request." and exit 0 (systemd c494b739a4). It counts as a chroot when
  the root directory is not the one of PID 1, or `/proc` is not mounted; `$UDEV_IN_CHROOT`, then
  `$SYSTEMD_IN_CHROOT`, override the detection, and the deprecated `$SYSTEMD_IGNORE_CHROOT` disables
  it. All four check their options, the option values and, for `trigger`, the match options first, so
  `--help` and `--version` work in a chroot, and invalid options, values and matches fail there as
  elsewhere; only a valid request is ignored (deviation: systemd's `trigger` and `control` look for a
  chroot before they parse their options; its `settle` and `monitor` parse them first, like eudev).
  Maintainer scripts that run in debootstrap or sbuild chroots and call these commands now do nothing.

- **Exit statuses:** `udevadm trigger` exits 1 when writing a uevent fails (it always exited 0), for
  an invalid `--action=` ("Invalid action 'x'."; was "unknown action" and 2) and for a device that
  cannot be found ("Failed to open the device '…': No such device"; was "unable to open the device"
  and 2); `udevadm test` exits 1 on every error (was 2 to 5); `udevadm test-builtin` prints only the
  error and exits 1 (was the help text and 2 to 6); `udevadm control` exits 1 on every failure and
  stops at the first failing command (was 2, or the status of the last command); `udevadm info` with a
  missing or invalid device exits 1 ('Unknown device "…": No such device'; was 2); `udevadm settle` as
  root exits 1 when the control socket cannot be created (was 0); invalid `--timeout=` values of
  `control` and `settle` exit 1; `udevadm` without a command or with an unknown one exits 1 (was 2);
  `udevadm version` with arguments exits 1 ("Too many arguments."; was 0); `udevadm info` exits 1 for
  a query or `-a` without a device ("A device name or path is required"; was the help text and 2, or
  4), for `--query=name` on a device without a node ("No device node found: No such file or
  directory"; was 5) and for an unknown query type ("Unknown query type 'x'"; was 3); `udevadm settle`
  as root exits 1 when udevd cannot be pinged for another reason than not running, e.g. when it does
  not answer within the ping timeout of at least 5 s ("Failed to connect to udev daemon: …", "Failed
  to wait for daemon to reply: …"; was 0); `udevadm trigger` with an unknown `--type=` ("Unknown type
  --type=x"; was 2) or an invalid match option (see "Match options" below) exits 1; `udevadm test -D`
  exits 1 for a directory that does not exist ("Failed to access '…': No such file or directory") or a
  file ("'…' is not a directory."); `udevadm monitor` exits 1 when a filter cannot be applied.

- **Option parsing:** invalid options are reported with systemd's texts, through the log at error
  level: "udevadm: unrecognized option '-Z'", "option '-n' requires an argument", "option '--hel'
  doesn't allow an argument" and "option '--exp' is ambiguous; possibilities: --export,
  --export-prefix, --export-db" (before, glibc's texts with the command name). An abbreviation shared
  by an option and its alias is ambiguous now, as in systemd and in musl builds:
  `udevadm control --log…` (`--log-level`/`--log-priority`) and `--relo…`
  (`--reload`/`--reload-rules`) must be spelled out. Without a command, udevadm says "Command verb
  required (one of help, info, …).", and for an unknown one "Unknown command verb 'x', did you mean
  'y'?". `systemd-hwdb`, `udevd` and the helper programs (`ata_id`, `cdrom_id`, `collect`,
  `dmi_memory_id`, `fido_id`, `mtd_probe`, `scsi_id`, `v4l_id`) report invalid options with systemd's
  texts too, through the log at error level (e.g. "ata_id: unrecognized option '-Z'"; before, glibc's
  texts on stderr). So do the `blkid` and `hwdb` builtins, whose `IMPORT{builtin}` then fails (before,
  invalid options were skipped silently). The helpers print their help in systemd's layout; `ata_id`
  and `mtd_probe` take exactly one device ("Need exactly one DEVICE argument."; `ata_id` accepted
  more), and `dmi_memory_id` no argument ("This program takes no arguments.").
- **Property order:** properties are listed in the order they were added, which is systemd's order,
  instead of sorted by name: in `udevadm info`, its JSON output, program environments, monitor
  messages and `udev_device_get_properties_list_entry()`; the database `E:` lines are not sorted
  either, but their order can differ from systemd's. The values of `DEVLINKS` and `TAGS` stay sorted
  (deviation: systemd uses hash order, which changes between runs).
- **Device arguments** of `info`, `test`, `test-builtin`, `trigger` and `wait` are resolved like
  systemd: a device ID (e.g. `b8:0`, `n1`, `+net:lo`), then the path (also relative, or through a
  symlink), then the path below `/dev` or `/sys`; a path outside `/dev` and `/sys` is an unknown
  device, and for `info`, `test`, `test-builtin` and `trigger` a path that is not a device gives "No
  such device", also e.g. `/dev/null/x`, as in systemd (`wait` warns about it, see "udevadm");
  `/dev/block/MAJ:MIN` and `/dev/char/MAJ:MIN` are looked up by the number, so they work without the
  symlinks. Several `--parent-match=`/`--name-match=` of `trigger` now all count (before, only the
  last).
- **Match options:** `udevadm trigger` checks `--attr-match=`, `--attr-nomatch=`, `--property-match=`
  and `--tag-match=` like `udevadm info --export-db` and systemd: an invalid attribute or property
  name ("a//b is not a valid key name"), a `--property-match=` without `=` ("Missing '=' in key/value
  pair FOO.") and an invalid tag name ("Failed to add tag match '../data': Invalid argument") fail
  with exit status 1 (before, they were accepted, and arguments were cut at 4096 bytes), also in a
  chroot (see above); `udevadm info` checks them also without `--export-db` ("'../data' is not a valid
  tag name"). Both take attribute paths relative to the device, e.g. `queue/rotational` or `../size`,
  and refuse an empty name, a leading `/`, empty components and `.` components (deviation: systemd
  refuses every name with a `/`). A tag name may contain only letters, digits, `-` and `_` and be at
  most 255 bytes long, also in `udev_enumerate_add_match_tag()` (EINVAL); before, e.g.
  `--tag-match=../data` listed every device with a database entry.
- **Terminal output:** colors need both stdout and stderr on a terminal and `$TERM` set, and use
  256/24-bit colors (`$SYSTEMD_COLORS`); log messages to a terminal are colored by level by default
  (see "Logging"); `udevadm info` output and all help texts go through a pager on a terminal
  (`--no-pager`, `$SYSTEMD_PAGER`). See "udevadm".

### libudev users

- Several public functions changed behaviour, as in systemd: property order and validation, sticky
  tags, syspath and attribute checks, device lookups and their error codes, parent devices, the device
  IDs of drivers and of devices without a subsystem, the devices that enumerations list (e.g. the
  /sys/bus/*/drivers directories, each device only under its own subsystem), the tag names that
  `udev_enumerate_add_match_tag()` accepts, devices received from a monitor keeping the values of
  their event, the errno of `udev_hwdb_new()`, and udev.conf being read once per process. See
  "libudev" for the list.

### Since 3.2.14: changes that 3.2.15 made without a release note

- **`SYMLINK=` values** are checked and normalized: a value with a `..` component or an absolute path
  outside `/dev/` is refused; a `/dev/` prefix is accepted; a trailing slash is removed, so a value
  that substitutes to `foo/` creates `/dev/foo` (in 3.2.14 that made the worker loop until the event
  timeout). New in this release: redundant slashes and `.` components are removed instead of refused
  (`a//b` creates `/dev/a/b`), components longer than NAME_MAX and control characters are refused (the
  latter unless `OPTIONS+="string_escape=none"`), invalid values are warnings, and devlinks read from
  the database are checked and normalized the same way.
- **Tags** may contain only letters, digits, `-` and `_`. Invalid tags recorded in the database by
  3.2.14 are ignored when it is read, so they vanish from the device (`udevadm info`, `TAGS`); their
  `/run/udev/tags/<tag>/` entries stay until reboot, so `udevadm trigger --tag-match=<tag>` still
  finds those devices.
- **`TAG=""`** only clears the tags; an empty tag cannot be added. With sticky tags (see "Rules") it
  clears the current tags only.
- **Protected properties:** an `ENV{}` assignment to a property owned by the kernel or udevd
  (`DEVPATH`, `SEQNUM`, `MODALIAS`, ...) drops the whole rule line, not only that key.
- **Host-managed zoned (ZAC) SATA drives** on non-libata transports (mpt3sas, megaraid, smartpqi,
  USB SAT) are identified by `ata_id`: their `ID_SERIAL`, `ID_BUS` and `ID_MODEL` change, and they get
  `disk/by-id/ata-*` links. The whole-disk `scsi-*` link is kept by a rule, which also gives libata
  ZAC disks an additional `scsi-*` link; their partitions get their `scsi-*-part<N>` links again with
  this release (deviation: systemd's rule covers only whole disks).
- **ATA drives behind SCSI/ATA translation layers** whose sense data has bit 7 of the response code
  set (e.g. some SAS HBAs) are identified by `ata_id`: they get `ID_BUS=ata` and
  `disk/by-id/ata-<model>_<serial>` links, and lose the `disk/by-id/scsi-<serial>` links (disk and
  partitions) that 3.2.14 created. eudev ships no compatibility rule for them.
- **Helper exit statuses and outputs:** `ata_id`, `cdrom_id`, `mtd_probe` and `v4l_id` exit 0
  silently when the device node vanished (ENODEV, ENXIO, ENOENT; `ata_id`, `mtd_probe` and `v4l_id`
  also on ENOMEDIUM); `scsi_id` exits 1 when it cannot open the device; zoned SCSI disks get
  `ID_TYPE=zbc`.

## udevd

- **Locked block devices:** while another program holds an exclusive BSD lock (flock(2)) on a block
  device, e.g. `udevadm lock`, `sfdisk --lock` or mkfs under flock, udevd postpones the events of
  that disk and its partitions instead of processing them (systemd 5d354e525a and follow-ups). It
  retries every 200 ms, at once on a new event for the disk, and when a watched device is closed after
  writing; `udevadm settle` waits for postponed events. `dm-*`, `md*` and now `drbd*` devices and
  remove events are not postponed. After 3 minutes the event is given up and only the kernel event is
  passed to listeners; the device's database entry and tags are kept (deviation: systemd deletes the
  database entry).
- **ID_PROCESSING:** while udevd processes a device that already has a database entry, and while its
  `RUN` programs run, the database has `ID_PROCESSING=1` (systemd f6bda694f9). `RUN` programs see it,
  and `udevadm wait` and `udevadm info --wait-for-initialization` now wait until the `RUN` programs
  have finished. Properties added by `RUN{builtin}` are stored in the database. The sticky bit of
  `OPTIONS="db_persist"` is kept while the event is processed (deviation: systemd loses it until the
  final write). A failed event never leaves `ID_PROCESSING=1` behind: the previous database entry is
  written back and the tag index restored (the tags the failed event added are removed, the previous
  ones added again); when the entry cannot be written back, it is removed together with its tags
  (deviation).
- **Failed events:** an event whose tag index or database entry cannot be written fails like in
  systemd: `RUN` is not executed, the event is still sent to listeners, and an entry that cannot be
  written is removed. When the final database write after `RUN` fails, only that error is logged, and
  the previous entry and tag index are restored as for a failure before `RUN` (deviation); the rules
  test runner of `make check` does the same.
- **Trace logging:** new kernel option `udev.trace[=BOOL]` (`rd.udev.trace` in the initrd) and
  `udevadm control --trace=BOOL` (systemd 695c592a03, 25a2e4738b). Trace mode logs at debug level and
  logs like systemd: every rule key with its result (PASS/FAIL), the compared strings, format
  substitutions, set, imported and removed properties and tags, "DONE" for actions, each action once,
  the conditions checked on parent devices ("Checking conditions for parent devices (including
  self):") and the replaced characters, like `udevadm test -v`. `udevadm control --revert` resets the
  log level, trace mode, the maximum number of workers and the properties set by `udevadm control`
  (systemd c53d155d8d). `--log-level=` restarts the workers only when the level changes.
- **Control socket:** udevd answers `--trace` and `--revert` with a reply, so that `udevadm control`
  can tell an older udevd ("udevd does not support --trace, restart it after upgrading."); it logs
  control messages of unknown type; it ignores a negative maximum number of workers with a warning
  (deviation: systemd logs at debug level) and an invalid log level, also a negative one, with a
  warning; a maximum of 0 workers (`udevadm control -m 0`, `-c 0`, `udev.children_max=0`) means the
  computed default (before, udevadm refused 0, and a 0 sent over the control socket stopped udevd from
  starting workers); `--start-exec-queue` starts the held events at once instead of after up to 3
  seconds. udevd handles all the messages that `udevadm control` sends over one connection, in their
  order (eudev's own message type 11 starts such a connection; an older udevadm, which sends one
  message per connection, still works).
- **Default number of workers** is `MIN(2 x CPUs + 16, MAX(RAM / 128 MiB, 10), 2048)` (systemd
  e438c57a64, 88bd5a32e8, fe56acd8e0), with the CPUs counted in udevd's affinity mask and the RAM
  limited by `memory.max` of PID 1's cgroup (cgroup v2), or by `memory.limit_in_bytes` when PID 1 is in
  a cgroup v1 memory hierarchy, found through /proc/self/mountinfo wherever it is mounted (deviation:
  systemd a446e8ff2c reads only cgroup v2). Before it was `8 + 2 x CPUs`. Examples (CPUs, RAM: before
  -> now): 2, 1 GiB: 12 -> 10; 4, 3 GiB: 16 -> 23; 8, 2 GiB: 24 -> 15; 16, 64 GiB: 40 -> 48. udevd(8)
  and udev.conf(5) document it.
- **Configuration sources** are merged like systemd: udev.conf < udevd options < kernel command line <
  `udevadm control`, and 0 means "not set" for the maximum number of workers, the exec delay and the
  event timeout (e.g. `udev.children_max=0` no longer overrides `--children-max=5`). New udev.conf keys
  `children_max=`, `exec_delay=`, `event_timeout=` and `resolve_names=` (systemd 4b3ca79ea9,
  a14e7af162); `exec_delay=` and `event_timeout=` take time spans. Invalid or empty values of these
  keys and of `timeout_signal=` are warned about when udevd starts, e.g.
  "/etc/udev/udev.conf:1: Failed to parse children_max=abc, ignoring: Invalid argument", and the
  previous valid value is kept.
- **udev.conf drop-ins** (systemd 07f5e35fe7, 6378f257e7): `udev.conf.d/*.conf` files in the
  directories of udev.conf (see "Packagers") are read after the main udev.conf, sorted by name; a
  drop-in overrides one of the same name in later directories, and an empty file or a symlink to
  `/dev/null` masks it. A masked or non-regular drop-in is skipped (deviation: systemd's parser then
  ignores the whole configuration). `udevadm cat --config` shows the drop-ins, `udevadm hwdb --root`
  reads `hwdb_format=` (see "hwdb" for format 1) from those below the root, and udev.conf(5) documents
  them, with the alias page udev.conf.d(5).
- **Event order:** kernel uevents are queued by their sequence number, as in systemd (6a04c1e518): an
  event that arrives out of order is put before the later ones ("Unordered event is received (…),
  reordering." at debug level), so it no longer runs at the same time as an earlier event of the same
  device, and an event that is queued already is refused ("The event (SEQNUM=N) has been already
  queued."); before, events were queued in the order they arrived.
- **Rules reload:** like systemd, udevd decides from the rules files themselves whether the rules
  changed: it remembers the status of every rules file it read, and before it starts queued events, at
  most every 3 seconds and not in the first 3 seconds after it started, it checks whether a rules file
  was added, removed or changed ("Udev rules need reloading" at debug level). An empty file, a file
  whose name does not end in `.rules` or a new empty directory no longer makes it reload the rules and
  kill the idle workers, and rules and builtins are reloaded separately; udevd no longer watches the
  rules directories with inotify, and a rules file written in the first 3 seconds after udevd started
  is used from then on. udevd no longer reloads the rules, and kills its idle workers, a few seconds
  after it started, because it had created `/run/udev/rules.d` after loading them. When the rules
  cannot be loaded again, udevd keeps the old ones, with systemd's warning "Failed to read udev rules,
  using the previously loaded rules, ignoring: …" (before, it tried again silently).
  `udevadm control --reload` and SIGHUP load the rules and the builtins at once, also when nothing
  changed (deviation: systemd reloads only what changed; eudev thus also resolves the user and group
  names again).
- **Timeouts:** `--event-timeout=`, `--exec-delay=`, `udev.event_timeout=` and `udev.exec_delay=` take
  time spans with units (`500ms`, `5min`, `infinity`); plain numbers are still seconds; negative
  delays are refused. An event timeout of 0 or below 1 ms means the default of 180 s (before, 0 made
  udevd kill every worker); an exec delay at least as long as the event timeout is ignored. udevd
  kills a worker only 10 s after the event timeout (systemd's `extra_timeout_usec`;
  `$UDEV_EXTRA_TIMEOUT_SEC` or `$SYSTEMD_UDEV_EXTRA_TIMEOUT_SEC`, at most 5 h), so the worker kills a
  timed-out program itself and the event reaches listeners normally. Worker deadlines are checked on
  every iteration of udevd's main loop, so hanging workers are warned about and killed on time also on
  busy systems; a worker still running 5 s after the timeout signal gets SIGKILL ("Worker [PID]
  processing SEQNUM=N did not exit after SIGTERM, killing it with SIGKILL."), or 90 s after a signal
  that dumps core (e.g. `timeout_signal=SIGABRT`), so that the core is complete.
- **Programs** (`PROGRAM`, `IMPORT{program}`, `RUN`): each gets the time its event has left, and the
  warning comes after a third of it, as in systemd; a program is killed exactly at the event timeout,
  with one message, and the timeout signal is sent once; a program is not started after its event has
  timed out ("The event already takes longer (…) than the timeout (…), skipping execution of '…'."),
  and a `RUN` program whose `exec_delay` would reach the timeout is skipped ("Cannot delay execution
  of "…" for …, skipping."). Programs start with all signals at their default action and none blocked,
  like systemd's (before, signals that whoever started udevd ignored stayed ignored).
- **How programs are run,** like in systemd: a program is found, and checked to be an executable
  regular file, before udevd forks for it ("Failed to find and pin callout binary "…": …"; see
  "`$<NAME>_PATH`" above); the process is named "(spawn)", ends when its worker dies, unsets
  `$NOTIFY_SOCKET`, and gets only stdin, stdout and stderr: before, it also inherited an extra
  descriptor of /dev/null and every descriptor that whoever started udevd left open. stdin is
  /dev/null, opened read-only when both stdout and stderr go to udevd (as at the default log level);
  stdout and stderr are blocking, like in systemd since v256, so a program that writes more than 64
  KiB no longer fails with EAGAIN. A program whose standard streams cannot be set up, e.g. when
  /dev/null is missing, is not run ("Failed to rearrange stdio fds: …"); every failure to set up or
  execute the program exits with status 1. udevd reads the output of a program until it exits, also
  after the timeout signal, so a program no longer blocks on a full pipe, and its output is logged at
  debug level in full; a background process that a program leaves behind with its stdout or stderr no
  longer keeps the event waiting until the timeout; output printed after a program closed its stderr
  is logged too, and no UTF-8 character is split between two messages; after a read error, udevd tries
  again once a second, with a warning (deviation: systemd tries again at once, in a loop). udevd
  raises its limit of open files to the highest the kernel allows, like systemd, and programs get the
  soft limit 1024.
- **Exit and idle workers:** on exit, a worker still processing an event gets SIGKILL 5 s after
  SIGTERM, and udevd waits at most 30 s from the start of the exit (before, it left a hanging worker
  behind after 30 s, or never exited while something kept waking it up); idle workers are killed 3 s
  after the last event, also while control messages keep arriving, but not while a child re-reads a
  partition table, after whose exit the 3 s start, nor while a uevent is pending (systemd a0d2576705,
  v262.1, only does not start its timer then).
- **`timeout_signal`:** the signal sent to programs and workers when the event times out is
  configurable with `timeout_signal=` in udev.conf, `--timeout-signal=` and `udev.timeout_signal=`
  (default SIGKILL; systemd e209926778). Signals that cannot terminate a process (SIGCHLD, SIGCONT,
  SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU, SIGURG and SIGWINCH) are refused with a warning such as
  "timeout_signal=SIGCHLD cannot terminate a process, ignoring." (deviation).
- **`udev.blockdev_read_only[=BOOL]`:** new kernel option that marks physical block devices read-only
  when they appear (systemd 95ac523030).
- **Partition table re-read:** when a whole disk is closed after writing, its partition table is
  re-read in a child process named `(udev-synth)` (systemd 9c47b1527e; see "Process names"), so a slow
  disk no longer blocks udevd. GPT tables are re-read partition by partition with libblkid and BLKPG
  (systemd 757887d01d), so a partition that is in use no longer keeps the others from being updated
  (e.g. growing a partition on a disk whose first partition is mounted); other tables, and builds
  without libblkid, still use BLKRRPART. Like in systemd, the child starts with all signals at their
  default action and none blocked, and ends when udevd dies. The re-read waits until no worker
  processes an event of the disk or of its partitions, and their events wait until the re-read is
  done; when the disk is closed after writing again during the re-read, the table is re-read once more
  afterwards, but only when the running re-read may have missed that write (deviation: in systemd
  a446e8ff2c, and in eudev before, a re-read that met such an event gave up and only change events
  were sent, so new partitions could be missing, e.g. after `udevadm lock` around a program that
  writes the table). The change events of the re-read, and those that udevd synthesizes for other
  block devices closed after writing (partitions, dm devices, ...), carry a random UUID and the caller
  information when they fit (see "Caller information in triggered uevents" below; in systemd
  a446e8ff2c they carry only a UUID). `udevadm settle` waits for the events of the other block
  devices, at most a minute after each of them was synthesized, but not for one that the kernel did
  not send (deviation: systemd waits the minute then). Deviations: when the partition table cannot be
  applied, udevd sends change events for the disk and for the partitions that did not get an event
  yet, with a warning that names them (systemd v259 sends nothing); if the child cannot be forked, or
  its PID cannot be stored, the re-read runs synchronously, with a warning; after BLKPG updates, the
  disk and resized partitions get change events (after the kernel's add events of new partitions); the
  child resets its OOM score like the workers. The debug messages about a re-read name the disk by its
  kernel name, e.g. `sda`, not by its device node.
- **Program limits:** the monitor messages and the environment of programs have no fixed size any
  more (before, a device with more than 4096 bytes or 128 properties was not broadcast); `TAGS`,
  `DEVLINKS` and `CURRENT_TAGS` are no longer cut at 1024 bytes; database entries may be up to 1 MiB
  (was 16 KiB; deviation: systemd has no limit).
- **Initrd detection:** `rd.*` options are honoured in an initrd only. An initrd is detected by
  `$SYSTEMD_IN_INITRD` (boolean), then `/etc/initrd-release`, as in systemd, and then (deviation) a
  memory root file system with `/init` and one of `/conf/initramfs.conf` (initramfs-tools),
  `/lib/dracut-lib.sh`, `/init_functions`, `/etc/initrd.defaults` or `/.modloop`, so that e.g.
  `rd.udev.log_level=` works in initramfs-tools initrds. `$UDEV_PROC_CMDLINE` and
  `$SYSTEMD_PROC_CMDLINE` replace `/proc/cmdline` for testing (systemd 2467cc55f1;
  `$UDEV_PROC_CMDLINE` is eudev's own and checked first).
- **Messages:** udevd logs a single start line, "starting eudev-3.3.0 (udev 262)", at info level
  through its log like its other messages, after it daemonized, also without `--daemon` (deviation:
  systemd logs one only when it daemonizes); before, it logged "starting version 3.2.15" and wrote
  "starting eudev-3.2.15" directly to /dev/kmsg. With `--debug`, udevd prints all its messages on
  stderr, whatever log target the environment or the kernel command line selects, also when it runs as
  PID 1: the warnings about all options, also those given before `--debug`, about invalid log
  settings, about udev.conf, also with `udev_log=err` in udev.conf, and about the kernel command line;
  kernel command line messages are logged with the merged log level. An invalid `--resolve-names=` is
  warned about and ignored ("Invalid --resolve-names= value '…', ignoring."; before, udevd exited with
  status 0), and invalid `--children-max=` and `--ready-notify=` values get messages like systemd's
  ("Failed to parse --children-max= value '…', ignoring: …"). Startup failures are logged once, with
  the real error and systemd v261's texts, e.g. "Failed to create inotify descriptor: …", "Failed to
  read udev rules: …", "Failed to start device monitor: …" and those of the control socket (see
  "Changed log messages"); udevd then cleans up, e.g. removes `/run/udev/control`, and exits with
  status 1 (before, some of them exited with status 0 or 164 and left the control socket behind). A
  worker that cannot set up its event loop exits with an error instead of aborting. A rename of an
  interface that is up (EBUSY) is logged at info level. Program output that does not fit is cut with
  systemd's warning "Truncating stdout of '...' up to N byte." (it was an error naming an internal
  variable). Invalid options are logged at error level with systemd's texts, e.g. "udevd: unrecognized
  option '-Z'" or "udevd: option '--d' is ambiguous; possibilities: --daemon, --debug" (before,
  glibc's texts on stderr, with the path udevd was started with); the exit status does not change.

- **Worker start:** if a new worker's monitor cannot receive devices, the worker is not started, the
  error is logged and the event is retried, as in systemd; before, the event timed out. A new worker
  exits at once when udevd died before the worker asked for its death signal, as in systemd.

- **Caller information in triggered uevents** (systemd #43973, after a446e8ff2c: 66563e97b7,
  b1df918307, 9692552071, 000f4fa03f): the uevents that `udevadm trigger` and udevd trigger (a watched
  device closed after writing, the partition table re-read, eudev's change events after BLKPG updates
  and after a failed re-read, and `path_id`'s change events for the old ATA link) carry a random
  `SYNTH_UUID=` and the caller's `SYNTH_ARG_PID=`, `SYNTH_ARG_Comm=`, `SYNTH_ARG_TimestampRealtime=`,
  `SYNTH_ARG_TimestampMonotonic=` and `SYNTH_ARG_TimestampBoottime=` (note the mixed-case names) on
  Linux 4.13 and later, without systemd's `SYNTH_ARG_PIDFDID=` and `SYNTH_ARG_InvocationID=`. Before,
  the triggered events carried the kernel's `SYNTH_UUID=0`. `udevadm trigger` takes the time once per
  run, udevd for each event; `SYNTH_ARG_Comm=` is the program name with only its letters and digits
  (`udevadm`, `udevd`, or `udevworker` for the events of `path_id`, which a worker triggers), and
  `SYNTH_ARG_PID=` is udevd's own also for the events of its `(udev-synth)` children, or the worker's
  for those of `path_id`; udevd determines it after `--daemon` forks (systemd 000f4fa03f reports the
  PID of the exited parent). The properties can be matched with `ENV{}`, are not stored in the
  database, and udevd's "seq N queued" debug line shows them. The kernel builds an event in a buffer
  of 2048 bytes for at most 32 variables (64 since Linux 5.8): before an event is triggered, the
  `uevent` file of the device is read, and the arguments, and then also the UUID, are left out when
  the event would not fit with them (systemd 66563e97b7 has no such check); on kernels that cut keys
  off the `MODALIAS` of an input device to make room (Linux 6.10, and the stable releases since
  4.19.317, 5.4.279, 5.10.221, 5.15.162, 6.1.95, 6.6.33, 6.8.12 and 6.9.3), only the UUID may cost it
  keys. The `uevent` files of power supplies and remote control receivers (`rc`) are not read, as
  reading them queries or waits for the hardware (a power supply before Linux 5.8 is counted by its
  attribute files), and on the kernel series 4.19, 5.4, 5.10, 5.15, 6.1, 6.6 and 6.9 to 6.14, some of
  whose releases make the read wait while a driver probes the device, none is read. An event that the
  kernel refuses anyway (ENOMEM) is triggered again without the arguments, and then also without the
  UUID (systemd 66563e97b7 fails such an event); as Linux 4.13 to 4.20 before 4.14.99, 4.19.21 and
  4.20.8 do not report the refusal, on these and on older or unparsable releases
  `/sys/kernel/uevent_seqnum` is read before and after each write, and an unchanged number counts as a
  refusal. A kernel that reports Linux 4.13 or newer is taken to support UUIDs, without a test. On a
  kernel that reports an older version, which may have the support backported, the first triggered
  event finds out: it is triggered with a UUID and, if that event does not arrive within a second,
  again without it, and the plain event decides, as Linux 4.13 and newer add `SYNTH_UUID=0` to it;
  when neither arrives, e.g. for a disk whose events the kernel suppresses while it reads its
  partition table, nothing is decided, and the next event finds out. udevd shares the result with its
  workers and children, and a decided result is stored in `/run/udev/uevent-uuid-support` with the
  boot ID and the kernel release, so that later `udevadm trigger` runs and a restarted udevd use it
  until the next boot. Where the kernel's uevents cannot be watched for this test (e.g. no netlink in
  a container), such old kernels get the events with the plain action. udevadm(8) and udev(7) document
  the properties, udevadm(8) also the test.
- **Watched devices:** a close after writing that the kernel reports while a worker starts to process
  an event of the same device is no longer lost: the worker removes only the inotify watch during the
  event and keeps its symlinks in `/run/udev/watch`, the old one renamed to `<wd>.removed`, which
  udevd removes when the kernel confirms that the watch is gone, also after an overflow of the inotify
  queue; udevd restores the watch of an event that its exit interrupted when it starts again. A device
  that cannot be watched gets one warning, e.g. "Failed to watch device node '…', not watching it: …"
  (before, errors such as "inotify_add_watch(…) failed"), and a missing watch directory one per
  worker. When `/run/udev/watch` is removed while udevd runs, udevd creates it again with the links of
  its watches ("The watch directory /run/udev/watch was removed or replaced, creating it again"), and
  the workers of an earlier udevd that still run after a restart no longer change it. udevd's main
  process no longer reads the `uevent` file of a watched device to look it up after a close (for the
  size check of the change event see "Caller information in triggered uevents"), and its debug
  messages name the device by its kernel name.
- **Starting events:** like `on_post()` of systemd, udevd starts the events that became ready after
  every event source it handled: the events that a worker that died had blocked start at once, waiting
  events start as soon as `udevadm control --children-max=` raises the limit, the events of a device
  that was closed after writing start right after the close was handled, and
  `udevadm control --reload` and SIGHUP take effect at once, so the idle workers exit at once; before,
  this happened up to 3 seconds later when nothing else woke udevd.
- **`/run/udev/queue`** is created once when events are queued and removed when the queue is empty, as
  in systemd a446e8ff2c, instead of being touched in every iteration of udevd's main loop; it is kept
  while a partition table is to be re-read or is re-read, and until the change events that udevd
  triggered itself arrived. As in systemd, when something else removes it while events are queued,
  udevd creates it again only after the queue has emptied (before, at once), so `udevadm settle` and
  `udev_queue_get_queue_is_empty()` see an empty queue meanwhile.

## Rules

- **New `OPTIONS`:** `log_level=<level>` or `log_level=reset` changes the log level for the rest of
  the event in udevd (systemd 1a0bd01529); `dump` and `dump-json` log the current state of the event,
  as text or JSON (systemd b4ffb77669, fd1351e3c8); `net_altnames` (see "Network interface names").

- **Sticky tags** (systemd e77b146f82 and follow-ups): `TAGS` keeps the tags of earlier events, and the
  new `CURRENT_TAGS` lists those of the latest event; `TAG==`/`TAGS==` match the current tags;
  `TAG-=` and `TAG=` affect only the current tags; `/run/udev/tags` entries last until the device is
  removed; the database gains `Q:` and `V:1` lines, and events and `RUN` programs get
  `UDEV_DATABASE_VERSION=1`. Databases of older versions are read with all tags current. Empty tag
  directories are removed when a device is removed (deviation: systemd leaves them).
- **Global properties** set with `udevadm control --property=` are used by `$env{}`/`%E{}` in all
  assignments and by `ENV{}+=` (systemd 854b3c0485). This also fixes `$env{FOO}` being empty in
  `RUN`, `PROGRAM` and `IMPORT` in 3.2.15 although `ENV{FOO}==` matched.
- **Users and groups** are resolved like systemd: numbers always, and names without substitutions with
  `resolve_names=early`, when the rules are read; device node owners that are not system accounts get
  systemd's deprecation warning. The highest system user and group IDs come from `SYS_UID_MAX` and
  `SYS_GID_MAX` in `/etc/login.defs`, read at runtime (deviation: an opt-in build option in systemd),
  with the configure values as fallback; restart udevd after changing them.
  `/etc/systemd/dont-synthesize-nobody`, and also `/etc/udev/dont-synthesize-nobody` (eudev-only),
  stop "nobody"/65534 from being accepted without an account. Only NSS is used.
- **Device node permissions** are applied through an `O_PATH` file descriptor, as in systemd: a
  missing device node, or one with another device number, is skipped and its symlinks are still
  created; a failing chmod or chown is logged and no longer prevents the symlinks. Static nodes use the
  same code: a failure on one no longer stops the others, and `OWNER` without `GROUP` and `MODE` keeps
  the node's mode (it used to force 0600). For static nodes, 0 is a real value for owner, group and
  mode, so e.g. `OWNER="root"` applies.
- **Device node symlinks** (systemd's rework of udev-node.c): when several devices claim a symlink, it
  now reliably points to the one with the highest `link_priority` (the newest one on equal priority),
  also when their events run in parallel; it is never pointed at a device node that no longer exists;
  links are always replaced atomically; a regular file or directory at a link's path is no longer
  replaced; very long link names work; empty `/dev/char`, `/dev/block` and stack directories are
  removed; failures are logged as warnings. `/run/udev/links` entries are symlinks
  `<priority>:<devnode>` named by device ID, in directories with systemd's names, locked through
  `/run/udev/links.lock`; entries of a still running older eudev are taken over, so upgrading without
  a reboot works (going back to an older eudev without a reboot is not supported). On removal, the
  target of a link is resolved through all symlinks, like in systemd 03a65741d7 (v262.1): a link that
  leads to the node of another device is kept, one whose target cannot be resolved is searched for
  again, and the debug messages name the resolved target. Deviations: a broken symlink (outside
  `/dev`, to a non-device or a loop) is repaired by the next add or change event; creating a link is
  retried when another worker removed its parent directory at the same time; a remove event always
  removes the symlinks recorded in the device's database entry, also when a rule evaluated on remove
  uses `SYMLINK=` or `SYMLINK-=` (systemd then leaves dangling links).
- **`ATTR{}` writes** go through libudev: a path outside `/sys` is refused, symlinks inside `/sys` are
  followed, trailing newlines are stripped, values are cut at 4096 bytes (before: refused), the file
  is neither created nor truncated, write errors are logged, and an unresolvable `[subsystem/kernel]`
  key is warned about and ignored. Writes never wait: `ATTR{}=` refuses a FIFO or a socket ("Bad file
  descriptor"), and `SYSCTL{}=` writes only regular files (deviation: systemd waits for a reader).

- **`SYSCTL{}`** of a missing parameter compares as empty, and whitespace around values is stripped.
  `TEST` and `ATTR` paths with a `/*/` component work, as since systemd d5b4357f8f (they never match
  in systemd a446e8ff2c).
- **Attribute values** with a trailing carriage return are used without it in `ATTR{}`/`ATTRS{}`
  matches and `$attr{}`, as in systemd; e.g. `ID_NET_LABEL_ONBOARD` is now set for such PCI labels,
  also with the `eudev` scheme (the interface names do not change). `ATTR` match values are no longer
  cut at 511 bytes when trailing whitespace is stripped (deviation: systemd has the same bug).

- **`[SUBSYSTEM/KERNEL]attr`:** `ATTR{[…]attr}` matches and `$attr{[…]attr}` use the whole value
  instead of the first 511 bytes (deviation: systemd cuts it), a value that does not fit a substitution
  is refused like other substitutions, and an attribute that is a directory fails like in systemd. A
  `[…]` path that does not fit fails `TEST` (also with `!=`) and refuses the `ATTR{}=` assignment with
  a warning ("The path to the attribute … is too long"), instead of using a cut path (deviation).

- **`IMPORT{file}`** reads lines of up to 1 MiB; a longer line stops the import and the key does not
  match (before, lines over 16 KiB were split).
- **FIFOs and devices:** `IMPORT{file}` reads a character device too, as in systemd, e.g. `/dev/null`
  imports nothing and the key is true, but it never waits: a FIFO or a socket is not read, and a file
  without data, e.g. a terminal, fails to be read; the key is false then (deviation: systemd waits for
  a writer and for data). `SYSCTL{}` on a FIFO or another non-regular file fails like an unreadable
  parameter (see "Errors stop the event") instead of blocking the worker (deviation: systemd blocks),
  and on a directory with "Bad file descriptor", like systemd. A `SYSCTL{}` name with a `..` component
  is refused, like in systemd ("Failed to read sysctl "…": Invalid argument"; the match stops the
  event, the assignment is not written), and names are normalized like in systemd (no leading or
  double slashes).
- **`NAME`, `SYMLINK`, `OWNER`, `GROUP` and `MODE`** no longer make a whole rule be skipped on devices
  without a node or interface and on remove events; only those keys are ignored there, as in systemd:
  `NAME=` on any device that is not a network interface is ignored with "Only network interfaces can
  be renamed, ignoring." (before, block and character devices got their own error), and `SYMLINK` on a
  device without a node with a debug message. A cut `IMPORT{builtin}` command no longer marks a
  run-once builtin as run (deviation: systemd has the same bug).
- **Messages:** every message about a rule names its file and the first line of the rule; messages
  while applying a rule start with "DEVICE: FILE:LINE KEY="value": ", with the key as written in the
  rule (`RUN+=`, `OWNER="root"`, `OPTIONS+="…"`) and the value escaped only for control characters and
  invalid UTF-8 (deviation: systemd prints it raw); they name the parent device for keys that match
  parents, with systemd's wording where systemd has the same message; "Replaced N character(s)"
  messages appear only in trace mode; `SYMLINK` and tag names that are refused are warnings; an empty
  `TAG` (at every event) and several `LABEL` keys are warned about; "Added device node symlink" is
  logged only when the link is new, and the symlink messages use systemd's texts; `IMPORT{file}` logs
  "Importing properties from "…""; a failed `PROGRAM` or `IMPORT{program}` logs "Command "…" returned
  N (error)", and lines that `IMPORT` cannot parse are logged at debug level, cut at 2 KiB like in
  systemd ("Failed to parse key and value from "…", ignoring: Invalid argument"); running out of
  memory is "Out of memory.". The eudev-only "Hint: comments..." line after a syntax error is kept.

- **Rule size limits:** line numbers above 65535 and file names are reported correctly.
- **Documentation:** udev(7) describes property rules, sticky tags, the systemd-only keys, the
  `OPTIONS`, how `SYMLINK` names are normalized, how `RUN` arguments are split, the fixed order in
  which the keys of a line are evaluated, the removal of the database symlinks on remove events, FIFOs
  and devices in `IMPORT{file}`, `ATTR{}` and `SYSCTL{}`, the properties that `IMPORT` and hwdb
  entries do not set, what `IMPORT{db}` and `IMPORT{parent}` import, and the order of events, with the
  sound card as example.
- **Tags and links within an event:** programs (`RUN`, `PROGRAM`, `IMPORT{program}`) and monitor
  listeners see the changes of `TAGS`, `CURRENT_TAGS` and `DEVLINKS` that earlier rules made in the
  same event, e.g. a tag added on a remove event reaches the `RUN` programs and the monitors that
  filter by that tag (deviation: in systemd a446e8ff2c, as in eudev before, they could get the values
  from before such a change, once a program had got the environment).
- **Sound cards:** `78-sound-card.rules` imports `SOUND_INITIALIZED` from the database on the add
  event of a card, so that a card whose add event is replayed, e.g. by `udevadm trigger --action=add`,
  keeps it (deviation: systemd's rule does not); its comments say that the change event of the card,
  not the event of `controlC*`, is the point by which the other devices of the card were processed.


## udevadm

- **New commands** (ported from systemd): `udevadm verify` checks rules files (`--root`,
  `--no-summary`, `--no-style`, `-N`) with systemd's checks and messages; `udevadm cat` prints rules
  files and udev.conf (`--root`, `--tldr`, `--config`); `udevadm wait` waits for devices to be
  initialized or removed (`--timeout`, `--initialized=`, `--removed`, `--settle`); `udevadm lock`
  locks block devices while a command runs (`--device`, `--backing`, `--timeout`, `--print`), and now
  that udevd postpones the events of locked devices it works as in systemd. `udevadm verify -N never`
  does not report lines that only set `OWNER=`/`GROUP=` by name as having no effect (deviation:
  systemd does, and fails). `udevadm wait` warns, like systemd, about a path that cannot be a device,
  e.g. one below a file ("Failed to check if device "…" is initialized, assuming not initialized: Not
  a directory").
- **`udevadm cat` and `verify`** resolve symlinks inside `--root`, skip rules files that are not
  regular files (dangling symlinks with a warning), and fail like systemd for a directory or FIFO
  given by name ("Is a directory", "not a regular file"), for `/` (and `.` below `--root`: "Cannot
  assign requested address") and for a path ending in `..` ("Invalid argument"); `verify` reports the
  errors of a rules file given or found through a symlink under the symlink's name. `cat --config`
  shows udev.conf and its drop-ins, prints "# Main configuration file udev/udev.conf not found" when
  there is none, names the mask when the main udev.conf is masked (deviation: systemd says "not
  found"), and logs the directories it looks in ("Looking for configuration in:") at debug level, like
  systemd.
- **`udevadm trigger`:** new `--settle`/`-w`, `--wait-daemon[=SECONDS]`, `--uuid`, `--quiet`,
  `--prioritized-subsystem=`, `--initialized-match`/`--initialized-nomatch` and `--include-parents`;
  `--action=` takes every kernel action (`add`, `remove`, `change`, `move`, `online`, `offline`,
  `bind`, `unbind`; the last two need Linux 4.14) and `help`, and an invalid one fails with "Invalid
  action 'x'."; devices are looked up in systemd's order (positional arguments, then `--name-match=`,
  then `-b`, before the `--wait-daemon` ping), and one that cannot be found fails with "Failed to open
  the device '…': …"; write errors are logged; `-o` is refused instead of aborting; `--wait-daemon`
  reports a failure of the control socket (it said "Out of memory."), and an answer that does not come
  with "Failed to wait for daemon to reply: …", like systemd v261; the match options are checked
  before anything is triggered (see "Match options" under "Before upgrading"). `--include-parents`
  also works with `--tag-match=` and `--parent-match=` (unlike systemd a446e8ff2c, which ignores it
  there). `--wait-daemon` waits in whole seconds. Every event is triggered with a random UUID and the
  caller information when they fit (see "Caller information in triggered uevents" under "udevd"). On a
  kernel that reports a version before Linux 4.13, the first triggered event finds out whether the
  kernel supports UUIDs in synthetic uevents, which takes up to two seconds, once per boot (see
  there): without the support, `--settle` waits for an event of each device instead of hanging, and
  `--uuid` warns and prints no UUIDs. Devices without a subsystem (e.g. `/sys/devices/platform` with
  `--include-parents`) never send a uevent, nor do hidden block devices (e.g. the path devices of
  native NVMe multipath such as `nvme0c0n1`) since Linux 5.12 and the stable releases 5.11.11,
  5.10.27, 5.4.109 and 4.19.184, so `--settle` does not wait for them and `--uuid` prints no UUID for
  them (deviation: systemd's `--settle` hangs on a hidden device); nor for a device for which the
  kernel sent no uevent when it was triggered, e.g. a disk whose partition table the kernel is still
  reading, which `udevadm` sees in `/sys/kernel/uevent_seqnum` (deviation: systemd waits forever); nor
  for a device whose event does not fit with the UUID, or that the kernel refused with it, which
  `--uuid` warns about ("Could not trigger the uevent with a UUID, triggered it without one.").
  `--settle` gives up when none of the remaining events arrived for as long as udevd may take to pass
  an event on, by default 8 minutes and 10 seconds (3 minutes for a locked device, the event timeout
  from `udev.event_timeout=` or udev.conf, 180 s by default, and 130 s for udevd's extra time, the
  SIGKILL and a margin), with a warning that names each device, and exits with status 1 (deviation:
  systemd waits forever). With `--debug`, each triggered device is logged as `<sysname>: Triggered
  '<syspath>': ACTION=<action>, UUID=<uuid>`, without the UUID part when the event was triggered
  without one (systemd 2b0c8c9b48 always prints one). Devices are matched without reading their
  `uevent` files, except with `--property-match=`, `--initialized-match` and `--initialized-nomatch`,
  and when a network interface whose `ifindex` attribute cannot be read is looked up by its index
  (`--tag-match=`, or a device ID such as `n1`) (deviation: systemd reads the file of every device it
  enumerates). udevadm(8) says that a device given as an argument or with `--name-match=` is triggered
  with all its children, and that `--settle` does not wait for the events that rules trigger in
  response. `--type=subsystems` and `--type=all` also list the /sys/bus/*/drivers directories, like
  systemd (see "libudev"); they have no `uevent` file, so nothing is triggered for them, and the
  failed write is logged at debug level only, as in systemd.
- **`udevadm info`:** several devices, `-n` and `-p` can be repeated, and it continues after an
  unknown device; new `--wait-for-initialization`/`-w`, `--property=`, `--value`, `--tree`, `--json=`
  and `--no-pager`; `--export-db` takes `--subsystem-match`/`-nomatch`, `--attr-match`/`-nomatch`,
  `--property-match`, `--tag-match` (several match any of the tags), `--sysname-match`,
  `--name-match`, `--parent-match` and `--initialized-match`/`-nomatch`. Records show the new `M:`,
  `R:`, `J:`, `U:`, `B:`, `T:`, `D:`, `I:`, `Q:` and `V:` fields, in color on a terminal, and `L:`
  also for priority 0. `-a` lists the attributes sorted, also those in subdirectories (e.g.
  `power/control`), shows unreadable ones as "(not readable)", and has JSON (and JSON-SEQ) output.
  `-P` implies `-x`; `-R` is refused; `-c` and `-d` refuse device arguments; `-w0` does not wait, as
  udevadm(8) now says; the match options are checked also without `--export-db` (see "Match options"
  under "Before upgrading"). `--cleanup-db` also removes unused lock files of `/run/udev/links.lock`
  (deviation), and, like systemd, files whose names start with a dot. `udevadm info /sys/class` and
  other directories directly below `/sys`, outside `/sys/devices`, show a pseudo-device as in systemd,
  and devices without a subsystem show their properties and `J:` line only when they have a device
  number or an interface index (see "libudev"). A missing or invalid device fails with the error of
  the lookup, e.g. 'Unknown device "/dev/block/8:9999": No such device', or with 'Bad argument "…",
  expected an absolute path in /dev/ or /sys/, or device ID: …', and exit status 1; every failed
  lookup of a path gives "No such device", also e.g. for `/dev/null/x`, as in systemd. `--tree` also
  lists the /sys/bus/*/drivers directories as "drivers" devices, like systemd; it takes the devices
  and their parents from the enumerator (see "libudev"), which still lists the sound `controlC*`
  devices after the other devices of their card, as libudev always did (systemd v251 and later sort
  them by path, because of a bug in its `sound_device_compare()`). `--property-match=K=a=b` matches
  the value `a=b` (systemd cuts it at the second `=`). Without a device (a query or `-a`) it says "A
  device name or path is required", and "No device node found: …" and "Unknown query type '…'" use
  systemd's texts and exit codes, through the log, so the pager's exit status covers them (see "Exit
  statuses").
- **`udevadm test`:** see "Before upgrading" for the non-destructive mode and the output; new
  `--json=`, `-D`/`--extra-rules-dir=` (a directory whose files take priority; one that does not exist
  is an error) and `-v`/`--verbose` (trace log); `--action=` is checked and `help` lists the actions,
  `-N help` the values of `--resolve-names=`; /dev paths, drivers directories and device IDs are
  accepted; it logs "version 3.3.0 (udev 262)" at debug level, after the arguments are checked, uses
  systemd's messages ("Invalid action 'x'.", "--resolve-names= must be 'early', 'late', or 'never'.",
  "Failed to read udev rules: …") and logs the default naming scheme at debug level, as
  `udevadm test-builtin` now does too (deviation for test-builtin: systemd logs it at info level).

- **`udevadm test-builtin`:** new `-a`/`--action=`; the builtins get `ACTION` and the uevent
  properties; unknown options and extra arguments are errors; the help has the correct usage line and
  goes to stdout; a failing builtin is reported with its reason ("Builtin command 'path_id' fails:
  ...").
- **`udevadm control`:** new `--log-level=` (`--log-priority=` still works), `--ping`, `--trace=`,
  `--revert` and `-t` for `--timeout=`; `--timeout=` takes time units, rounded up to whole seconds,
  and 0 means the default of 60 s; `-m 0` asks for the default. All options are parsed before anything
  is sent, so an invalid one sends nothing; the commands are sent in systemd's fixed order (revert,
  log level, stop/start queue, reload, properties, maximum workers, ping, trace), `--exit` alone, and
  the last `-l`, `-s`/`-S` and `-m` win. Like systemd v261, it sends all commands over one connection
  and waits once for udevd's answer ("Failed to wait for daemon to reply: …" when it does not come);
  with an older udevd, which handles only the first message of a connection, it sends each command
  over a connection of its own. So several options now all take effect (before, only the first, with
  exit status 2). `--log-level=help` lists the log levels. `--help` and `--version` work without root.
  Error messages are systemd's, from v261 where a446e8ff2c only has Varlink texts ("Failed to
  initialize udev control: …", "Failed to send exit request: …"). Like in systemd v261, an error on
  the socket after a message was sent, e.g. when udevd closes the connection, ends the wait of
  `udevadm control`, `settle` and `trigger` instead of failing with "Input/output error" (`--trace`
  and `--revert`, which need an answer, still fail and name the error).
- **`udevadm settle`:** `--timeout=` takes time units and `infinity`, and sub-second timeouts are
  honoured; on a timeout it logs "Timed out while waiting for udev queue to empty.", without a running
  udevd it fails with "udevd is not running.", it fails when the control socket cannot be created
  ("Failed to initialize udev control: …", as in systemd v261), `-E` is validated ("Invalid path: …")
  and extra arguments get "This subprogram takes no positional arguments.". When it pings udevd (as
  root), it ignores, like systemd v261, only a missing control socket and connection errors such as a
  refused or broken connection ("Failed to connect to udev daemon, ignoring: …" at debug level, exit
  0); other errors fail with "Failed to connect to udev daemon: …", and no answer within the ping
  timeout (the `--timeout=`, but at least 5 s) with "Failed to wait for daemon to reply: …" (before,
  it exited 0 in every case).
- **`udevadm hwdb`:** see "hwdb".
- **All commands** accept `-V`/`--version` and print 262; `udevadm --help` has an Options section and
  still lists `hwdb` ("Maintain the hardware database index", after `lock`, as the commands are now in
  systemd's order) (deviation: systemd no longer lists it); the debug line "calling: COMMAND" comes
  after the arguments are checked; every help text ends with "See the udevadm(8) man page for
  details.", a link on terminals that support links, as are the file names in `udevadm cat` headers
  (`$SYSTEMD_URLIFY`). `udevadm version` with arguments fails with "Too many arguments.", while `-V`
  and `--version` still ignore what follows them, as in systemd. Like udevd, udevadm connects
  `/dev/null` to the standard streams that are closed when it starts, so its log messages no longer
  end up in the output of a program that `udevadm test` runs.
- **Pager:** the output of `udevadm info` and all help texts go through a pager on a terminal, as in
  systemd (`--no-pager`, `$SYSTEMD_PAGER`, `$PAGER`, `$SYSTEMD_LESS`, `$SYSTEMD_LESSCHARSET`,
  `$SYSTEMD_PAGERSECURE`). `$PAGER` and `$SYSTEMD_PAGER` are used only with `$SYSTEMD_PAGERSECURE`
  set. Secure mode is decided from `/proc/self/loginuid` instead of logind, which eudev does not have:
  it is on when the login user is unknown or differs from the effective user (e.g. under sudo), so it
  is always on without pam_loginuid. Quitting the pager early keeps the command's failure code, exits
  1 when an error was logged while the pager ran, and 0 otherwise (deviation: systemd exits 141).

- **Colors and characters:** `$SYSTEMD_COLORS` (including 256 and 24-bit modes) and `$SYSTEMD_UTF8` are
  honoured; `--json=pretty` output is colored on a terminal like systemd's, `--json=short` is not.

- **Shell completion:** bash and zsh completion for udevadm is installed (see "Build and
  configuration"); `test-builtin` offers `blkid`, `kmod` and `tpm2_id` only when they are built. zsh
  offers `-d`, `-V` and `-h`, completes /dev nodes for `test`, `test-builtin` and `wait`, repeated
  options and `trigger`'s short options; bash completes after `wait --removed`/`--settle`, yes/no for
  `wait --initialized`, `lock`'s options and command, and device names for `--sysname-match`. Both
  offer the `help` and `version` commands, with nothing to complete after them, and bash completes the
  value of `--option=value` words like the argument of a separate option, also right after the `=`,
  and no longer takes the `=` of `--root=PATH` as the root of `verify` and `cat`, or the value of
  `lock --timeout=5` as the command to run (deviation: systemd's completions do none of this); bash
  completes nothing after a short option written with `=`, e.g. `udevadm -d=` or `info -q=`, which
  udevadm does not take, and zsh shows no message after `help` and `version`.
- **`udevadm monitor`:** its filters work like systemd's:
  `--subsystem-match=SUBSYSTEM/DEVTYPE` and `--tag-match=` also apply to the kernel uevents (which
  have no tags, so `-k -t` shows none), several `--subsystem-match=` of one subsystem with different
  device types all count (before, only the last), and a filter that cannot be applied fails with
  systemd's message ("Failed to apply subsystem filter '…': …") and exit status 1.

## Logging

- **Format:** messages to a terminal are colored by level by default, as in systemd
  (`$SYSTEMD_LOG_COLOR=0` or `$NO_COLOR` turns it off); source locations name the file relative to the
  source tree (`src/udev/udevadm.c:90:`); `$SYSTEMD_LOG_TIME` and `$SYSTEMD_LOG_TID` add the time and
  the thread ID. See "Init scripts and service supervisors" for the variables and the kernel command
  line.
- **/dev/kmsg:** a message that does not fit a kmsg record is cut at 976 bytes, at the start of a
  UTF-8 character, and ends with "..."; 976 bytes fit a record on every kernel since Linux 3.6, also
  with `CONFIG_PRINTK_CALLER`. Before, the kernel refused such a message and the process logged to the
  console from then on. Invalid UTF-8 no longer empties a record. Other targets get the whole message:
  messages are no longer cut at 2 KiB; a message longer than 128 KiB (2 KiB when memory runs out) is
  cut at the start of a UTF-8 character and ends with "...". udevd's start line goes through the log
  like its other messages (before, it was written to /dev/kmsg directly, whatever the log level,
  target and rate limit), so e.g. `udev_log=err` hides it.
- **udevd's early messages:** when stderr is a terminal, the messages printed while udev.conf is read
  go to stderr instead of the kernel log, unless the environment (`$UDEV_LOG_TARGET`,
  `$SYSTEMD_LOG_TARGET`) or the kernel command line (`systemd.log_target=`) selects a log target,
  which is then also kept after udev.conf is read, e.g. for a udevd started by an init script on the
  boot console; with `--debug` they always go to stderr. With `udevadm -d`, `$SYSTEMD_LOG_LEVEL=debug`
  or `udevd --debug`, the udev.conf parser's debug messages (masked or overridden drop-ins, bad lines)
  are shown, and an invalid `$SYSTEMD_LOG_LEVEL` is no longer hidden by `udev_log=` in udevadm.

- **Log levels** (`udev_log=`, `udev.log_level=`, `udevadm control --log-level=`,
  `OPTIONS="log_level="`) are parsed like systemd's: a name or 0 to 7, also with `0x`, `0o` or `0b`;
  an empty value or trailing blanks are refused (EINVAL).
- **Escaping:** values in messages are escaped only for control characters and invalid UTF-8 (`\xNN`,
  e.g. a tab in program output is `\x09`); a backslash and valid UTF-8 (e.g. "ä") are shown as they
  are. This now holds for substituted values, compared strings, rule formats and program output in all
  messages of rules, trace mode, programs, interface renames, `SECLABEL` and `SYSCTL`, for the device
  name that starts the messages about a device, for interface names, paths (device nodes, symlinks,
  database, hwdb, udev.conf, watches), rules file names, the arguments in the messages of builtins and
  udevadm, option errors, the text dump of `udevadm test` and `OPTIONS="dump"`, and the properties
  that `udevadm test-builtin` prints (deviation: systemd prints most of these raw). The data that
  `udevadm info`, `monitor`, `trigger --verbose` and `hwdb --test` print is not escaped, as in
  systemd.
- **Helper programs** (`ata_id`, `cdrom_id`, `collect`, `dmi_memory_id`, `fido_id`, `mtd_probe`,
  `scsi_id`, `v4l_id`) and `systemd-hwdb` honour `$SYSTEMD_LOG_LEVEL` and the other log variables, and
  the kernel command line settings when they have no controlling terminal, like systemd's helpers;
  `mtd_probe` and `v4l_id` do not read `udev_log=` from udev.conf.

## Builtins and helper programs

- **New `tpm2_id identify` builtin** with `60-tpm2-id.rules` and `60-tpm2.hwdb` (systemd dc75e54270,
  f2eed3fa25): sets `ID_TPM2_MANUFACTURER`, `ID_TPM2_VENDOR_STRING`, `ID_TPM2_MODALIAS` and hwdb quirks
  such as `TPM2_BROKEN_NVPCR`. It needs no tpm2-tss: it talks to the TPM device directly, sends
  systemd's command sequence (TPM2_Startup, the capability queries and the AES-128-CFB check; a TPM
  that fails the check gets no properties, as in systemd), and probes the device and checks the
  responses like tpm2-tss (tag and size; TPM 1.2 devices get their own message). The probe costs 1 s
  on Linux 4.18 and 4.19 and when the TPM answers it with a bare header. Deviations: a response
  shorter than its size field fails (tpm2-tss only warns); a TPM with an empty or non-advancing
  capability list fails cleanly where systemd aborts or loops; `POLLIN` reported together with other
  events is accepted and the whole probe answer is read; the device is opened with `O_CLOEXEC` and
  closed; the vendor bit is kept when paging the command list, so TPMs whose pages end in vendor
  commands are identified (systemd loops); `TPM_RC_VALUE` with a parameter number counts as "not
  supported"; the failures of probe, startup and capability queries have distinct messages ("Failed to
  probe TPM2 device '…'", "Failed to start up …", "Failed to query the capabilities of …"). A property
  that cannot be set is warned about, as in systemd. `--disable-tpm2` leaves the builtin and its rules
  out; `60-tpm2.hwdb` is installed either way.
- **New `factory_reset status` builtin** (systemd 9f0c830b5f): sets `ID_FACTORY_RESET=` (unsupported,
  unspecified, off, on, complete or pending) from `systemd.factory_reset=`,
  `/run/systemd/factory-reset-complete`, `$SYSTEMD_FACTORY_RESET_SUPPORTED` and the
  `FactoryResetRequest` EFI variable.
- **blkid:**
  - GPT root partition discovery (systemd cbd353ce77 and follow-ups): in the initrd, the disk with the
    ESP or XBOOTLDR partition named by the `LoaderDevicePartUUID` EFI variable, and on the running
    system the disk under `/`, get `ID_PART_GPT_AUTO_ROOT_DISK=1` and `ID_PART_GPT_AUTO_ROOT_UUID`, and
    the root partition `ID_PART_GPT_AUTO_ROOT=1`; the new `90-image-dissect.rules` creates
    `/dev/gpt-auto-root`, `/dev/gpt-auto-root-luks` and their `-ignore-factory-reset` variants;
  - `ID_PART_GPT_SECTOR_SIZE` on GPT disks from GPT sector-size probing, and
    `ID_PART_GPT_AUTO_ROOT_DISK_NEEDS_LOOP=1` on boot disks whose partitions the kernel cannot expose
    (systemd 0e187fae07, 047ae265cc, 4e0eabd401, 1dc599ce41), without systemd's rule that sets up the
    loop device; udev(7) documents both;
  - new `ID_FS_VOLUME_ID`, `ID_FS_LOGICAL_VOLUME_ID`, `ID_FS_VOLUME_SET_ID` and
    `ID_FS_DATA_PREPARER_ID` (ISO 9660/UDF, util-linux 2.37 or later);
  - devices are opened with `O_NONBLOCK`, so probing no longer closes an open CD tray;
  - libblkid is no longer asked for superblocks with bad checksums (systemd 1f47f5504c), so such a
    device still gets its other properties, e.g. the partition table type of a disk whose ext4 has a
    broken checksum (before, it got none);
  - a vanished device or one without medium is not an error; `--offset` is parsed strictly (a missing
    value no longer crashes);
  - it fails when the number of probed values cannot be read.
- **btrfs:** when `/dev/btrfs-control` is missing (driver not loaded), btrfs members get
  `ID_BTRFS_READY=0` and therefore `SYSTEMD_READY=0`; before, the builtin failed and set nothing.
  Retrigger after loading btrfs.
- **path_id:** see "Persistent storage links"; it no longer crashes on an FC LUN without a number, and
  a serio device without a number gets no `serio-(null)`.
- **usb_id:** a USB device without `idVendor` or `idProduct` gets no `ID_*` properties, and
  `test-builtin` reports why (systemd 71bd61c576); `bInterfaceClass`, `bInterfaceSubClass` and the SCSI
  type are parsed strictly; a short read of the descriptors is warned about, and a descriptors file
  that fills the buffer is accepted (systemd 760034bebe).
- **input_id:** capability blocks that do not parse are ignored instead of partially parsed.
  **keyboard:** empty or too large `KEYBOARD_KEY_*` and `EVDEV_ABS_*` codes are refused with a
  warning; numeric key codes accept `0b`/`0o` and refuse overflow; codes are logged as unsigned
  numbers. The key names are generated from a copy of the kernel's input-event-codes.h shipped with
  eudev, like systemd, and both builtins use eudev's copies of linux/input.h and input-event-codes.h,
  so they no longer depend on the build host's kernel headers: aliases work (`zoom`, `coffee`,
  `screenlock`, `btn_a`...), as do full names (`key_zoom`), and block markers (`btn_misc`,
  `key_min_interesting`...) are no longer accepted; this fixes `performance` with older kernel headers
  and the six `zoom` entries of 60-keyboard.hwdb in every build. The force-release list gets only the
  codes it lacks: no duplicates, no empty first entry, no rewrite when nothing is new (deviation); any
  number of codes works (systemd drops those after the 1023rd), and a list too long for the sysfs
  attribute is refused with an error instead of being cut ("Failed to set force-release attribute, the
  whole list '…' was refused: …"). A scan code of 512 (0x200) or higher, which the kernel's atkbd
  driver does not take, is skipped with a warning naming the property ("Scan code 0x… of
  KEYBOARD_KEY_… is out of range for the force-release list, ignoring"); before, it made the kernel
  refuse the whole list (deviation: systemd writes it). A missing serio parent or force-release
  attribute is an error, as in systemd. The debug messages of `input_id` about the capability bits are
  systemd's.
- **net_id:** see "Network interface names". With the `eudev` scheme, a missing `type` attribute is
  ignored, as in systemd's schemes ("Failed to determine prefix for network interface naming,
  ignoring"). DeviceTree aliases that cannot be read count as not found, and `wl` interfaces then fall
  back to the `ethernet` aliases, as in systemd (the names do not change). The debug messages of the
  name candidates use systemd's arrow ("→", or "->" outside UTF-8 locales) and texts.
- **All builtins** return an error code where systemd does, so failures have a reason; their messages
  start with the device name ("sda: ...") and use systemd's texts: `kmod` prints systemd's usage text
  as a warning, logs the module loading like systemd ("Loading module: ...", "Inserted module '...'",
  built-in, already loaded and deny-listed modules reported as such) and sets libkmod's log function
  after loading the index; `hwdb` logs "No entry found from hwdb.", "Loaded/Unloaded hardware
  database." and "hwdb needs reloading." at debug level; a sysfs attribute value that is refused is
  logged as "DEVICE: libudev: 'ATTR' sysattr contains invalid characters, refusing: VALUE" (systemd
  says "sd-device:"), and libudev no longer logs a debug line for every attribute path it cannot
  resolve. The `blkid` and `hwdb` builtins fail on invalid options with systemd's messages (see
  "Option parsing" under "Before upgrading"). The `hwdb` builtin looks up the parent of a USB device
  without `MODALIAS` whose IDs cannot be read, accepts the vendor and product ID 0000, logs invalid
  IDs at debug level, and uses the `MODALIAS` of a device without a subsystem when it has a device
  number or an interface index, as in systemd. `blkid` fails with systemd's "Failed to get device
  major/minor of device: …" for a device without a device number when it looks for the root disk, and
  `hwdb --device=` with an unknown device says "Failed to create sd_device object '…': …", as in
  systemd (both at debug level). Workers no longer log "Unloaded kernel module index." and "Unloaded
  hardware database." when they exit, as in systemd; udevd still logs them on a reload and when it
  exits. When `hwdb.bin` cannot be loaded, the debug log names the reason, with sd-hwdb's texts
  ("Failed to open …: …", "File … is too short.", "Failed to recognize the format of ….", see
  "libudev").
- **cdrom_id** (systemd's 2020-2021 rewrite): the drive is no longer opened exclusively, so it no
  longer races with automounters; all MMC profiles are recognized, with new drive and
  `ID_CDROM_MEDIA_*` properties (e.g. `ID_CDROM_DVD_R_DL`, `ID_CDROM_BD_R_SRM`, `ID_CDROM_HDDVD_RW_DL`);
  profile 0x52 is now HD DVD-RAM and 0x53 HD DVD-RW; a DVD-RAM without media sets no
  `ID_CDROM_MEDIA_*`; for pre-MMC2 drives READ DISC INFORMATION is issued in two steps; new
  `--version`, help text and the eudev-only `--dry-run`; extra arguments are refused. Deviations:
  pre-MMC2 drives still get the TOC and media state read (systemd lost them in 38f3e20883); a busy
  drive is tried 20 times (systemd 11); `ID_CDROM_DVD_R=1` is printed once; a pre-MMC2 data track is
  no longer counted twice.
- **ata_id:** `--version` and systemd's help; unknown options are errors (systemd 61da49cfd6); exits
  1 when the udev context cannot be created. The ATA status check after IDENTIFY is kept on the SG_IO
  v3 path that `/dev/sdX` uses (deviation: systemd 66026fca95 skips it there).
- **Other helpers:** `fido_id` and `mtd_probe` have `--help` and `--version`, accept `--` before the
  device and refuse extra arguments; `mtd_probe` closes its device; `fido_id`, `dmi_memory_id` and
  `v4l_id` exit 1 on errors (was 234, 243, 254, 2 or 3); `v4l_id` refuses extra arguments and exits 1
  when the capabilities cannot be queried (deviation: systemd exits 0 with no output); `scsi_id` exits
  1 when the udev context cannot be created. All helpers print 262 for `--version`, and their help in
  systemd's layout (see "Option parsing"). `dmi_memory_id` prints voltages that are whole tenths with
  one decimal, e.g. `1.2` and `1.0` (before, `1` for 1.2 V and `2` for 1.5 V), and ignores the
  reserved bit 31 of the extended size (deviations: systemd a446e8ff2c has both bugs); `make check`
  tests it with systemd's dmidecode dumps.
- **String checks** of values read from devices are exactly systemd's: valid UTF-8 without TAB, other
  C0 controls or DEL; C1 characters are accepted. This applies to `scsi_id` (`ID_SCSI_SERIAL`,
  `ID_WWN*`, `ID_TARGET_PORT`), `dmi_memory_id`, `v4l_id` (`ID_V4L_PRODUCT`) and the onboard label of
  the `eudev` scheme.
- **collect:** a checkpoint whose file path is longer than 1024 characters is refused with a message
  (exit 3; before, the length check read uninitialized memory); NUL bytes in the checkpoint file are
  separators and no longer cause a read before its buffer; IDs are no longer added twice after an ID
  of more than 8 characters; a last ID without a separator is kept; a directory that cannot be created
  ("Cannot create ..."), read errors (taken as the end of the file before) and write errors (also
  short writes; ignored before) are reported, the latter two with exit code 255; running out of memory
  is reported (exit 2) instead of printing a wrong count; the `COLLECT_` line is printed only on
  success; the checkpoint file is closed on every error; the timeout handler uses `_exit()`; the usage
  text lists the real exit codes. The exit status for missing IDs is at most 254, so it no longer
  wraps around to 0 at 256 missing IDs or equals the error code 255; the `COLLECT_` line has the real
  count (counts of 1 to 4 can still equal the exit codes of errors, as documented in the usage text).
  "Missing parameter(s)" goes to stderr, and a failure to create the udev context (out of memory)
  exits 2 with "Out of memory.".
- **scsi_id:** see "Local rules" for the configuration file. `-f FILE` now also applies to the global
  options (an `options=` line without `vendor=`): the command line is parsed first, the global options
  are read from the file it names, and the command line still overrides them; `--help` and `--version`
  work with a broken `/etc/scsi_id.config`, and an invalid command line exits 1 before the file is
  read (deviation: systemd reads the global options from the default `/etc/scsi_id.config` before it
  parses the command line, as eudev did). An option that a `vendor=` line may not set is refused with
  systemd's "Option -d/--device not supported in the config file." (was "Unknown or bad option 'd'
  (0x64)"). Such an error, or a line after the global options line that cannot be parsed, found when
  the options for the device are looked up, makes `scsi_id` fail with exit status 1 and no output, as
  in systemd (before, it went on).

## hwdb

- **Data:** the Bluetooth vendor names of v0245 ("Endress+Hauser") and v06E0 ("Avaya") lose a trailing
  no-break space (deviation: still in systemd). Duplicated ACPI vendor entries are removed without
  changing any lookup. Later systemd changes: PCPanel controllers, the accelerometer mount matrix of
  the Minisforum V3 and V3 SE and the fix of its Z axis, the VEIKK A15 Pro resolution and the Casper
  Nirvana force-release keys (systemd aa5c0f0f77, 8ab902b635, 583679fe49, 7455546a89, ba7554dafe); the
  Retoo E803 Air Mouse and the Samsung Galaxy Book2 Go keyboard are not tablets, the volume keys of
  the Lenovo ThinkBook 16 G7 ARP (21MW) get force-release, the Google Pixelbook (Eve) its chassis and
  top-row keys, the ViewSonic Woodpad 7 its resolution, the MSI Modern 15 B13M its webcam key, the HP
  Pavilion Gaming 15-dk0 its lid keys (only with `hwdb_format=2`, see below) and the MSI Stealth 14
  its touchpad toggle (systemd 2371cb9b65, 37fcd0161a, 1fedf6810b, 32e38ebd76, 0490b976b9, 6a91d25cc4,
  491b0c51c4, 388d7a6ef6, de1e749daa).
- **Format 1 and the order of records:** with the default `hwdb_format=1`, when several records set
  the same key for a device, it is undefined which of the values is used, not necessarily the one of
  the later record, as in 3.2.15; hwdb(7) now says so, and its example lookup string is corrected. Set
  `hwdb_format=2` in udev.conf and run `udevadm hwdb --update` to get the order that hwdb(7)
  describes. Known to differ are the `KEYBOARD_KEY_*` entries of the Acer Aspire 5720 family (`ee`),
  the Dell Latitude XT2 (`9e`), the HP Pavilion 13 x360 (`d9`), the HP Pavilion Gaming 15-dk0 and
  15-dk1 (`d7`, `d8`: with format 1 the lid still toggles airplane mode), the Samsung 355V4 and 356V4
  (`b3`) and 900X3A (`96`, `97`, `ce`, `d5`), and the `ACCEL_MOUNT_MATRIX` of two BOSC0200 machines
  whose DMI strings say "Default string" and of the MEDION E2228T.
- **Masks and odd files,** in `udevadm hwdb --update` and `systemd-hwdb update`: an empty hwdb file
  masks like a symlink to `/dev/null`; directories, FIFOs, devices other than `/dev/null` and dangling
  symlinks are skipped, dangling ones with a warning, and no longer hide files of the same name in
  later directories; the hwdb compiler, like `udevadm cat` and `verify`, follows symlinks inside
  `--root` instead of on the host; a non-regular file is skipped with "File '...' is not a regular
  file, ignoring." at debug level (deviation: systemd says "File descriptor in bad state").
- **Reading hwdb files** like systemd: lines longer than 2047 bytes are no longer split (a line over
  1 MiB is an error); `\r` and NUL end a line; syntax errors are reported as "FILE:LINE: ..." at warning
  level with systemd's texts (they were errors with eudev's texts, so `udev_log=err` now hides them);
  relative directories in `$UDEV_HWDB_PATH` are used, below `--root` or else the current directory
  (they were ignored); the v2 database records the path of each source file as found in its
  directory.
- **Compiler errors** (all deviations, systemd has these bugs): read and allocation errors fail the
  update with a message and exit status 1, and the old `hwdb.bin` is kept (before, an incomplete or
  broken `hwdb.bin` was written with status 0); a `hwdb.d` directory that exists but cannot be read,
  also one that is not a directory, is an error and does not remove `hwdb.bin`, while a missing one is
  skipped; a failure to insert data, and running out of memory while listing the files, are reported
  once; with `--strict`, a record without properties at the end of a file fails too. udevadm(8) and
  systemd-hwdb(8) describe these failures.
- **`hwdb.bin`:** it is removed when there are no hwdb files (systemd 4638e18593); it is relabelled for
  SELinux after the update (systemd ea683512f9, 905c37e60e); it records tool version 262 (was 3).

- **`udevadm hwdb`:** new `-V`/`--version`; `--test` honours `--root` and fails with a message when
  there is no `hwdb.bin` (deviation: systemd fails silently); `--root=` is simplified once (trailing
  `/`, `//`, `/./`), and an empty `--root=` means no root, also for `cat`, `verify` and
  `systemd-hwdb`; `--output` and `$UDEV_HWDB_PATH` are below `--root`, as udevadm(8) now says. "Either
  --update or --test must be used." ends with a period, like systemd's. `--test` names the real error
  of an unusable `hwdb.bin` ("Failed to open the hardware database (hwdb.bin): …", e.g. "Invalid
  argument" for a file that is not a hwdb.bin, which said "No such file or directory" before).

- **New `systemd-hwdb` tool** (`update`, `query`, `--usr`, `--root`, `--strict`,
  `$SYSTEMD_HWDB_UPDATE_BYPASS`, man page systemd-hwdb(8)) for scripts and packages that call it. It
  shares the code of `udevadm hwdb` and honours `hwdb_format=` from udev.conf and its drop-ins
  (deviation: systemd always writes format 2; for format 1, the default, see "Format 1" above).
  `query` without `hwdb.bin` prints an error, and like `udevadm hwdb --test` it names the real error
  of an unusable `hwdb.bin`. Invalid options, a missing verb ("Command verb required (one of query,
  update, help).") and an unknown one ("Unknown command verb 'x', did you mean 'y'?") get systemd's
  texts, and the `help` verb, which the help does not list, shows the help, as in systemd.
- **libudev** logs each `hwdb.bin` path it tries at debug level, ignores `$UDEV_HWDB_BIN` in setuid and
  similar programs, and reads `$(sysconfdir)/udev/hwdb.bin` before `$(udevlibexecdir)/hwdb.bin`.

- **Sources:** the source directory is renamed from `hwdb/` to `hwdb.d/` like systemd, its README is
  installed with the hwdb files, and it contains systemd's sources and tools of the generated
  `20-*.hwdb` files: `make regenerate-hwdb` regenerates them (python3 with pyparsing, and patch) in a
  work directory and changes nothing in the source directory when a step fails, and `make parse-hwdb`
  checks the hwdb files with systemd's `parse_hwdb.py`. The release tarball grows to about 6.1 MB.


## libudev

The exported symbols are unchanged; these functions behave differently, as in systemd:

- **`udev_device_new_from_syspath()`** (and through it `new_from_devnum()`,
  `new_from_subsystem_sysname()`, `new_from_device_id()` and `udev_enumerate_add_syspath()`): the path
  must be below `/sys` by component (`/sysfoo` gives EINVAL); it is fully resolved, a result outside
  `/sys` gives ENODEV, and `//`, `.` and a trailing `/` are accepted and canonicalized (before:
  EINVAL); a path that does not exist, `/sys` itself, a non-directory, and a directory in
  `/sys/devices` (or `/sys/devices` itself) without a `uevent` file give ENODEV; other directories
  below `/sys` (`/sys/class`, `/sys/bus`, `/sys/module`, ...) are pseudo-devices; a path component
  longer than 255 bytes gives EINVAL; a path that is not on sysfs gives ENODEV unless
  `$UDEV_DEVICE_VERIFY_SYSFS=0` (or `$SYSTEMD_DEVICE_VERIFY_SYSFS=0`), which setuid programs ignore.
  Devices with a write-only `uevent` file are accepted.
- **Device lookups** (`udev_device_new_from_device_id()`, `udev_device_new_from_subsystem_sysname()`,
  `udev_device_new_from_devnum()`) work like sd-device's: a malformed ID gives EINVAL (ERANGE for a
  number that is too large), an unknown device ENODEV (was ENOENT); the device found must have the
  requested subsystem and name, and two different matching devices give ETOOMANYREFS (e.g.
  "+subsystem:gpio" when both /sys/bus/gpio and /sys/class/gpio exist); devices below /sys/firmware
  are found (e.g. "+devicetree:base"), and /sys/subsystem is no longer used; "+subsys:name" translates
  `!` to `/`, and a leading `/` in a sysname becomes `!`; "nIFINDEX" gives ENXIO when the interface
  was renamed; a device number with major 0 gives ENODEV, and a device with another number or type
  ENXIO; a name component longer than 255 bytes or a name of 4096 bytes or more gives EINVAL, and
  nothing is cut silently any more; "drivers" IDs need a driver name. The device found is checked by
  its `dev` or `ifindex` attribute or its subsystem link, without reading its `uevent` file, which is
  read only when a property is needed, or when the `ifindex` attribute of a network interface cannot
  be read, e.g. while it is being unregistered (deviation: sd-device reads it, which on some kernels
  waits while a driver probes the device).
- **`udev_device_get_parent()`** works like sd-device: it stops at the first error other than ENODEV
  (the error is not cached), finds top-level parents with one-character names, and returns
  pseudo-devices such as /sys/module as parents. A `uevent` file that is a FIFO no longer blocks. Like
  in systemd, a failure to read the `uevent` file is remembered, so the file is read only once, and a
  missing or unreadable one is not logged; so e.g. `udevadm test /sys/class/net` works, as in systemd.
  Looking up the parents of a device takes about 40% less time.
- **`udev_device_get_sysattr_value()`:** reads values of up to 4 MiB (before: ENOBUFS at 4096 bytes),
  EFBIG beyond; refuses attributes whose resolved path leaves `/sys`; follows symlinks inside `/sys`;
  strips trailing `\n` and `\r`; decides readability by opening the file (so root can read 0200
  files); sets errno on NULL (EACCES, ENOENT, EISDIR for a directory (deviation: systemd EBADF), EBADF
  for other non-regular files, EINVAL outside sysfs, EFBIG) and caches every error except ENOMEM with
  its errno. Reading a FIFO never blocks (deviation).
- **`udev_device_set_sysattr_value()`:** EINVAL for a path outside `/sys`; follows symlinks inside
  `/sys`; cuts the value at 4096 bytes and strips trailing newlines (before: EINVAL above 4096); caches
  the written value under the resolved path, and a successful write clears a cached error of the same
  attribute under any name (deviation: systemd keeps it).
- **`udev_device_get_sysattr_list_entry()`** also lists the attributes in subdirectories as `dir/name`
  (not those of child devices) and write-only attributes; mode-000 files are still left out.
- **Properties** (`udev_device_get_properties_list_entry()`, `udev_device_get_property_value()`):
  insertion order like sd-device (see "Before upgrading"); invalid properties never appear; empty
  values are never stored; `CURRENT_TAGS` is new; `TAGS` includes sticky tags; `DEVLINKS`, `TAGS` and
  `CURRENT_TAGS` disappear when they become empty (deviation: systemd keeps them stale); private
  properties are included in received devices.
- **Tags:** `udev_device_get_tags_list_entry()` and `udev_device_has_tag()` include the tags of
  earlier events; `udev_device_get_current_tags_list_entry()` and `udev_device_has_current_tag()` now
  return only the current tags (before, all tags), except for devices from databases and messages of
  older versions; `udev_enumerate_add_match_tag()` and tag filters of monitors match devices that had
  the tag in any earlier event; `udev_device_has_tag(dev, NULL)` no longer crashes.
- **Devlinks and device nodes:** `udev_device_get_devlinks_list_entry()` drops unsafe links from the
  database or messages and normalizes the others (a database `S:/x` becomes `/dev/x`);
  `udev_device_get_devnode()` returns NULL for an unsafe `DEVNAME` or one outside `/dev`.
- **Received and environment devices** (`udev_monitor_receive_device()`,
  `udev_device_new_from_environment()`): invalid variables are skipped; a device is refused when
  `DEVPATH`, `SUBSYSTEM`, `ACTION` or a non-zero `SEQNUM` is missing, `DEVPATH` or `SUBSYSTEM` is
  invalid, a typed property (`IFINDEX`, `MAJOR`, `MINOR`, `SEQNUM`, `DISKSEQ`, `DEVMODE`, `DEVUID`,
  `DEVGID`, `USEC_INITIALIZED`, `UDEV_DATABASE_VERSION`, `ACTION`) is malformed, `DEVNAME` or
  `DEVLINKS` is unsafe, or a `TAGS` entry is invalid. So `fido_id` run by hand from the environment
  needs `ACTION` and `SEQNUM`. Messages of any size are received. These devices keep the values of
  their event, like the sealed devices of systemd before v258 and since f58a2efc55 (v262.1):
  `udev_device_get_devtype()` no longer reads the live `uevent` file, which replaced `DEVTYPE`,
  `DEVNAME`, `MAJOR`/`MINOR`, `IFINDEX` and other values with the device's current ones, so a devtype
  filter now matches the event's own `DEVTYPE` (this also fixes a use-after-free in udevd, see
  "Fixes").
- **The "udev" monitor** (`udev_monitor_new_from_netlink(udev, "udev")`) is enabled also when /dev is
  a devtmpfs, not only when /run/udev/control exists, like systemd; otherwise it logs "The udev
  service seems not to be active, disabling the monitor."
- **Drivers:** the subsystem of `/sys/bus/X/drivers` is "drivers" (was "subsystem"); device IDs of
  drivers are `+drivers:<subsystem>:<driver>` and of the drivers directory `+drivers:X:drivers`;
  `udev_device_new_from_subsystem_sysname("drivers", "X:drivers")` works. Their `/run/udev/data` and
  tag files get new names; the old ones are unused, harmless, and go away at reboot.
- **Enumerator:** `udev_enumerate_scan_devices()` and `udev_enumerate_scan_subsystems()` also list the
  parents of the devices they find in /sys when the parents match the filters (a parent without a
  subsystem never matches), like sd-device's enumerator, except in scans with a tag or parent match,
  which find the devices in other ways; in practice this adds the /sys/bus/*/drivers directories
  (subsystem "drivers") to subsystem scans, so they may list devices they did not list before. Like in
  sd-device's enumerator, a device found in `/sys/class/X` or `/sys/bus/X/devices` is matched against
  its own subsystem, and entries that are neither directories nor symlinks are skipped (before, a
  device of another subsystem, or without one, in such a directory could be listed for a subsystem
  filter it does not match); a directory that cannot be opened for another reason than not existing is
  logged at debug level; `udev_enumerate_add_match_tag()` refuses an invalid tag name (EINVAL; see
  "Match options"). Scans below a parent device and scans of tagged devices no longer read `uevent`
  files unless properties are matched; a tag scan still reads the file of a tagged network interface
  whose `ifindex` attribute cannot be read (deviation: sd-device reads them). The order is unchanged,
  also for the sound `controlC*` devices.
- **`udev_hwdb_new()`** sets errno when it fails, like systemd's libudev: ENOENT when there is no
  `hwdb.bin`, the error of opening, `fstat()` or `mmap()`, EIO for a file too short for the header,
  EINVAL for one that is not a hwdb.bin, EFBIG for one larger than the address space (on 32-bit
  systems, "File … is too long."), ENOMEM; the reason is logged at debug level with sd-hwdb's texts,
  and the documentation says so.
- **Devices without a subsystem** that have a device number or an interface index get the device IDs
  `c<major>:<minor>` and `n<ifindex>`, like in sd-device, so libudev reads their database entry, and
  `udevadm info` shows their `J:` line and properties (udevd does not process events of such devices).

- **Database:** `Q:` and `V:` lines are read and written; lines of up to 1 MiB are stored, longer ones
  are ignored as a whole (before, their tail was parsed as a new line); short lines are skipped; line
  breaks and control characters are never written.
- **udev.conf:** `udev_new()` reads udev.conf and its drop-ins (see "udevd") once per process, at the
  first call, and reuses the result; every `udev_new()` still applies `udev_log=`; when that first
  read fails, e.g. because a file cannot be opened or memory runs out, nothing is kept, and the next
  `udev_new()` reads the files again.
- **Other:** `$UDEV_HWDB_BIN` is ignored in setuid and similar programs; the debug messages about
  udev.conf name the file that was read; a failed replacement of a list entry keeps the old value;
  `udev_list_entry_get_by_name()` with a NULL name no longer crashes; a monitor message with an
  invalid properties offset is logged as "Invalid properties offset (N) for message of length M.";
  `udev_monitor_send_device()` does not send a device without a subsystem, like systemd.

## Build and configuration

- **New configure options:**
  - `--enable-smack` (default off; uses `<sys/xattr.h>`);
  - `--disable-tpm2` (the `tpm2_id` builtin and its rules are built by default; no new dependency);
  - `--disable-systemd-hwdb`;
  - `--with-bashcompletiondir=` (default: bash-completion's `completionsdir`, else
    `$(datadir)/bash-completion/completions`) and `--with-zshcompletiondir=` (default
    `$(datadir)/zsh/site-functions`); `no` disables either;
  - `--with-system-uid-max=` and `--with-system-gid-max=` (default: `SYS_UID_MAX`/`SYS_GID_MAX` of
    the build host's `/etc/login.defs`, else 999);
  - `--with-nobody-user=` and `--with-nobody-group=` (default `nobody`);
  - `--with-foreign-uid-base=` (default 0x7FFE0000; 0 is allowed like systemd; decimal or hexadecimal,
    a multiple of 65536, at most 0xFFFE0000);
  - `--with-net-ifnames-default=yes|no` (default `yes`; see "Network interface names").
- **Changed:** `--enable-manpages` and `--disable-hwdb` have correct help texts (the man pages are
  still not installed by default); with `--disable-programs` no man pages, no hwdb files and no rule
  generator are installed, and the summary says "no (--disable-programs)" for them, for `systemd-hwdb`
  and the completion directories; `--enable-rule-generator=<value>` works for any value other than
  `no`. The summary shows SELinux, SMACK, man pages, hwdb, the rule generator, the system ID limits
  and nobody names, the udev.conf search directories (instead of the udev.conf path) and fully
  expanded directories, and the default of `net.ifnames=`. `80-net-name-slot.rules` is not installed
  with `--enable-rule-generator` unless `--with-net-ifnames-default=no` is given too, which then
  installs a variant of `75-persistent-net-generator.rules` that records no names with
  `net.ifnames=1`, as the help text of `--with-net-ifnames-default=` says; `80-net-altnames.rules` is
  installed in every variant. `make` makes `64-btrfs.rules` (through a temporary file), and the rule
  generator's `write_net_rules` and `rule_generator.functions`, with the fully expanded directories of
  the build, the latter with the directory of `--with-rootrundir=` (see "Fixes").
- **glibc:** eudev no longer uses glibc's C23 `strtol()`/`sscanf()` variants (systemd 97f81508c5), so
  binaries built with glibc 2.38 or later no longer need `GLIBC_2.38` (libudev needs at most
  `GLIBC_2.33`, the programs `GLIBC_2.34`, unless a library that they link statically, e.g. libblkid,
  needs a newer one).
- **Integer parsing** follows systemd's `safe_atou()` family: `0b` and `0o` prefixes are accepted,
  unsigned values refuse a minus sign with ERANGE on every architecture ("-0" is 0; before, "-1" was
  accepted as the largest value), and leading whitespace is skipped, including `\v` and `\f`
  (deviation: systemd skips only space, tab, CR and LF, so "\v-1" passes its minus check); the same
  for time spans.
- **Cleanups:** configure no longer looks for a C++ compiler or m4, always looks for pkg-config (so
  `--disable-blkid` no longer breaks the kmod check), uses no `$(...)` or `$(( ))`, and drops the
  unused `ROOTPREFIX` define and the keymap leftovers; the auxiliary build scripts are kept in
  `build-aux`, so the release tarball always contains them; `m4/` is kept in git, so a fresh checkout
  gives no aclocal warning; `.travis.yml` is removed; the build has no warnings with `-Wall`, also on
  32-bit systems, nor `-Woverride-init` warnings with `-Wextra`; the release tarball no longer ships
  the generated rules files and now ships `autogen.sh`, the man page tools and the build documents
  (see "Packagers"); the man pages no longer make groff 1.23 warn about `an-trap`, and they are built
  without the double space after "e.g." and "i.e." and after code that ends with a period, a question
  mark or an exclamation mark; `udev.conf.d(5)` is installed as a symlink.
- **Smaller binaries:** the keyboard key table is generated with gperf `--multiple-iterations=10`,
  like systemd b11ba559a6, so udevd and udevadm each have about 28 KiB less data; gperf then takes
  about 2.6 s instead of 0.3 s.
- **Licensing:** the new `LICENSES/` directory holds the license texts, named by SPDX identifier, and
  a README that lists which files carry which notice; as in systemd, files without a notice of their
  own are LGPL-2.1-or-later, except the test sysfs tree `test/sys.tar.xz`, which is taken to be
  non-copyrightable; `siphash24.h` and `udev.pc.in` carry SPDX lines (CC0-1.0, LGPL-2.1-or-later);
  `scsi_id` is GPL-2.0-only because of `scsi.h`. The GPL-2.0 copy of `ioprio.h` is replaced by
  systemd's LGPL definitions, or the kernel's `<linux/ioprio.h>` where it exists; the shipped input
  headers are GPL-2.0-only WITH Linux-syscall-note. `LICENSES/README.md` also records which lines of
  the rule generator come from Debian's (by Marco d'Itri) and why they are LGPL-2.1-or-later.

- **Tests:** `make check` also runs the JSON writer test, a test of devices claiming the same symlink,
  the rules syntax check with python3, a test of `hwdb --update` failures (`hwdb-test.sh`), and tests
  of `collect`, of the configuration parser of `scsi_id`, of `dmi_memory_id` on systemd's dmidecode
  dumps and of devices received from a monitor or built from the environment (`test-event-device`).
  `udev-test.pl` reports SKIP (77) when it cannot run instead of PASS, also when its runner cannot set
  up its mount namespace (e.g. without `CAP_SYS_ADMIN`, or in a chroot whose mount is shared); in a
  plain chroot whose `/` is not a mount point it now runs when the chroot's mount is private or a
  slave (this needs Linux 6.8 or later), and its runner binds the host's `/dev/null`, `/dev/zero`,
  `/dev/full`, `/dev/random` and `/dev/urandom` read-only. The test of devices claiming the same
  symlink runs also as root, then only in a mount namespace of its own, so also in chroots such as
  those of sbuild (a plain chroot whose `/` is not a mount point needs Linux 6.8 or later, as for
  `udev-test.pl`), binds the host's device nodes read-only, skips (77) when it cannot, and removes its
  work directory on every exit. The rules syntax check also checks the rule generator's rules and, in
  VPATH builds, the generated rules of the build tree, and reports an error when a generated rules
  file is missing. The rules test runner hides every rules directory of the host, finalizes its
  database like udevd, restores it like udevd when the final write fails, and runs in its own network
  namespace, so `NAME=` cannot rename a host interface (without that namespace it skips renames and
  alternative names). Tests on a fake sysfs need `UDEV_DEVICE_VERIFY_SYSFS=0`. Builds with `-DDEBUG`
  dump the rule tokens in rule syntax.

## Documentation

- udev(7) has new sections on network interface naming and on the builtins (`factory_reset`,
  `tpm2_id`, GPT root discovery, the new blkid properties), and documents the changes above;
  udevadm(8) documents the new commands and options, an Environment section with the log variables,
  `ID_PROCESSING` under "Initialized Devices", relative directories in `$UDEV_HWDB_PATH` and the hwdb
  update failures, names the time arguments `SEC`/`SECS` like the help texts and `--children-max=N`,
  says for `test -N never` and `verify -N never` which keys are ignored, only `OWNER` and `GROUP`
  values that are not numeric IDs, while the rest of the rule applies (systemd's text speaks of
  ignored rules), and refers to udevd(8) instead of udevd.service(8); udevd(8) documents the naming
  scheme options, the kernel options with `_` and `-`, the log level order, an Environment section,
  the default number of workers, the SIGKILL after the timeout signal, the exit, and the default event
  timeout of 180 s (it said 30 s); udev.conf(5) documents the new keys, the drop-ins (alias page
  udev.conf.d(5)), the default number of workers and that udev.conf is read once per process; hwdb(7)
  mentions `udevadm hwdb --update`, that systemd-hwdb(8) may not be installed, `$UDEV_HWDB_PATH` and
  that format 1 does not keep the order of records, with a corrected example; systemd-hwdb(8) is new;
  udev(7) and hwdb(7) say that empty files mask too; udevadm(8) lists `-d` with `--debug`, shows the
  values of the `--export-db` filters as required (deviation: systemd's man page shows them as
  optional) and gets systemd's sentence about the exit status of `settle`. The default udev.conf lists
  the new keys as comments. udevadm(8) and udev(7) document the `SYNTH_ARG_*` properties of triggered
  uevents (as of systemd d404b58f3a, systemd does not), and udevadm(8) says that `trigger --uuid`
  prints the UUIDs that every event is triggered with, how and for how long the support of UUIDs is
  found out, how the size of a triggered event is checked, on which kernels refused events are
  triggered again, which `trigger` options read `uevent` files, when `--settle` gives up, which
  devices `--settle` does not wait for (hidden block devices, devices for which the kernel sends no
  uevent, and the events that rules trigger in response), that a device given to `trigger` is
  triggered with its children, that `info -w0` does not wait, the filters of `monitor`, attribute
  paths in `--attr-match=`, `control --log-level=help`, and that all four commands that do nothing in
  a chroot check their options first. udev(7) describes the properties that `IMPORT` and hwdb entries
  do not set (hwdb(7) too), what `IMPORT{db}` and `IMPORT{parent}` import, the order of events with
  the sound card as example, both defaults of `net.ifnames=`, the rule generator in a new section, for
  both defaults, and says "built with" for every build option; udevd(8) and udev.conf(5) say correctly
  that `resolve_names=never` still applies numeric `OWNER` and `GROUP` values; udevd(8) shows the help
  text and `-V`/`--version`, the `net.ifnames=` defaults with an example for each, and where the
  console messages go after `--daemon`.

## Fixes

- Device node symlinks: races between parallel events that could leave a link on a lower-priority
  device, links kept to vanished nodes, an old database `..` link that made udevd remove a path outside
  `/dev`, and empty or failing stack entries for long link names.
- Rules: a crash with more than 64 keys, a crash on out of memory while loading rules, reading past
  the end of the rules when out of memory while storing their end (now loading the rules fails:
  udevd does not start, or keeps its rules on a reload, and `udevadm test` fails), the output of
  `PROGRAM` taken as empty when it could not be stored for lack of memory (now the event stops, as
  when the value of another key cannot be stored), a 1-byte stack overflow when plain text filled a
  substitution buffer, an over-read in `ATTR` matches of long values ending in whitespace, wrapped
  line numbers above 65535.
- libudev: move events stored `DEVPATH`, `TAGS`, `IFINDEX` and similar in the database; a stale
  `DEVLINKS` stayed after all links were removed; the database reader parsed the tail of an overlong
  line as a new line and could drop the last character; a FIFO named `uevent` or read as an attribute
  blocked the caller; when `hwdb.bin` could not be mapped, `udev_hwdb_new()` called `munmap()` on
  `MAP_FAILED`; devices received from a monitor or built from the environment read the live `uevent`
  file and replaced the values of their event (see "libudev"); two threads that created their first
  udev context at the same time could race on the hash key of libudev's tables; out of memory,
  `udev_enumerate_get_list_entry()` silently left devices out of the list and kept it that way (now
  it returns NULL with errno set to ENOMEM, and the next call builds the list again).
- udevd: a 0 sent as the maximum number of workers stopped event processing; a NULL dereference when a
  worker failed during exit; programs started late in an event were killed before the event timeout;
  very long timeouts broke reading program output; hanging workers were never killed while uevents or
  messages arrived more often than every 3 s; a worker that did not die from the timeout signal (e.g.
  `timeout_signal=SIGTERM`) was never killed; a stray SIGCHLD made a worker abandon its program;
  programs were started after the event timeout; held events started up to 3 s after `udevadm control
  --start-exec-queue`; `IMPORT{file}`, `SYSCTL{}` and `ATTR{}=` on a FIFO blocked a worker; a
  heap-use-after-free in the main process, when libudev replaced the device node of a queued event
  while udevd still used the old one (GitHub #304); two events of one device that wrote their database
  entry at the same time shared one temporary file, so one of the writes could fail ("Failed to update
  database under /run/udev/data/: No such file or directory"); the database is now written through a
  temporary file with a unique name, which always gets mode 0644, or 01644 with `db_persist`; a few
  seconds after it started, udevd reloaded the rules and killed its idle workers, because it had
  created `/run/udev/rules.d` after loading them; programs that wrote more than 64 KiB failed with
  EAGAIN; a program's output was no longer logged once it closed its stderr; a background process that
  a program left behind with its stdout or stderr kept the event waiting until the timeout.
- udevadm: `trigger -o` aborted; `hwdb --test` ignored `--root`; `//` and an empty path in hwdb
  messages; `udevadm control` with several options applied only the first; `udevadm control --help`
  needed root.
- Helpers and builtins: `blkid --offset` crashed; `path_id` crashed on an FC LUN without a number;
  `ata_id` probed the device on unknown options; the keyboard builtin dropped force-release codes
  after the 1023rd and cut long lists silently; `collect` could read before its buffer, duplicated
  IDs, checked the checkpoint path against uninitialized memory, and exited 0 (all present) with 256
  missing IDs or 255 (its error code) with 255; `scsi_id -f FILE` ignored the global options of FILE;
  on 32-bit systems, `dmi_memory_id` dropped memory sizes that are multiples of 4 GiB or whose low 32
  bits are all ones.
- Rule generator builds: when the final rename failed after a temporary one, the event kept the old
  name; when the temporary rename failed, a different interface could be renamed; an invalid `NAME=`
  left the interface named `rename_<name>`; names with digits in the middle (`enp0s3`, `eth0.100`) got
  a cut temporary name ("enp", "eth"); when the `NAME=` was taken, the interface stayed
  `rename_<name>` after a 90-second wait (now the wait ends at the event timeout and the interface
  keeps its previous name); a taken temporary name caused a 90-second wait and is now logged once at
  info level; temporary names could be negative ("eth-5"), and `rename_<name>` was cut at 15
  characters (now `rename<ifindex>` when it does not fit); on kernels before 6.2, an interface brought
  up during the wait stayed `rename_<name>` (now it is taken down, renamed and brought up again); a
  failed temporary rename suppressed the alternative names; the installed `write_net_rules` sourced
  `rule_generator.functions` from `/lib/udev` (an unexpanded `${exec_prefix}`), so with
  `--prefix=/usr` it failed, and wrote to a literal `${prefix}/etc/udev/rules.d` with the default
  `--sysconfdir`; now it uses the directories of the build. `write_net_rules` wrote a second rule for
  an interface that got another add event before the rules were read again (Debian #765577; now it
  uses the name of the existing rule), mangled backslashes in names and comments under dash, took a
  name as used when another one matched it as a regular expression (e.g. `x.0` by `xa0`), and without
  udevd's run directory waited 30 s and failed with "Cannot lock …!".
- SELinux builds: when the labels could not be loaded while SELinux was enforcing, the error
  could get lost, so udevd, `systemd-hwdb` and `udevadm hwdb` went on without the labels instead of
  failing.
- The rules syntax check of `make check` never actually ran.
