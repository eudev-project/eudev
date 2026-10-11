AC_PREREQ([2.68])
AC_INIT([eudev],[3.2.15],[https://github.com/eudev-project/eudev/issues])
AC_SUBST(UDEV_VERSION, 262)
AC_CONFIG_SRCDIR([src/udev/udevd.c])
AC_CONFIG_AUX_DIR([build-aux])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_PREFIX_DEFAULT([/usr])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign 1.11])
AM_SILENT_RULES([yes])

LT_PREREQ(2.2)
LT_INIT

# Checks for programs.
AC_PROG_MKDIR_P
AC_PROG_LN_S
AC_PROG_SED
AC_PROG_GREP
AC_PROG_AWK
# Look for pkg-config here, unconditionally: otherwise the first PKG_* macro expands the check, and when
# that one is in a branch that is skipped, e.g. with --disable-blkid, the later checks find no pkg-config.
PKG_PROG_PKG_CONFIG

AC_PROG_CC
AS_IF([test "x$ac_cv_prog_cc_c99" = "xno"], [
	AC_MSG_ERROR([no C99 compiler found, $PACKAGE requires a C99 compiler.])
])

AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for header files.
AC_CHECK_HEADERS(
	[arpa/inet.h fcntl.h inttypes.h limits.h locale.h netinet/in.h sys/ioctl.h \
	sys/mount.h sys/param.h sys/socket.h sys/statvfs.h sys/time.h sys/vfs.h \
	syslog.h termios.h unistd.h],
	[],
	[AC_MSG_ERROR([*** POSIX header not found])]
)

AC_CHECK_HEADERS(
	[mtd/mtd-user.h],
	[],
	[AC_MSG_ERROR([*** KERNEL header not found])]
)

AC_CHECK_HEADERS(
	[linux/btrfs.h],
	[],
	[AC_MSG_WARN([*** KERNEL header not found])]
)

# optional, src/shared/missing_ioprio.h has the definitions for kernel headers without it
AC_CHECK_HEADERS([linux/ioprio.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_CHECK_DECLS([getrandom, gettid, name_to_handle_at, accept4, mkostemp, ppoll, strndupa], [], [],
[[#include <fcntl.h>
#include <linux/random.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>]])

AC_CHECK_SIZEOF(pid_t)
AC_CHECK_SIZEOF(uid_t)
AC_CHECK_SIZEOF(gid_t)
AC_CHECK_SIZEOF(dev_t)
AC_CHECK_SIZEOF(rlim_t,,[[
#include <sys/time.h>
#include <sys/resource.h>]])

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_FUNC_GETGROUPS
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_HEADER_MAJOR
AC_FUNC_MMAP
AC_FUNC_STRERROR_R

AC_CHECK_FUNCS(
	[alarm dup2 ftruncate localtime_r mempcpy mkdir munmap nl_langinfo rmdir \
	setlocale socket stpcpy uname],
	[],
	[AC_MSG_ERROR([*** POSIX function not found])]
)
AC_CHECK_FUNCS([explicit_bzero])
AC_CHECK_FUNCS([secure_getenv])
AC_SEARCH_LIBS([clock_gettime], [rt], [], [AC_MSG_ERROR([*** POSIX librt not found])])
LT_LIB_M

# ------------------------------------------------------------------------------
# With _GNU_SOURCE, glibc 2.38 and later redirect strtol(), sscanf() and friends to their C23 versions,
# which need GLIBC_2.38 and also parse a "0b" prefix. Like systemd, keep the older versions with the
# wrappers of stdlib.h and stdio.h in src/include/glibc, which are included before the headers of glibc.
AC_MSG_CHECKING([whether the C library is glibc])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <features.h>
#ifndef __GLIBC__
#error not glibc
#endif]])], [libc_is_glibc=yes], [libc_is_glibc=no])
AC_MSG_RESULT([$libc_is_glibc])
AS_IF([test "x$libc_is_glibc" = xyes],
	[LIBC_CPPFLAGS='-isystem $(top_srcdir)/src/include/glibc'],
	[LIBC_CPPFLAGS=])
AC_SUBST([LIBC_CPPFLAGS])

# The names of the source files in the locations of the log messages are relative to the top of the source
# tree, like in systemd, see PROJECT_FILE in src/shared/macro.h; make expands the variables in each directory.
AC_SUBST([PROJECT_FILE_CPPFLAGS], ['-DPROJECT_SUBDIR=\"$(subdir)\" -DPROJECT_TOP_SRCDIR=\"$(top_srcdir)\"'])

# ------------------------------------------------------------------------------

# TODO: the old python checks are irrelevant, but we do need python and perl for tests

# ------------------------------------------------------------------------------
# Set paths here

AC_ARG_WITH(
	[rootprefix],
	[AS_HELP_STRING(
		[--with-rootprefix=DIR],
		[rootfs directory prefix for config files and kernel modules])],
	[],
	[with_rootprefix="\${prefix}"]
)

AC_ARG_WITH(
	[rootlibdir],
	[AS_HELP_STRING(
		[--with-rootlibdir=DIR],
		[Root directory for libraries necessary for boot])],
	[],
	[with_rootlibdir=${libdir}]
)

AC_ARG_WITH(
	[rootlibexecdir],
	[AS_HELP_STRING(
		[--with-rootlibexecdir=DIR],
		[Root directory for libexecs necessary for boot])],
	[],
	[with_rootlibexecdir=${with_rootlibdir}/udev]
)

AC_ARG_WITH(
	[rootrundir],
	[AS_HELP_STRING(
		[--with-rootrundir=DIR],
		[Configurable path for /run])],
	[],
	[with_rootrundir=/run]
)

AC_ARG_ENABLE(
	[split-usr],
	[AS_HELP_STRING(
		[--enable-split-usr],
		[Include hard-coded default search paths in / and /usr])],
	[],
	[AS_IF(
		[test "x${ac_default_prefix}" != "x${with_rootprefix}" && test "x${with_rootprefix}" != "x\${prefix}"],
		[enable_split_usr=yes],
		[enable_split_usr=no])]
)

AS_IF(
	[test "x${enable_split_usr}" = "xyes"],
	[AC_DEFINE(HAVE_SPLIT_USR, 1, [Define to include hard-coded default search paths in / and /usr])]
)

# Configured paths
AC_SUBST([rootprefix], [${with_rootprefix}])
AC_SUBST([rootlibdir], [${with_rootlibdir}])
AC_SUBST([rootlibexecdir], [${with_rootlibexecdir}])
AC_SUBST([udevlibexecdir], [${rootlibexecdir}])

# sysconfdir paths
AC_SUBST([udevconfdir],[${sysconfdir}/udev])
AC_SUBST([udevhwdbbin],[${udevconfdir}/hwdb.bin])

# udevlibexecdir paths
# the shipped hwdb files, like in systemd; ${udevconfdir}/hwdb.d is the directory of the administrator
AC_SUBST([udevhwdbdir],[${udevlibexecdir}/hwdb.d])
AC_SUBST([udevrulesdir],[${udevlibexecdir}/rules.d])

# pkgconfigdir paths
AC_SUBST([pkgconfiglibdir], [${libdir}/pkgconfig])
AC_SUBST([sharepkgconfigdir],[${datadir}/pkgconfig])

AC_SUBST([rootrundir],[${with_rootrundir}])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE([programs],
	AS_HELP_STRING([--disable-programs], [disable programs (udevd, udevadm and helpers)]),
	[], [enable_programs="yes"])
AM_CONDITIONAL([ENABLE_PROGRAMS], [test "x$enable_programs" = "xyes"])

# ------------------------------------------------------------------------------
have_blkid=no
AC_ARG_ENABLE(blkid, AS_HELP_STRING([--disable-blkid], [Disable optional blkid support]))
if test "x$enable_blkid" != "xno"; then
	PKG_CHECK_MODULES([BLKID], [blkid >= 2.20],
		[AC_DEFINE(HAVE_BLKID, 1, [Define if blkid is available]) have_blkid=yes], have_blkid=no)
	if test "x$have_blkid" = xno && test "x$enable_blkid" = xyes; then
		AC_MSG_ERROR([*** blkid support requested but not found])
	fi
	if test "x$have_blkid" = xyes; then
		save_LIBS="$LIBS"
		LIBS="$LIBS $BLKID_LIBS"
		AC_CHECK_FUNCS([blkid_probe_set_hint])
		LIBS="$save_LIBS"
	fi
fi
AM_CONDITIONAL(HAVE_BLKID, [test "x$have_blkid" = "xyes"])

# ------------------------------------------------------------------------------
have_selinux=no
AC_ARG_ENABLE(selinux, AS_HELP_STRING([--disable-selinux], [Disable optional SELINUX support]))
if test "x$enable_selinux" != "xno"; then
	PKG_CHECK_MODULES([SELINUX], [libselinux >= 2.1.9],
		[AC_DEFINE(HAVE_SELINUX, 1, [Define if SELinux is available]) have_selinux=yes], have_selinux=no)
	if test "x$have_selinux" = xno && test "x$enable_selinux" = xyes; then
		AC_MSG_ERROR([*** SELinux support requested but libraries not found])
	fi
fi
AM_CONDITIONAL(HAVE_SELINUX, [test "$have_selinux" = "yes"])
if test "x${have_selinux}" != xno ; then
	sushell=/sbin/sushell
else
	sushell=/bin/bash
fi
AC_SUBST(sushell)

# ------------------------------------------------------------------------------
# SMACK: label the device nodes with SECLABEL{smack}="...", and the directories and symlinks created in /dev
# like systemd does, when the kernel has SMACK (/sys/fs/smackfs). Unlike in systemd, off by default.
AC_ARG_ENABLE([smack],
	AS_HELP_STRING([--enable-smack], [enable SMACK support [default=no]]),
	[], [enable_smack=no])
AS_IF([test "x$enable_smack" = "xyes"], [
	AC_CHECK_HEADER([sys/xattr.h], [],
		[AC_MSG_ERROR([*** SMACK support requested but sys/xattr.h not found])])
	AC_DEFINE(HAVE_SMACK, 1, [Define if SMACK support is enabled])
], [test "x$enable_smack" != "xno"], [
	AC_MSG_ERROR([*** invalid value for --enable-smack: $enable_smack])
])

# selinux-util.c uses struct mallinfo which is not available for all C libraries (musl).
AC_CHECK_FUNCS([mallinfo])
# mallinfo is deprecated, prefer to use mallinfo2 when available
AC_CHECK_FUNCS([mallinfo2])

# ------------------------------------------------------------------------------

AC_CHECK_DECL([unshare],
	[AC_DEFINE(HAVE_UNSHARE, 1, [Define if unshare is declared])],
	[AC_CHECK_DECL([SYS_unshare],
		[ ] ,
		[AC_MSG_ERROR([*** unshare nor SYS_unshare found.])],
		[#include <syscall.h>])],
	[#include <sched.h>])

# ------------------------------------------------------------------------------
AC_PATH_TOOL(GPERF, gperf)
if test -z "$GPERF" ; then
	AC_MSG_ERROR([*** gperf not found])
fi

# ------------------------------------------------------------------------------
# The man pages are shipped pre-built (man/make.sh regenerates them), so installing them needs no tools.
# Like the man option of systemd's meson, they are not installed by default. They describe the programs,
# udev.conf, the rules and the hwdb, and libudev has none, so there are none to install without the
# programs.
AC_ARG_ENABLE([manpages],
	AS_HELP_STRING([--enable-manpages], [install the man pages, not with --disable-programs [default=no]]),
	[], [enable_manpages=no])
install_manpages=$enable_manpages
AS_IF([test "x$enable_manpages" = "xyes" && test "x$enable_programs" != "xyes"],
	[install_manpages="no (--disable-programs)"])
AM_CONDITIONAL(ENABLE_MANPAGES, [test "x$install_manpages" = "xyes"])

# ------------------------------------------------------------------------------
have_kmod=no
AC_ARG_ENABLE(kmod, AS_HELP_STRING([--disable-kmod], [disable loadable modules support]))
if test "x$enable_kmod" != "xno"; then
	PKG_CHECK_EXISTS([ libkmod ], have_kmod=yes, have_kmod=no)
	if test "x$have_kmod" = "xyes"; then
		PKG_CHECK_MODULES(KMOD, [ libkmod >= 15 ],
			[AC_DEFINE(HAVE_KMOD, 1, [Define if kmod is available])],
			AC_MSG_ERROR([*** kmod version >= 15 not found]))
	fi
	if test "x$have_kmod" = xno && test "x$enable_kmod" = xyes; then
		AC_MSG_ERROR([*** kmod support requested, but libraries not found])
	fi
fi
AM_CONDITIONAL(HAVE_KMOD, [test "$have_kmod" = "yes"])

# ------------------------------------------------------------------------------

# The hwdb files are installed only with the programs, which compile them into hwdb.bin (udevadm hwdb --update,
# systemd-hwdb update); libudev only reads hwdb.bin.
AC_ARG_ENABLE([hwdb],
	AS_HELP_STRING([--disable-hwdb], [do not install the hwdb.d files, which are never installed with --disable-programs]),
	[], [enable_hwdb=yes])
install_hwdb=$enable_hwdb
AS_IF([test "x$enable_hwdb" = "xyes" && test "x$enable_programs" != "xyes"],
	[install_hwdb="no (--disable-programs)"])
AM_CONDITIONAL(ENABLE_HWDB, [test "x$install_hwdb" = "xyes"])

# ------------------------------------------------------------------------------
# systemd-hwdb - the hwdb tool of systemd, for the scripts and packages that call it
# ------------------------------------------------------------------------------
AC_ARG_ENABLE([systemd-hwdb],
	AS_HELP_STRING([--disable-systemd-hwdb], [do not install the systemd-hwdb tool, which is never installed with --disable-programs]),
	[], [enable_systemd_hwdb=yes])
install_systemd_hwdb=$enable_systemd_hwdb
AS_IF([test "x$enable_systemd_hwdb" = xyes && test "x$enable_programs" != "xyes"],
	[install_systemd_hwdb="no (--disable-programs)"])
AM_CONDITIONAL([ENABLE_SYSTEMD_HWDB], [test "x$install_systemd_hwdb" = xyes])

# ------------------------------------------------------------------------------
# shell completion of udevadm, installed like systemd's meson options do it
# ------------------------------------------------------------------------------
AC_ARG_WITH([bashcompletiondir],
	AS_HELP_STRING([--with-bashcompletiondir=DIR],
		[bash completion directory, "no" to not install the bash completion @<:@default: completionsdir of bash-completion.pc, or DATADIR/bash-completion/completions@:>@]),
	[],
	[PKG_CHECK_VAR([with_bashcompletiondir], [bash-completion], [completionsdir], [],
		[with_bashcompletiondir='${datadir}/bash-completion/completions'])])
AS_IF([test -z "$with_bashcompletiondir"],
	[with_bashcompletiondir='${datadir}/bash-completion/completions'])
AC_SUBST([bashcompletiondir], [$with_bashcompletiondir])
AM_CONDITIONAL([ENABLE_BASH_COMPLETION], [test "x$with_bashcompletiondir" != xno])

AC_ARG_WITH([zshcompletiondir],
	AS_HELP_STRING([--with-zshcompletiondir=DIR],
		[zsh completion directory, "no" to not install the zsh completion @<:@default: DATADIR/zsh/site-functions@:>@]),
	[],
	[with_zshcompletiondir='${datadir}/zsh/site-functions'])
AC_SUBST([zshcompletiondir], [$with_zshcompletiondir])
AM_CONDITIONAL([ENABLE_ZSH_COMPLETION], [test "x$with_zshcompletiondir" != xno])

# ------------------------------------------------------------------------------
# rule-generator - persistent network and optical device rule generator
# ------------------------------------------------------------------------------
# It consists of rules, a script for them and support in udevd, so it is never enabled with --disable-programs.
AC_ARG_ENABLE([rule-generator],
	AS_HELP_STRING([--enable-rule-generator], [enable legacy persistent network, cdrom support, not with --disable-programs]),
	[], [enable_rule_generator=no])
# every value other than "no" enables it; the define and the automake conditional follow the same result
AS_IF([test "x$enable_rule_generator" = xno],
	[install_rule_generator=no],
	[test "x$enable_programs" != xyes],
	[install_rule_generator="no (--disable-programs)"],
	[install_rule_generator=yes])

AS_IF([test "x$install_rule_generator" = xyes],
	[AC_DEFINE([ENABLE_RULE_GENERATOR], [1], [Define if we are enabling rule generator])])

AM_CONDITIONAL([ENABLE_RULE_GENERATOR], [test "x$install_rule_generator" = xyes])

# ------------------------------------------------------------------------------
# net-ifnames-default - what happens without net.ifnames= on the kernel command line: with yes, the
# default, network interfaces are renamed to their predictable names unless net.ifnames=0, and get the
# alternative names regardless of it; with no, they keep the names the kernel gave them, and get the
# predictable names and the alternative names only with net.ifnames=1. The variant of
# 80-net-name-slot.rules and 80-net-altnames.rules that is installed (rules/net-ifnames-no/ for no) follows it.
# ------------------------------------------------------------------------------
AC_ARG_WITH([net-ifnames-default],
	AS_HELP_STRING([--with-net-ifnames-default=yes|no],
		[without net.ifnames= on the kernel command line, rename network interfaces to their predictable names and assign the alternative names, or keep the kernel names @<:@default: yes@:>@]),
	[], [with_net_ifnames_default=yes])
AS_CASE([$with_net_ifnames_default],
	[yes|no], [],
	[AC_MSG_ERROR([*** invalid value of --with-net-ifnames-default: $with_net_ifnames_default (yes or no)])])
AM_CONDITIONAL([NET_IFNAMES_DEFAULT_NO], [test "x$with_net_ifnames_default" = xno])

# ------------------------------------------------------------------------------
# mtd_probe - autoloads FTL module for mtd devices
# ------------------------------------------------------------------------------
AC_ARG_ENABLE([mtd_probe],
	AS_HELP_STRING([--disable-mtd_probe], [disable MTD support]),
	[], [enable_mtd_probe=yes])
AM_CONDITIONAL([ENABLE_MTD_PROBE], [test "x$enable_mtd_probe" = xyes])

# ------------------------------------------------------------------------------
# tpm2 - identification of TPM2 chips (tpm2_id builtin and 60-tpm2-id.rules)
# ------------------------------------------------------------------------------
AC_ARG_ENABLE([tpm2],
	AS_HELP_STRING([--disable-tpm2], [disable the tpm2_id builtin and its rules]),
	[], [enable_tpm2=yes])

if test "x${enable_tpm2}" != xno; then
	AC_DEFINE([ENABLE_TPM2], [1], [Define if the tpm2_id builtin is enabled])
fi

AM_CONDITIONAL([ENABLE_TPM2], [test "x$enable_tpm2" != xno])

# ------------------------------------------------------------------------------
# system-uid-max, system-gid-max - the highest user and group IDs of system accounts, like the meson
# options of systemd: by default, or with 0, SYS_UID_MAX and SYS_GID_MAX of /etc/login.defs of the
# build system, and 999 if it does not set them; like systemd built with compat-mutable-uid-boundaries,
# these are the defaults for the values that /etc/login.defs of the running system does not set
# ------------------------------------------------------------------------------
AC_ARG_WITH([system-uid-max],
	AS_HELP_STRING([--with-system-uid-max=UID],
		[the highest user ID of system users @<:@default: SYS_UID_MAX of /etc/login.defs, or 999@:>@]),
	[], [with_system_uid_max=0])
AC_ARG_WITH([system-gid-max],
	AS_HELP_STRING([--with-system-gid-max=GID],
		[the highest group ID of system groups @<:@default: SYS_GID_MAX of /etc/login.defs, or 999@:>@]),
	[], [with_system_gid_max=0])

# the last value of the setting $1 in /etc/login.defs, like systemd's meson.build finds it
login_defs_value() {
	test -r /etc/login.defs && $AWK -v key="$1" '$1 == key && NF >= 2 { v = $2 } END { print v }' /etc/login.defs
}

AS_IF([test "x$with_system_uid_max" = x0 || test -z "$with_system_uid_max"],
	[with_system_uid_max=`login_defs_value SYS_UID_MAX`])
AS_IF([test -z "$with_system_uid_max"], [with_system_uid_max=999])
AS_IF([test "x$with_system_gid_max" = x0 || test -z "$with_system_gid_max"],
	[with_system_gid_max=`login_defs_value SYS_GID_MAX`])
AS_IF([test -z "$with_system_gid_max"], [with_system_gid_max=999])

for v in "$with_system_uid_max" "$with_system_gid_max"; do
	case "$v" in
	*@<:@!0-9@:>@*|???????????*)
		AC_MSG_ERROR([*** invalid system user or group ID: $v]) ;;
	esac
	AS_IF([test "$v" -ge 4294967295],
		[AC_MSG_ERROR([*** invalid system user or group ID: $v])])
done

AC_DEFINE_UNQUOTED([SYSTEM_UID_MAX], [$with_system_uid_max], [The highest user ID of system users])
AC_DEFINE_UNQUOTED([SYSTEM_GID_MAX], [$with_system_gid_max], [The highest group ID of system groups])

# ------------------------------------------------------------------------------
# nobody-user, nobody-group - the names of the user and the group with the ID 65534, like the meson
# options of systemd, e.g. "nogroup" on Debian; with the same warnings about the local system
# ------------------------------------------------------------------------------
AC_ARG_WITH([nobody-user],
	AS_HELP_STRING([--with-nobody-user=NAME],
		[the name of the nobody user, the one with the UID 65534 @<:@default: nobody@:>@]),
	[], [with_nobody_user=nobody])
AC_ARG_WITH([nobody-group],
	AS_HELP_STRING([--with-nobody-group=NAME],
		[the name of the nobody group, the one with the GID 65534 @<:@default: nobody@:>@]),
	[], [with_nobody_group=nobody])

for v in "$with_nobody_user" "$with_nobody_group"; do
	case "$v" in
	''|yes|no|@<:@0-9-@:>@*|*@<:@!A-Za-z0-9._-@:>@*)
		AC_MSG_ERROR([*** invalid name of the nobody user or group: $v]) ;;
	esac
done

AS_IF([test "x$cross_compiling" = xno && command -v getent >/dev/null 2>&1], [
	nobody_name=`getent passwd 65534 | cut -d: -f1`
	AS_IF([test -n "$nobody_name" && test "x$nobody_name" != "x$with_nobody_user"],
		[AC_MSG_WARN([The local user with the UID 65534 does not match the configured user name "$with_nobody_user" of the nobody user (its name is $nobody_name).])])
	nobody_id=`getent passwd "$with_nobody_user" | cut -d: -f3`
	AS_IF([test -n "$nobody_id" && test "x$nobody_id" != x65534],
		[AC_MSG_WARN([The local user with the configured user name "$with_nobody_user" of the nobody user does not have UID 65534 (it has $nobody_id).])])
	nobody_name=`getent group 65534 | cut -d: -f1`
	AS_IF([test -n "$nobody_name" && test "x$nobody_name" != "x$with_nobody_group"],
		[AC_MSG_WARN([The local group with the GID 65534 does not match the configured group name "$with_nobody_group" of the nobody group (its name is $nobody_name).])])
	nobody_id=`getent group "$with_nobody_group" | cut -d: -f3`
	AS_IF([test -n "$nobody_id" && test "x$nobody_id" != x65534],
		[AC_MSG_WARN([The local group with the configured group name "$with_nobody_group" of the nobody group does not have GID 65534 (it has $nobody_id).])])
])
AS_IF([test "x$with_nobody_user" != "x$with_nobody_group" &&
       ! (test "x$with_nobody_user" = xnobody && test "x$with_nobody_group" = xnogroup)],
	[AC_MSG_WARN([The configured user name "$with_nobody_user" and group name "$with_nobody_group" of the nobody user/group are not equivalent.])])

AC_DEFINE_UNQUOTED([NOBODY_USER_NAME], ["$with_nobody_user"], [The name of the user with the UID 65534])
AC_DEFINE_UNQUOTED([NOBODY_GROUP_NAME], ["$with_nobody_group"], [The name of the group with the GID 65534])

# ------------------------------------------------------------------------------
# foreign-uid-base - the first ID of the range of the 65536 foreign users and groups of systemd, like
# its meson option: a number, also 0 like in systemd, in decimal, or hexadecimal with 0x, which meson
# does not take; the lower 16 bits must be zero, which systemd checks when it is compiled, and the range
# must end below 0xFFFFFFFF; checked without $(( )), which shells before POSIX do not know: printf
# converts a hexadecimal value, and the lower 16 bits are zero if its hexadecimal form ends with 0000
# ------------------------------------------------------------------------------
AC_ARG_WITH([foreign-uid-base],
	AS_HELP_STRING([--with-foreign-uid-base=UID],
		[the first ID of the range of the foreign users and groups of systemd @<:@default: 0x7FFE0000@:>@]),
	[], [with_foreign_uid_base=0x7FFE0000])

case "$with_foreign_uid_base" in
0@<:@xX@:>@)
	foreign_uid_base= ;;
0@<:@xX@:>@*@<:@!0-9a-fA-F@:>@*|0@<:@xX@:>@?????????*)
	foreign_uid_base= ;;
0@<:@xX@:>@*)
	foreign_uid_base=`printf '%u' "$with_foreign_uid_base"` ;;
@<:@1-9@:>@*@<:@!0-9@:>@*|???????????*)
	foreign_uid_base= ;;
@<:@1-9@:>@*)
	foreign_uid_base=$with_foreign_uid_base ;;
0)
	foreign_uid_base=0 ;;
*)
	foreign_uid_base= ;;
esac
AS_IF([test -n "$foreign_uid_base"],
	[AS_CASE([`printf '%x' "$foreign_uid_base"`],
		[0|*0000], [],
		[foreign_uid_base=])])
AS_IF([test -z "$foreign_uid_base" ||
       test "$foreign_uid_base" -gt 4294836224],
	[AC_MSG_ERROR([*** invalid base of the foreign user and group IDs: $with_foreign_uid_base])])

AC_DEFINE_UNQUOTED([FOREIGN_UID_BASE], [${foreign_uid_base}U], [The first ID of the foreign users and groups])

# ------------------------------------------------------------------------------

AC_CONFIG_FILES([Makefile
	hwdb.d/Makefile
	man/Makefile
	rule_generator/Makefile
	rule_generator/write_net_rules
	rules/Makefile
	src/Makefile
	src/ata_id/Makefile
	src/cdrom_id/Makefile
	src/collect/Makefile
	src/dmi_memory_id/Makefile
	src/fido_id/Makefile
	src/mtd_probe/Makefile
	src/scsi_id/Makefile
	src/v4l_id/Makefile
	src/shared/Makefile
	src/libudev/Makefile
	src/libudev/libudev.pc
	src/udev/Makefile
	src/udev/udev.pc
	test/Makefile])

AC_OUTPUT

# ------------------------------------------------------------------------------
# The summary shows the directories fully expanded, as make uses them, e.g. /usr/lib/udev for
# ${exec_prefix}/lib/udev.
expand_dir() {
	expand_dir_value=$1
	for expand_dir_i in 1 2 3 4 5 6 7 8 9 10; do
		eval "expand_dir_next=\"$expand_dir_value\""
		test "x$expand_dir_next" = "x$expand_dir_value" && break
		expand_dir_value=$expand_dir_next
	done
	echo "$expand_dir_value"
}

# command substitution with backticks rather than $(...), which shells before POSIX do not know
summary_prefix=`expand_dir "$prefix"`
summary_exec_prefix=`expand_dir "$exec_prefix"`
summary_sysconfdir=`expand_dir "$sysconfdir"`
summary_datadir=`expand_dir "$datadir"`
summary_includedir=`expand_dir "$includedir"`
summary_bindir=`expand_dir "$bindir"`
summary_libdir=`expand_dir "$libdir"`
summary_rootprefix=`expand_dir "$rootprefix"`
summary_rootlibdir=`expand_dir "$rootlibdir"`
summary_rootlibexecdir=`expand_dir "$rootlibexecdir"`
summary_datarootdir=`expand_dir "$datarootdir"`
summary_rootrundir=`expand_dir "$rootrundir"`
summary_udevconfdir=`expand_dir "$udevconfdir"`
summary_udevhwdbdir=`expand_dir "$udevhwdbdir"`
summary_udevhwdbbin=`expand_dir "$udevhwdbbin"`
summary_udevlibexecdir=`expand_dir "$udevlibexecdir"`
summary_udevrulesdir=`expand_dir "$udevrulesdir"`
summary_pkgconfiglibdir=`expand_dir "$pkgconfiglibdir"`
summary_sharepkgconfigdir=`expand_dir "$sharepkgconfigdir"`
summary_bashcompletiondir=`expand_dir "$with_bashcompletiondir"`
summary_zshcompletiondir=`expand_dir "$with_zshcompletiondir"`
# the completions are installed only with the programs
AS_IF([test "x$enable_programs" != "xyes"], [
	AS_IF([test "x$with_bashcompletiondir" != xno], [summary_bashcompletiondir="no (--disable-programs)"])
	AS_IF([test "x$with_zshcompletiondir" != xno], [summary_zshcompletiondir="no (--disable-programs)"])
])
# the directories of udev.conf and its drop-ins udev.conf.d/*.conf, in the order in which libudev looks at
# them, see udev_conf_dirs[] in src/libudev/libudev.c; each one once
summary_udevconfdirs=
summary_dirs="$summary_udevconfdir $summary_rootrundir/udev /usr/local/lib/udev $summary_udevlibexecdir"
AS_IF([test "x$enable_split_usr" = "xyes"], [summary_dirs="$summary_dirs /lib/udev /usr/lib/udev"])
for summary_dir in $summary_dirs; do
	case " $summary_udevconfdirs " in
	*" $summary_dir "*) ;;
	*) summary_udevconfdirs="${summary_udevconfdirs:+$summary_udevconfdirs }$summary_dir" ;;
	esac
done

AC_MSG_RESULT([
	prefix:                  ${summary_prefix}
	exec_prefix:             ${summary_exec_prefix}
	sysconfdir:              ${summary_sysconfdir}
	datadir:                 ${summary_datadir}
	includedir:              ${summary_includedir}
	bindir:                  ${summary_bindir}
	libdir:                  ${summary_libdir}

	rootprefix:              ${summary_rootprefix}
	rootlibdir:              ${summary_rootlibdir}
	rootlibexecdir:          ${summary_rootlibexecdir}
	datarootdir:             ${summary_datarootdir}
	rootrundir:              ${summary_rootrundir}

	udevconfdir:             ${summary_udevconfdir}
	udev.conf search dirs:   ${summary_udevconfdirs}
	udevhwdbdir:             ${summary_udevhwdbdir}
	udevhwdbbin:             ${summary_udevhwdbbin}
	udevlibexecdir:          ${summary_udevlibexecdir}
	udevrulesdir:            ${summary_udevrulesdir}

	pkgconfiglibdir:         ${summary_pkgconfiglibdir}
	sharepkgconfigdir:       ${summary_sharepkgconfigdir}

	system UIDs:             <=${with_system_uid_max}
	system GIDs:             <=${with_system_gid_max}
	nobody user name:        ${with_nobody_user}
	nobody group name:       ${with_nobody_group}
	foreign UID base:        ${foreign_uid_base}

	SELinux:                 ${have_selinux}
	SMACK:                   ${enable_smack}
	man pages:               ${install_manpages}
	hwdb.d files:            ${install_hwdb}
	systemd-hwdb:            ${install_systemd_hwdb}
	bashcompletiondir:       ${summary_bashcompletiondir}
	zshcompletiondir:        ${summary_zshcompletiondir}
	rule generator:          ${install_rule_generator}
	net.ifnames default:     ${with_net_ifnames_default}
])
