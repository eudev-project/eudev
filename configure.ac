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

AC_PROG_CC
AS_IF([test "x$ac_cv_prog_cc_c99" = "xno"], [
	AC_MSG_ERROR([no C99 compiler found, $PACKAGE requires a C99 compiler.])
])

AC_PROG_CXX
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

AC_PATH_PROG([M4], [m4])

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
AC_SUBST([udevconffile],[${udevconfdir}/udev.conf])
AC_SUBST([udevhwdbdir],[${udevconfdir}/hwdb.d])
AC_SUBST([udevhwdbbin],[${udevconfdir}/hwdb.bin])

# udevlibexecdir paths
AC_SUBST([udevkeymapdir],[${udevlibexecdir}/keymaps])
AC_SUBST([udevkeymapforceredir],[${udevkeymapdir}/force-release])
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
AC_ARG_ENABLE([manpages], AS_HELP_STRING([--disable-manpages],[disable manpages]),[],[enable_manpages=no])
AM_CONDITIONAL(ENABLE_MANPAGES, [test "x$enable_manpages" = "xyes"])

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

AC_ARG_ENABLE([hwdb], AS_HELP_STRING([--enable-hwdb],[install hwdb.d files]),[],[enable_hwdb=yes])
AM_CONDITIONAL(ENABLE_HWDB, [test "x$enable_hwdb" = "xyes"])

# ------------------------------------------------------------------------------
# systemd-hwdb - the hwdb tool of systemd, for the scripts and packages that call it
# ------------------------------------------------------------------------------
AC_ARG_ENABLE([systemd-hwdb],
	AS_HELP_STRING([--disable-systemd-hwdb], [do not install the systemd-hwdb tool]),
	[], [enable_systemd_hwdb=yes])
AM_CONDITIONAL([ENABLE_SYSTEMD_HWDB], [test "x$enable_systemd_hwdb" = xyes])

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
AC_ARG_ENABLE([rule-generator],
	AS_HELP_STRING([--enable-rule-generator], [enable legacy persistent network, cdrom support]),
	[], [enable_rule_generator=no])

if test "x${enable_rule_generator}" != xno; then
	AC_DEFINE([ENABLE_RULE_GENERATOR], [1], [Define if we are enabling rule generator])
fi

AM_CONDITIONAL([ENABLE_RULE_GENERATOR], [test "x$enable_rule_generator" = xyes])

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
# build system, and 999 if it does not set them
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
	[with_system_uid_max=$(login_defs_value SYS_UID_MAX)])
AS_IF([test -z "$with_system_uid_max"], [with_system_uid_max=999])
AS_IF([test "x$with_system_gid_max" = x0 || test -z "$with_system_gid_max"],
	[with_system_gid_max=$(login_defs_value SYS_GID_MAX)])
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
	nobody_name=$(getent passwd 65534 | cut -d: -f1)
	AS_IF([test -n "$nobody_name" && test "x$nobody_name" != "x$with_nobody_user"],
		[AC_MSG_WARN([The local user with the UID 65534 does not match the configured user name "$with_nobody_user" of the nobody user (its name is $nobody_name).])])
	nobody_id=$(getent passwd "$with_nobody_user" | cut -d: -f3)
	AS_IF([test -n "$nobody_id" && test "x$nobody_id" != x65534],
		[AC_MSG_WARN([The local user with the configured user name "$with_nobody_user" of the nobody user does not have UID 65534 (it has $nobody_id).])])
	nobody_name=$(getent group 65534 | cut -d: -f1)
	AS_IF([test -n "$nobody_name" && test "x$nobody_name" != "x$with_nobody_group"],
		[AC_MSG_WARN([The local group with the GID 65534 does not match the configured group name "$with_nobody_group" of the nobody group (its name is $nobody_name).])])
	nobody_id=$(getent group "$with_nobody_group" | cut -d: -f3)
	AS_IF([test -n "$nobody_id" && test "x$nobody_id" != x65534],
		[AC_MSG_WARN([The local group with the configured group name "$with_nobody_group" of the nobody group does not have GID 65534 (it has $nobody_id).])])
])
AS_IF([test "x$with_nobody_user" != "x$with_nobody_group" &&
       ! (test "x$with_nobody_user" = xnobody && test "x$with_nobody_group" = xnogroup)],
	[AC_MSG_WARN([The configured user name "$with_nobody_user" and group name "$with_nobody_group" of the nobody user/group are not equivalent.])])

AC_DEFINE_UNQUOTED([NOBODY_USER_NAME], ["$with_nobody_user"], [The name of the user with the UID 65534])
AC_DEFINE_UNQUOTED([NOBODY_GROUP_NAME], ["$with_nobody_group"], [The name of the group with the GID 65534])

# ------------------------------------------------------------------------------

AC_CONFIG_FILES([Makefile
	hwdb/Makefile
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

AC_MSG_RESULT([
	prefix:                  ${prefix}
	exec_prefix:             ${exec_prefix}
	sysconfdir:              ${sysconfdir}
	datadir:                 ${datadir}
	includedir:              ${includedir}
	bindir:                  ${bindir}
	libdir:                  ${libdir}

	rootprefix:              ${rootprefix}
	rootlibdir:              ${rootlibdir}
	rootlibexecdir:          ${rootlibexecdir}
	datarootdir:             ${datarootdir}
	rootrundir:              ${rootrundir}

	udevconfdir:             ${udevconfdir}
	udevconffile:            ${udevconffile}
	udevhwdbdir:             ${udevhwdbdir}
	udevhwdbbin:             ${udevhwdbbin}
	udevlibexecdir:          ${udevlibexecdir}
	udevkeymapdir:           ${udevkeymapdir}
	udevkeymapforceredir:    ${udevkeymapforceredir}
	udevrulesdir:            ${udevrulesdir}

	pkgconfiglibdir:         ${libdir}/pkgconfig
	sharepkgconfigdir        ${datadir}/pkgconfig

	system UIDs:             <=${with_system_uid_max}
	system GIDs:             <=${with_system_gid_max}
	nobody user name:        ${with_nobody_user}
	nobody group name:       ${with_nobody_group}

	systemd-hwdb:            ${enable_systemd_hwdb}
	bashcompletiondir:       ${with_bashcompletiondir}
	zshcompletiondir:        ${with_zshcompletiondir}
])

# ------------------------------------------------------------------------------

dnl Set configured scripts executable
if test -f  src/keymap/check-keymaps.sh; then
	chmod +x src/keymap/check-keymaps.sh
fi

if test -f src/keymap/keyboard-force-release.sh; then
	chmod +x src/keymap/keyboard-force-release.sh
fi

