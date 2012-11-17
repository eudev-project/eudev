
AC_PREREQ([2.68])
AC_INIT([udev-ng], [0.1], [http://bugzilla.gentoo.org])
AC_CONFIG_SRCDIR([src/udev/udevd.c])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

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
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

GTK_DOC_CHECK([1.18],[--flavour no-tmpl])

AC_PATH_PROG([M4], [m4])
AC_PATH_PROG([XSLTPROC], [xsltproc])
AC_PATH_TOOL(GPERF, gperf)
if test -z "$GPERF" ; then
        AC_MSG_ERROR([*** gperf not found])
fi

# Checks for header files.
AC_CHECK_HEADERS(
    [arpa/inet.h fcntl.h inttypes.h limits.h netinet/in.h stddef.h stdint.h stdlib.h string.h \
     sys/ioctl.h sys/mount.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h],
    [],
    [AC_MSG_ERROR([*** POSIX header not found])]
)

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_DECLS([gettid, pivot_root, name_to_handle_at], [], [], [[#include <sys/types.h>
#include <unistd.h>
#include <sys/mount.h>
#include <fcntl.h>]])


# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_HEADER_MAJOR
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_STRNLEN
AC_FUNC_STRTOD
AC_CHECK_FUNCS(
    [alarm dup2 ftruncate memmove mempcpy memset \
     mkdir munmap rmdir socket strcasecmp strchr strcspn \
     strdup strerror strndup strpbrk strrchr strspn strstr \
     strtol strtoul strtoull uname],
    [],
    [AC_MSG_ERROR([*** POSIX function not found])]
)
AC_SEARCH_LIBS([clock_gettime], [rt], [], [AC_MSG_ERROR([*** POSIX librt not found])])
AC_SEARCH_LIBS([sqrt], [m], [], [AC_MSG_ERROR([*** POSIX libm not found])])


# we use python to build the man page index, and for systemd-python
have_python=no
have_python_devel=no

AC_ARG_WITH([python],
        [AS_HELP_STRING([--without-python], [Disable building the man page index and systemd-python (default: test)])])

AS_IF([test "x$with_python" != "xno"], [
        AM_PATH_PYTHON(,, [:])
        AS_IF([test "$PYTHON" != :], [have_python=yes])
])
AM_CONDITIONAL([HAVE_PYTHON], [test "$have_python" = "yes"])

AS_IF([test "x$with_python" != "xno"], [
        AC_PATH_PROG(PYTHON_CONFIG, python${PYTHON_VERSION}-config)
        AS_IF([test -n "$PYTHON_CONFIG"], [
              have_python_devel=yes
              PYTHON_CFLAGS="`$PYTHON_CONFIG --cflags`"
              PYTHON_LIBS="`$PYTHON_CONFIG --ldflags`"
              AC_SUBST(PYTHON_CFLAGS)
              AC_SUBST(PYTHON_LIBS)
        ])
])
AM_CONDITIONAL([HAVE_PYTHON_DEVEL], [test "$have_python_devel" = "yes"])

# ------------------------------------------------------------------------------

have_introspection=no
AC_ARG_ENABLE([introspection],
        [AS_HELP_STRING([--without-introspection], [Disable man page index and systemd-python (default: no)])])
GOBJECT_INTROSPECTION_CHECK([1.31.1])
AM_CONDITIONAL([HAVE_INTROSPECTION], [test "$have_introspection" = "yes"])

# ------------------------------------------------------------------------------
have_selinux=no
AC_ARG_ENABLE(selinux, AS_HELP_STRING([--disable-selinux], [Disable optional SELINUX support]))
if test "x$enable_selinux" != "xno"; then
        PKG_CHECK_MODULES([SELINUX], [libselinux >= 2.1.9],
                [AC_DEFINE(HAVE_SELINUX, 1, [Define if SELinux is available]) have_selinux=yes], have_selinux=no)
        if test "x$have_selinux" = xno -a "x$enable_selinux" = xyes; then
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
AC_ARG_ENABLE([acl],
        AS_HELP_STRING([--disable-acl],[Disable optional ACL support]),
                [case "${enableval}" in
                        yes) have_acl=yes ;;
                        no) have_acl=no ;;
                        *) AC_MSG_ERROR(bad value ${enableval} for --disable-acl) ;;
                esac],
                [have_acl=auto])

if test "x${have_acl}" != xno ; then
        AC_CHECK_HEADERS(
                [sys/acl.h acl/libacl.h],
                [have_acl=yes],
                [if test "x$have_acl" = xyes ; then
                        AC_MSG_ERROR([*** ACL headers not found.])
                fi])

        AC_CHECK_LIB(
                [acl],
                [acl_get_file],
                [have_acl=yes],
                [if test "x$have_acl" = xyes ; then
                        AC_MSG_ERROR([*** libacl not found.])
                fi])

        if test "x$have_acl" = xyes ; then
                ACL_LIBS="-lacl"
                AC_DEFINE(HAVE_ACL, 1, [ACL available])
        else
                have_acl=no
        fi
else
        ACL_LIBS=
fi
AC_SUBST(ACL_LIBS)
AM_CONDITIONAL([HAVE_ACL], [test "x$have_acl" != xno])

# ------------------------------------------------------------------------------
AC_ARG_WITH(firmware-path,
       AS_HELP_STRING([--with-firmware-path=DIR[[[:DIR[...]]]]],
          [Firmware search path (default=ROOTPREFIX/lib/firmware/updates:ROOTPREFIX/lib/firmware)]),
       [], [with_firmware_path="$rootprefix/lib/firmware/updates:$rootprefix/lib/firmware"])
OLD_IFS=$IFS
IFS=:
for i in $with_firmware_path; do
       if test "x${FIRMWARE_PATH}" = "x"; then
              FIRMWARE_PATH="\\\"${i}/\\\""
       else
              FIRMWARE_PATH="${FIRMWARE_PATH}, \\\"${i}/\\\""
       fi
done
IFS=$OLD_IFS
AC_SUBST([FIRMWARE_PATH], [$FIRMWARE_PATH])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE([gudev],
       AS_HELP_STRING([--disable-gudev], [disable Gobject libudev support @<:@default=enabled@:>@]),
       [], [enable_gudev=yes])
AS_IF([test "x$enable_gudev" = "xyes"], [ PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.22.0 gobject-2.0 >= 2.22.0]) ])
AM_CONDITIONAL([ENABLE_GUDEV], [test "x$enable_gudev" = "xyes"])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE([keymap],
       AS_HELP_STRING([--disable-keymap], [disable keymap fixup support @<:@default=enabled@:>@]),
       [], [enable_keymap=yes])
AM_CONDITIONAL([ENABLE_KEYMAP], [test "x$enable_keymap" = "xyes"])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE(gtk-doc, AS_HELP_STRING([--disable-gtk-doc], [disable gtk-doc]))
AS_IF(
        [test "x$enable_gtk_doc" = "xyes" -a "x$XSLTPROC" = x],
        [AC_MSG_ERROR([*** GTK doc requested but xsltproc not found])]
)

# ------------------------------------------------------------------------------
have_manpages=no
AC_ARG_ENABLE(manpages, AS_HELP_STRING([--disable-manpages], [disable manpages]))
AS_IF([test "x$enable_manpages" != xno], [
        AS_IF([test "x$enable_manpages" = xyes -a "x$XSLTPROC" = x], [
                AC_MSG_ERROR([*** Manpages requested but xsltproc not found])
        ])
        AS_IF([test "x$XSLTPROC" != x], [have_manpages=yes])
])
AM_CONDITIONAL(ENABLE_MANPAGES, [test "x$have_manpages" = "xyes"])

# ------------------------------------------------------------------------------

AC_ARG_WITH([rootprefix],
        AS_HELP_STRING([--with-rootprefix=DIR], [rootfs directory prefix for config files and kernel modules]),
        [], [with_rootprefix=${ac_default_prefix}])

AC_ARG_WITH([rootlibdir],
        AS_HELP_STRING([--with-rootlibdir=DIR], [Root directory for libraries necessary for boot]),
        [],
        [with_rootlibdir=${libdir}])

AC_ARG_ENABLE([split-usr],
        AS_HELP_STRING([--enable-split-usr], [Assume that /bin, /sbin aren\'t symlinks into /usr]),
        [],
        [AS_IF([test "x${ac_default_prefix}" != "x${with_rootprefix}"], [
                enable_split_usr=yes
        ], [
                enable_split_usr=no
        ])])

AS_IF([test "x${enable_split_usr}" = "xyes"], [
        AC_DEFINE(HAVE_SPLIT_USR, 1, [Define if /bin, /sbin aren't symlinks into /usr])
])

AC_SUBST([rootprefix], [$with_rootprefix])
AC_SUBST([rootlibdir], [$with_rootlibdir])

# ------------------------------------------------------------------------------

AC_CONFIG_FILES([Makefile
                 docs/Makefile
                 docs/gudev/Makefile
                 docs/libudev/Makefile
                 hwdb/Makefile
                 keymaps-force-release/Makefile
                 keymaps/Makefile
                 man/Makefile
                 rules/Makefile
                 src/Makefile
                 src/gudev/Makefile
                 src/libudev/Makefile
                 src/test/Makefile
                 src/udev/Makefile
                 test/Makefile
                 src/udev/udev.pc
                 src/gudev/gudev-1.0.pc
                 src/libudev/libudev.pc
                 docs/gudev/version.xml
                 docs/libudev/version.xml
                 src/udev/keymap/keyboard-force-release.sh])
AC_OUTPUT
