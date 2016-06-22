#
#  This file is part of systemd.
#
#  Copyright 2010-2012 Lennart Poettering
#  Copyright 2010-2012 Kay Sievers
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ([2.64])

AC_INIT([systemd],
        [230],
        [http://github.com/systemd/systemd/issues],
        [systemd],
        [http://www.freedesktop.org/wiki/Software/systemd])

AC_CONFIG_SRCDIR([src/udev/udevd.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_PREFIX_DEFAULT([/usr])
AM_MAINTAINER_MODE([enable])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules tar-pax no-dist-gzip dist-xz subdir-objects parallel-tests])
AM_SILENT_RULES([yes])
AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([CANONICAL_HOST], "$host", [Canonical host string.])

AC_PROG_CC_C99

AX_COMPILER_VENDOR
AS_IF([test "x$ax_cv_c_compiler_vendor" = "xgnu"], [
      AC_CHECK_TOOLS([AR], [gcc-ar ar], [:])
      AC_CHECK_TOOLS([NM], [gcc-nm nm], [:])
      AC_CHECK_TOOLS([RANLIB], [gcc-ranlib ranlib], [:])
])

LT_PREREQ(2.2)
LT_INIT([disable-static])

AS_IF([test "x$enable_static" = "xyes"], [AC_MSG_ERROR([--enable-static is not supported by systemd])])
AS_IF([test "x$enable_largefile" = "xno"], [AC_MSG_ERROR([--disable-largefile is not supported by systemd])])

GETTEXT_PACKAGE=systemd
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE", [systemd])

AC_PROG_MKDIR_P
AC_PROG_LN_S
AC_PROG_SED
AC_PROG_GREP
AC_PROG_AWK

AC_PATH_PROG([M4], [m4])
AC_PATH_PROG([KMOD], [kmod], [/usr/bin/kmod], [$PATH:/usr/sbin:/sbin])

AS_IF([! ln --relative --help > /dev/null 2>&1], [AC_MSG_ERROR([*** ln doesn't support --relative ***])])

M4_DEFINES=

AC_CHECK_TOOL(GPERF, gperf)
if test -z "$GPERF" ; then
        AC_MSG_ERROR([*** gperf not found])
fi

# ------------------------------------------------------------------------------
CC_CHECK_FLAGS_APPEND([with_cflags], [CFLAGS], [\
        -pipe \
        -Wall \
        -Wextra \
        -Wundef \
        "-Wformat=2 -Wformat-security -Wformat-nonliteral" \
        -Wlogical-op \
        -Wmissing-include-dirs \
        -Wold-style-definition \
        -Wpointer-arith \
        -Winit-self \
        -Wdeclaration-after-statement \
        -Wfloat-equal \
        -Wsuggest-attribute=noreturn \
        -Werror=missing-prototypes \
        -Werror=implicit-function-declaration \
        -Werror=missing-declarations \
        -Werror=return-type \
        -Wstrict-prototypes \
        -Wredundant-decls \
        -Wmissing-noreturn \
        -Wshadow \
        -Wendif-labels \
        -Wstrict-aliasing=2 \
        -Wwrite-strings \
        -Wno-unused-parameter \
        -Wno-missing-field-initializers \
        -Wno-unused-result \
        -Wno-format-signedness \
        -Werror=overflow \
        -Wdate-time \
        -Wnested-externs \
        -ffast-math \
        -fno-common \
        -fdiagnostics-show-option \
        -fno-strict-aliasing \
        -fvisibility=hidden \
        -fstack-protector \
        -fstack-protector-strong \
        -fPIE \
        --param=ssp-buffer-size=4])

CC_CHECK_FLAG_APPEND([with_cflags], [CFLAGS], [-Werror=shadow], [
#include <time.h>
#include <inttypes.h>
typedef uint64_t usec_t;
usec_t now(clockid_t clock);
int main(void) {
        struct timespec now;
        return 0;
}
])

AS_CASE([$CC], [*clang*],
        [CC_CHECK_FLAGS_APPEND([with_cppflags], [CPPFLAGS], [\
               -Wno-typedef-redefinition \
               -Wno-gnu-variable-sized-type-not-at-end \
        ])])

AS_CASE([$CFLAGS], [*-O[[12345sz\ ]]*],
        [CC_CHECK_FLAGS_APPEND([with_cflags], [CFLAGS], [\
               -flto])],
        [AC_MSG_RESULT([skipping -flto, optimization not enabled])])
AC_SUBST([OUR_CFLAGS], "$with_cflags")

AS_CASE([$CFLAGS], [*-O[[12345sz\ ]]*],
        [CC_CHECK_FLAGS_APPEND([with_cppflags], [CPPFLAGS], [\
               -Wp,-D_FORTIFY_SOURCE=2])],
        [AC_MSG_RESULT([skipping -D_FORTIFY_SOURCE, optimization not enabled])])
AC_SUBST([OUR_CPPFLAGS], "$with_cppflags")

AS_CASE([$CFLAGS], [*-O[[12345sz\ ]]*],
        [CC_CHECK_FLAGS_APPEND([with_ldflags], [LDFLAGS], [\
               -Wl,--gc-sections])],
        [AC_MSG_RESULT([skipping --gc-sections, optimization not enabled])])
AC_SUBST([OUR_CFLAGS], "$with_ldflags")

AS_CASE([$CFLAGS], [*-O[[12345sz\ ]]*],
        [CC_CHECK_FLAGS_APPEND([with_cflags], [CFLAGS], [\
               -ffunction-sections -fdata-sections])],
        [AC_MSG_RESULT([skipping -ffunction/data-section, optimization not enabled])])
AC_SUBST([OUR_CFLAGS], "$with_cflags")

CC_CHECK_FLAGS_APPEND([with_ldflags], [LDFLAGS], [\
        -Wl,--as-needed \
        -Wl,--no-undefined \
        -Wl,-z,relro \
        -Wl,-z,now \
        -pie \
        -Wl,-fuse-ld=gold])
AC_SUBST([OUR_LDFLAGS], "$with_ldflags")

AC_CHECK_SIZEOF(pid_t)
AC_CHECK_SIZEOF(uid_t)
AC_CHECK_SIZEOF(gid_t)
AC_CHECK_SIZEOF(time_t)
AC_CHECK_SIZEOF(dev_t)
AC_CHECK_SIZEOF(rlim_t,,[
       #include <sys/time.h>
       #include <sys/resource.h>
])

# ------------------------------------------------------------------------------
# we use python to build the man page index
have_python=no
AC_ARG_WITH([python],
        [AS_HELP_STRING([--without-python], [Disable building the man page index and systemd-python (default: test)])])

have_lxml=no
AS_IF([test "x$with_python" != "xno"], [
        AM_PATH_PYTHON(,, [:])
        AS_IF([test "x$PYTHON" != "x:"], [
                AC_MSG_CHECKING([for python lxml module])
                AS_IF(["$PYTHON" -c 'import lxml' 2>/dev/null], [have_lxml=yes])
                AC_MSG_RESULT([$have_lxml])
                AS_IF([test "x$have_lxml" = "xyes"], [have_python=yes],
                      [AC_MSG_WARN([*** python support requires python-lxml module installed])])
        ])
])
AS_IF([test "$have_python" != "yes"], [
      AS_IF([test "$with_python" = "yes"],
            [AC_MSG_ERROR([*** python support requested but python support not found])])
      AS_IF([test "$with_python" != "no"],
            [AC_MSG_WARN([*** python support not found, some documentation cannot be built])])
])
AM_CONDITIONAL([HAVE_PYTHON], [test "x$have_python" = "xyes"])

# ------------------------------------------------------------------------------

AC_CHECK_HEADERS([linux/btrfs.h], [], [])

# unconditionally pull-in librt with old glibc versions
AC_SEARCH_LIBS([clock_gettime], [rt], [], [])

AC_CHECK_DECLS([
        gettid,
        name_to_handle_at,
        setns,
        getrandom,
        renameat2,
        kcmp],
        [], [], [[
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <linux/random.h>
#include <stdio.h>
#include <linux/kcmp.h>
]])

AC_CHECK_TYPES([char16_t, char32_t],
               [], [], [[
#include <uchar.h>
]])

AC_CHECK_DECLS([IFLA_INET6_ADDR_GEN_MODE,
                IFLA_MACVLAN_FLAGS,
                IFLA_IPVLAN_MODE,
                IFLA_VTI_REMOTE,
                IFLA_PHYS_PORT_ID,
                IFLA_BOND_AD_INFO,
                IFLA_VLAN_PROTOCOL,
                IFLA_VXLAN_REMCSUM_NOPARTIAL,
                IFLA_IPTUN_ENCAP_DPORT,
                IFLA_GRE_ENCAP_DPORT,
                IFLA_BRIDGE_VLAN_INFO,
                IFLA_BRPORT_PROXYARP,
                IFLA_BRPORT_LEARNING_SYNC,
                IFLA_BR_VLAN_DEFAULT_PVID,
                NDA_IFINDEX,
                IFA_FLAGS],
[], [], [[
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include <linux/if_link.h>
#include <linux/if_bridge.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
]])

# This makes sure pkg.m4 is available.
m4_pattern_forbid([^_?PKG_[A-Z_]+$],[*** pkg.m4 missing, please install pkg-config])

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
        if test "x$have_kmod" = xno -a "x$enable_kmod" = xyes; then
                AC_MSG_ERROR([*** kmod support requested, but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_KMOD, [test "$have_kmod" = "yes"])

# ------------------------------------------------------------------------------
have_blkid=no
AC_ARG_ENABLE(blkid, AS_HELP_STRING([--disable-blkid], [disable blkid support]))
if test "x$enable_blkid" != "xno"; then
        PKG_CHECK_MODULES(BLKID, [ blkid >= 2.24 ],
                [AC_DEFINE(HAVE_BLKID, 1, [Define if blkid is available]) have_blkid=yes], have_blkid=no)
        if test "x$have_blkid" = xno -a "x$enable_blkid" = xyes; then
                AC_MSG_ERROR([*** blkid support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_BLKID, [test "$have_blkid" = "yes"])

# ------------------------------------------------------------------------------
have_selinux=no
AC_ARG_ENABLE(selinux, AS_HELP_STRING([--disable-selinux], [Disable optional SELINUX support]))
if test "x$enable_selinux" != "xno"; then
        PKG_CHECK_MODULES([SELINUX], [libselinux >= 2.1.9],
                [AC_DEFINE(HAVE_SELINUX, 1, [Define if SELinux is available])
                 have_selinux=yes
                 M4_DEFINES="$M4_DEFINES -DHAVE_SELINUX"],
                [have_selinux=no])
        if test "x$have_selinux" = xno -a "x$enable_selinux" = xyes; then
                AC_MSG_ERROR([*** SELinux support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_SELINUX, [test "$have_selinux" = "yes"])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE([smack], AS_HELP_STRING([--disable-smack],[Disable optional SMACK support]),
                [case "${enableval}" in
                        yes) have_smack=yes ;;
                        no) have_smack=no ;;
                        *) AC_MSG_ERROR(bad value ${enableval} for --disable-smack) ;;
                esac],
                [have_smack=auto])

if test "x${have_smack}" != xno; then
        AC_DEFINE(HAVE_SMACK, 1, [Define if SMACK is available])
        M4_DEFINES="$M4_DEFINES -DHAVE_SMACK"
        have_smack=yes
fi

AM_CONDITIONAL([HAVE_SMACK], [test "x$have_smack" = "xyes"])

have_smack_run_label=no
AC_ARG_WITH(smack-run-label,
AS_HELP_STRING([--with-smack-run-label=STRING],
        [run systemd --system itself with a specific SMACK label]),
        [AC_DEFINE_UNQUOTED(SMACK_RUN_LABEL, ["$withval"], [Run systemd itself with SMACK label]) have_smack_run_label=yes],
        [])

if test "x${have_smack_run_label}" = xyes; then
        M4_DEFINES="$M4_DEFINES -DHAVE_SMACK_RUN_LABEL"
fi

AC_ARG_WITH(smack-default-process-label,
AS_HELP_STRING([--with-smack-default-process-label=STRING],
        [default SMACK label for executed processes]),
        [AC_DEFINE_UNQUOTED(SMACK_DEFAULT_PROCESS_LABEL, ["$withval"], [Default SMACK label for executed processes])],
        [])

# ------------------------------------------------------------------------------
have_efi=no
AC_ARG_ENABLE(efi, AS_HELP_STRING([--disable-efi], [disable EFI support]))
if test "x$enable_efi" != "xno"; then
        AC_DEFINE(ENABLE_EFI, 1, [Define if EFI support is to be enabled])
        have_efi=yes
fi
AM_CONDITIONAL(ENABLE_EFI, [test "x$have_efi" = "xyes"])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE(hwdb, [AC_HELP_STRING([--disable-hwdb], [disable hardware database support])],
       enable_hwdb=$enableval, enable_hwdb=yes)
AM_CONDITIONAL(ENABLE_HWDB, [test x$enable_hwdb = xyes])

# ------------------------------------------------------------------------------
have_manpages=no
AC_ARG_ENABLE(manpages, AS_HELP_STRING([--disable-manpages], [disable manpages]))
AC_PATH_PROG([XSLTPROC], [xsltproc])
AS_IF([test "x$enable_manpages" != xno], [
       have_manpages=yes
       AS_IF([test -z "$XSLTPROC"],
             AC_MSG_ERROR([*** xsltproc is required for man pages]))
])
AM_CONDITIONAL(ENABLE_MANPAGES, [test "x$have_manpages" = "xyes"])

# ------------------------------------------------------------------------------
AC_CONFIG_FILES([
        Makefile
])

AC_OUTPUT
AC_MSG_RESULT([
        $PACKAGE_NAME $VERSION
        SELinux:                           ${have_selinux}
        SMACK:                             ${have_smack}
        efi:                               ${have_efi}
        kmod:                              ${have_kmod}
        blkid:                             ${have_blkid}
        hwdb:                              ${enable_hwdb}
        Python:                            ${have_python}
        man pages:                         ${have_manpages}
        Split /usr:                        ${enable_split_usr}

        prefix:                            ${prefix}
        lib dir:                           ${libdir}
        Build Python:                      ${PYTHON}

        CFLAGS:   ${OUR_CFLAGS} ${CFLAGS}
        CPPFLAGS: ${OUR_CPPFLAGS} ${CPPFLAGS}
        LDFLAGS:  ${OUR_LDFLAGS} ${LDFLAGS}
])
