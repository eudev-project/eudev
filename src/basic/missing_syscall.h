#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2016 Zbigniew Jędrzejewski-Szmek

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

/* Missing glibc definitions to access certain kernel APIs */

/* ======================================================================= */

#if !HAVE_DECL_GETRANDOM
#  ifndef __NR_getrandom
#    if defined __x86_64__
#      define __NR_getrandom 318
#    elif defined(__i386__)
#      define __NR_getrandom 355
#    elif defined(__arm__)
#      define __NR_getrandom 384
#   elif defined(__aarch64__)
#      define __NR_getrandom 278
#    elif defined(__ia64__)
#      define __NR_getrandom 1339
#    elif defined(__m68k__)
#      define __NR_getrandom 352
#    elif defined(__s390x__)
#      define __NR_getrandom 349
#    elif defined(__powerpc__)
#      define __NR_getrandom 359
#    elif defined _MIPS_SIM
#      if _MIPS_SIM == _MIPS_SIM_ABI32
#        define __NR_getrandom 4353
#      endif
#      if _MIPS_SIM == _MIPS_SIM_NABI32
#        define __NR_getrandom 6317
#      endif
#      if _MIPS_SIM == _MIPS_SIM_ABI64
#        define __NR_getrandom 5313
#      endif
#    else
#      warning "__NR_getrandom unknown for your architecture"
#    endif
#  endif

static inline int getrandom(void *buffer, size_t count, unsigned flags) {
#  ifdef __NR_getrandom
        return syscall(__NR_getrandom, buffer, count, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}
#endif

/* ======================================================================= */

#if !HAVE_DECL_GETTID
static inline pid_t gettid(void) {
        return (pid_t) syscall(SYS_gettid);
}
#endif

/* ======================================================================= */

#if !HAVE_DECL_NAME_TO_HANDLE_AT
#  ifndef __NR_name_to_handle_at
#    if defined(__x86_64__)
#      define __NR_name_to_handle_at 303
#    elif defined(__i386__)
#      define __NR_name_to_handle_at 341
#    elif defined(__arm__)
#      define __NR_name_to_handle_at 370
#    elif defined(__powerpc__)
#      define __NR_name_to_handle_at 345
#    else
#      error "__NR_name_to_handle_at is not defined"
#    endif
#  endif

struct file_handle {
        unsigned int handle_bytes;
        int handle_type;
        unsigned char f_handle[0];
};

static inline int name_to_handle_at(int fd, const char *name, struct file_handle *handle, int *mnt_id, int flags) {
#  ifdef __NR_name_to_handle_at
        return syscall(__NR_name_to_handle_at, fd, name, handle, mnt_id, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}
#endif

/* ======================================================================= */

#if !HAVE_DECL_SETNS
#  ifndef __NR_setns
#    if defined(__x86_64__)
#      define __NR_setns 308
#    elif defined(__i386__)
#      define __NR_setns 346
#    else
#      error "__NR_setns is not defined"
#    endif
#  endif

static inline int setns(int fd, int nstype) {
#  ifdef __NR_setns
        return syscall(__NR_setns, fd, nstype);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}
#endif

/* ======================================================================= */

static inline pid_t raw_getpid(void) {
#if defined(__alpha__)
        return (pid_t) syscall(__NR_getxpid);
#else
        return (pid_t) syscall(__NR_getpid);
#endif
}

/* ======================================================================= */

#if !HAVE_DECL_RENAMEAT2
#  ifndef __NR_renameat2
#    if defined __x86_64__
#      define __NR_renameat2 316
#    elif defined __arm__
#      define __NR_renameat2 382
#    elif defined _MIPS_SIM
#      if _MIPS_SIM == _MIPS_SIM_ABI32
#        define __NR_renameat2 4351
#      endif
#      if _MIPS_SIM == _MIPS_SIM_NABI32
#        define __NR_renameat2 6315
#      endif
#      if _MIPS_SIM == _MIPS_SIM_ABI64
#        define __NR_renameat2 5311
#      endif
#    elif defined __i386__
#      define __NR_renameat2 353
#    else
#      warning "__NR_renameat2 unknown for your architecture"
#    endif
#  endif

static inline int renameat2(int oldfd, const char *oldname, int newfd, const char *newname, unsigned flags) {
#  ifdef __NR_renameat2
        return syscall(__NR_renameat2, oldfd, oldname, newfd, newname, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}
#endif

/* ======================================================================= */

#if !HAVE_DECL_KCMP
static inline int kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2) {
#  ifdef __NR_kcmp
        return syscall(__NR_kcmp, pid1, pid2, type, idx1, idx2);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}
#endif
