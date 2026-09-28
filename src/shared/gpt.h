/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

#include "id128-util.h"

/* GPT partition type UUIDs of the Discoverable Partitions Specification
 * (https://uapi-group.org/specifications/specs/discoverable_partitions_specification/), after
 * src/systemd/sd-gpt.h of systemd. Only the types needed by udev are defined. */

#define GPT_ROOT_ALPHA       ID128_MAKE(65,23,f8,ae,3e,b1,4e,2a,a0,5a,18,b6,95,ae,65,6f)
#define GPT_ROOT_ARC         ID128_MAKE(d2,7f,46,ed,29,19,4c,b8,bd,25,95,31,f3,c1,65,34)
#define GPT_ROOT_ARM         ID128_MAKE(69,da,d7,10,2c,e4,4e,3c,b1,6c,21,a1,d4,9a,be,d3)
#define GPT_ROOT_ARM64       ID128_MAKE(b9,21,b0,45,1d,f0,41,c3,af,44,4c,6f,28,0d,3f,ae)
#define GPT_ROOT_IA64        ID128_MAKE(99,3d,8d,3d,f8,0e,42,25,85,5a,9d,af,8e,d7,ea,97)
#define GPT_ROOT_LOONGARCH64 ID128_MAKE(77,05,58,00,79,2c,4f,94,b3,9a,98,c9,1b,76,2b,b6)
#define GPT_ROOT_MIPS        ID128_MAKE(e9,43,45,44,6e,2c,47,cc,ba,e2,12,d6,de,af,b4,4c)
#define GPT_ROOT_MIPS64      ID128_MAKE(d1,13,af,76,80,ef,41,b4,bd,b6,0c,ff,4d,3d,4a,25)
#define GPT_ROOT_MIPS_LE     ID128_MAKE(37,c5,8c,8a,d9,13,41,56,a2,5f,48,b1,b6,4e,07,f0)
#define GPT_ROOT_MIPS64_LE   ID128_MAKE(70,0b,da,43,7a,34,45,07,b1,79,ee,b9,3d,7a,7c,a3)
#define GPT_ROOT_PARISC      ID128_MAKE(1a,ac,db,3b,54,44,41,38,bd,9e,e5,c2,23,9b,23,46)
#define GPT_ROOT_PPC         ID128_MAKE(1d,e3,f1,ef,fa,98,47,b5,8d,cd,4a,86,0a,65,4d,78)
#define GPT_ROOT_PPC64       ID128_MAKE(91,2a,de,1d,a8,39,49,13,89,64,a1,0e,ee,08,fb,d2)
#define GPT_ROOT_PPC64_LE    ID128_MAKE(c3,1c,45,e6,3f,39,41,2e,80,fb,48,09,c4,98,05,99)
#define GPT_ROOT_RISCV32     ID128_MAKE(60,d5,a7,fe,8e,7d,43,5c,b7,14,3d,d8,16,21,44,e1)
#define GPT_ROOT_RISCV64     ID128_MAKE(72,ec,70,a6,cf,74,40,e6,bd,49,4b,da,08,e8,f2,24)
#define GPT_ROOT_S390        ID128_MAKE(08,a7,ac,ea,62,4c,4a,20,91,e8,6e,0f,a6,7d,23,f9)
#define GPT_ROOT_S390X       ID128_MAKE(5e,ea,d9,a9,fe,09,4a,1e,a1,d7,52,0d,00,53,13,06)
#define GPT_ROOT_TILEGX      ID128_MAKE(c5,0c,dd,70,38,62,4c,c3,90,e1,80,9a,8c,93,ee,2c)
#define GPT_ROOT_X86         ID128_MAKE(44,47,95,40,f2,97,41,b2,9a,f7,d1,31,d5,f0,45,8a)
#define GPT_ROOT_X86_64      ID128_MAKE(4f,68,bc,e3,e8,cd,4d,b1,96,e7,fb,ca,f9,84,b7,09)

#define GPT_ESP              ID128_MAKE(c1,2a,73,28,f8,1f,11,d2,ba,4b,00,a0,c9,3e,c9,3b)
#define GPT_XBOOTLDR         ID128_MAKE(bc,13,c2,ff,59,e6,42,62,a3,52,b2,75,fd,6f,71,72)

/* The root partition type of the architecture we are built for */
#if defined(__alpha__)
#  define GPT_ROOT_NATIVE GPT_ROOT_ALPHA
#elif defined(__arc__)
#  define GPT_ROOT_NATIVE GPT_ROOT_ARC
#elif defined(__aarch64__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define GPT_ROOT_NATIVE GPT_ROOT_ARM64
#elif defined(__arm__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define GPT_ROOT_NATIVE GPT_ROOT_ARM
#elif defined(__ia64__)
#  define GPT_ROOT_NATIVE GPT_ROOT_IA64
#elif defined(__loongarch_lp64)
#  define GPT_ROOT_NATIVE GPT_ROOT_LOONGARCH64
#elif defined(__mips__) && !defined(__mips64) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define GPT_ROOT_NATIVE GPT_ROOT_MIPS
#elif defined(__mips64) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define GPT_ROOT_NATIVE GPT_ROOT_MIPS64
#elif defined(__mips__) && !defined(__mips64) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define GPT_ROOT_NATIVE GPT_ROOT_MIPS_LE
#elif defined(__mips64) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define GPT_ROOT_NATIVE GPT_ROOT_MIPS64_LE
#elif defined(__parisc__)
#  define GPT_ROOT_NATIVE GPT_ROOT_PARISC
#elif defined(__powerpc__) && defined(__PPC64__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define GPT_ROOT_NATIVE GPT_ROOT_PPC64_LE
#elif defined(__powerpc__) && defined(__powerpc64__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define GPT_ROOT_NATIVE GPT_ROOT_PPC64
#elif defined(__powerpc__)
#  define GPT_ROOT_NATIVE GPT_ROOT_PPC
#elif defined(__riscv) && __riscv_xlen == 32
#  define GPT_ROOT_NATIVE GPT_ROOT_RISCV32
#elif defined(__riscv) && __riscv_xlen == 64
#  define GPT_ROOT_NATIVE GPT_ROOT_RISCV64
#elif defined(__s390__) && !defined(__s390x__)
#  define GPT_ROOT_NATIVE GPT_ROOT_S390
#elif defined(__s390x__)
#  define GPT_ROOT_NATIVE GPT_ROOT_S390X
#elif defined(__tilegx__)
#  define GPT_ROOT_NATIVE GPT_ROOT_TILEGX
#elif defined(__x86_64__)
#  define GPT_ROOT_NATIVE GPT_ROOT_X86_64
#elif defined(__i386__)
#  define GPT_ROOT_NATIVE GPT_ROOT_X86
#endif

/* Flags we recognize on the root partition when doing auto-discovery */
#define GPT_FLAG_NO_AUTO     (UINT64_C(1) << 63)
