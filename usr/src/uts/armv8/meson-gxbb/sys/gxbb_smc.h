/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2017 Hayashi Naoyuki
 */

#ifndef _IO_GXBB_SMC_H
#define _IO_GXBB_SMC_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

static inline uint64_t
gxbb_smc64(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
	register uint64_t x0 __asm__ ("x0") = a0;
	register uint64_t x1 __asm__ ("x1") = a1;
	register uint64_t x2 __asm__ ("x2") = a2;
	register uint64_t x3 __asm__ ("x3") = a3;
	register uint64_t x4 __asm__ ("x4") = a4;

	__asm__ volatile ("smc #0"
	    : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4)
	    :
	    :
	    "x5", "x6", "x7", "x8", "x9", "x10", "x11",
	    "x12", "x13", "x14", "x15", "x16", "x17", "x18", "memory", "cc");

	return x0;
}

static inline uint64_t
gxbb_share_mem_in_base(void)
{
	return gxbb_smc64(0x82000020, 0, 0, 0, 0);
}

static inline uint64_t
gxbb_share_mem_out_base(void)
{
	return gxbb_smc64(0x82000021, 0, 0, 0, 0);
}


static inline uint64_t
gxbb_efuse_read(uint64_t offset, uint64_t size)
{
	return gxbb_smc64(0x82000030, offset, size, 0, 0);
}

static inline uint64_t
gxbb_efuse_write(uint64_t offset, uint64_t size)
{
	return gxbb_smc64(0x82000031, offset, size, 0, 0);
}


#ifdef	__cplusplus
}
#endif

#endif	/* _IO_GXBB_SMC_H */
