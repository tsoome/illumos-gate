/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Hayashi Naoyuki
 */

#if	defined(_KERNEL)
#include	<sys/types.h>
#include	"reloc.h"
#else
#define	ELF_TARGET_AARCH64
#if defined(DO_RELOC_LIBLD)
#undef DO_RELOC_LIBLD
#define	DO_RELOC_LIBLD_AARCH64
#endif
#include	<stdio.h>
#include	"sgs.h"
#include	"machdep.h"
#include	"libld.h"
#include	"reloc.h"
#include	"conv.h"
#include	"msg.h"
#endif

/*
 * We need to build this code differently when it is used for
 * cross linking:
 *	- Data alignment requirements can differ from those
 *		of the running system, so we can't access data
 *		in units larger than a byte
 *	- We have to include code to do byte swapping when the
 *		target and linker host use different byte ordering,
 *		but such code is a waste when running natively.
 */
#if !defined(DO_RELOC_LIBLD) || defined(__aarch64)
#define	DORELOC_NATIVE
#endif

/*
 * This table represents the current relocations that do_reloc() is able to
 * process.  The relocations below that are marked SPECIAL are relocations that
 * take special processing and shouldn't actually ever be passed to do_reloc().
 */
/* XXXARM: This terrifying table needs to be flowed, and ideally c99-asigned. */
const Rel_entry	reloc_table[R_AARCH64_NUM] = {
/* 0 */		/* R_AARCH64_NONE */
		{0, FLG_RE_NOTREL, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
/* 256 */	/* not defined */            /* R_AARCH64_ABS64 */        /* R_AARCH64_ABS32 */        /* R_AARCH64_ABS16 */
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTREL, 8, 0, 0}, {0, FLG_RE_NOTREL, 4, 0, 0}, {0, FLG_RE_NOTREL, 2, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
/* 512 */
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
/* 768 */
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
/* 1024 */	/* R_AARCH64_COPY */         /* R_AARCH64_GLOB_DAT */     /* R_AARCH64_JUMP_SLOT */    /* R_AARCH64_RELATIVE */
		{0, 0, 0, 0, 0},             {0, FLG_RE_NOTREL, 8, 0, 0}, {0, FLG_RE_NOTREL, 8, 0, 0}, {0, FLG_RE_NOTREL, 8, 0, 0},
/* 1028 */	/* R_AARCH64_TLS_DTPREL64 */ /* R_AARCH64_TLS_DTPMOD64 */ /* R_AARCH64_TLS_TPREL64 */  /* R_AARCH64_TLSDESC */
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
/* 1032 */	/* R_AARCH64_IRELATIVE */
		{0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0}, {0, FLG_RE_NOTSUP, 0, 0, 0},
};

#if defined(_KERNEL)
#define	lml	0		/* Needed by arglist of REL_ERR_* macros */
int
do_reloc_krtld(Word rtype, uchar_t *off, Xword *value, const char *sym,
    const char *file)
#elif defined(DO_RELOC_LIBLD)
/*ARGSUSED5*/
int
do_reloc_ld(Rel_desc *rdesc, uchar_t *off, Xword *value,
    rel_desc_sname_func_t rel_desc_sname_func,
    const char *file, int bswap, void *lml)
#else
int
do_reloc_rtld(Word rtype, uchar_t *off, Xword *value, const char *sym,
    const char *file, void *lml)
#endif
{
#ifdef DO_RELOC_LIBLD
#define	sym (* rel_desc_sname_func)(rdesc)
	Word	rtype = rdesc->rel_rtype;
#endif
	Xword	uvalue = 0;
	Xword	__unused basevalue;
	Xword	__unused corevalue = *value;
	const	Rel_entry	*rep;

	rep = &reloc_table[rtype];

	switch (rep->re_fsize) {
	case 1:
		basevalue = *((uchar_t *)off);
		break;
	case 2:
		basevalue = *((Half *)off);
		break;
	case 4:
		basevalue = *((Word *)off);
		break;
	case 8:
		basevalue = *((Xword *)off);
		break;
	default:
		/*
		 * To keep chkmsg() happy: MSG_INTL(MSG_REL_UNSUPSZ)
		 */
		REL_ERR_UNSUPSZ(lml, file, sym, rtype, rep->re_fsize);
		return (0);
	}

	switch (rtype) {
	case R_AARCH64_ABS64:
	case R_AARCH64_ABS32:
	case R_AARCH64_ABS16:
	case R_AARCH64_GLOB_DAT:
	case R_AARCH64_JUMP_SLOT:
	case R_AARCH64_RELATIVE:
		uvalue = *value;
		break;
	}

	switch (rep->re_fsize) {
	case 1:
		*((uchar_t *)off) = (uchar_t)uvalue;
		break;
	case 2:
		*((Half *)off) = (Half)uvalue;
		break;
	case 4:
		*((Word *)off) = (Word)uvalue;
		break;
	case 8:
		*((Xword *)off) = uvalue;
		break;
	}
	return (1);

#ifdef DO_RELOC_LIBLD
#undef sym
#endif
}
