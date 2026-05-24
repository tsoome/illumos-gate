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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 *
 * Copyright 2018 Joyent Inc.
 */

#ifndef _SYS_SYSMACROS_H
#define	_SYS_SYSMACROS_H

#include <stand.h>
#include <sys/param.h>
#include <sys/stddef.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Some macros for units conversion
 */
/*
 * Disk blocks (sectors) and bytes.
 */
#define	dtob(DD)	((DD) << DEV_BSHIFT)
#define	btod(BB)	(((BB) + DEV_BSIZE - 1) >> DEV_BSHIFT)
#define	btodt(BB)	((BB) >> DEV_BSHIFT)
#define	lbtod(BB)	(((offset_t)(BB) + DEV_BSIZE - 1) >> DEV_BSHIFT)

/* common macros */
#ifndef MIN
#define	MIN(a, b)	((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define	MAX(a, b)	((a) < (b) ? (b) : (a))
#endif
#ifndef ABS
#define	ABS(a)		((a) < 0 ? -(a) : (a))
#endif
#ifndef	SIGNOF
#define	SIGNOF(a)	((a) < 0 ? -1 : (a) > 0)
#endif

#ifndef	__DECONST
#define	__DECONST(type, var)	((type)(uintptr_t)(const void *)(var))
#endif

/*
 * Macro for checking power of 2 address alignment.
 */
#define	IS_P2ALIGNED(v, a) ((((uintptr_t)(v)) & ((uintptr_t)(a) - 1)) == 0)

/*
 * Macros for counting and rounding.
 */
#define	howmany(x, y)	(((x)+((y)-1))/(y))
#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))

/*
 * Macro to determine if value is a power of 2
 */
#define	ISP2(x)		(((x) & ((x) - 1)) == 0)

/*
 * Macros for various sorts of alignment and rounding.  The "align" must
 * be a power of 2.  Often times it is a block, sector, or page.
 */

/*
 * return x rounded down to an align boundary
 * eg, P2ALIGN(1200, 1024) == 1024 (1*align)
 * eg, P2ALIGN(1024, 1024) == 1024 (1*align)
 * eg, P2ALIGN(0x1234, 0x100) == 0x1200 (0x12*align)
 * eg, P2ALIGN(0x5600, 0x100) == 0x5600 (0x56*align)
 */
#define	P2ALIGN(x, align)		((x) & -(align))

/*
 * return x % (mod) align
 * eg, P2PHASE(0x1234, 0x100) == 0x34 (x-0x12*align)
 * eg, P2PHASE(0x5600, 0x100) == 0x00 (x-0x56*align)
 */
#define	P2PHASE(x, align)		((x) & ((align) - 1))

/*
 * return how much space is left in this block (but if it's perfectly
 * aligned, return 0).
 * eg, P2NPHASE(0x1234, 0x100) == 0xcc (0x13*align-x)
 * eg, P2NPHASE(0x5600, 0x100) == 0x00 (0x56*align-x)
 */
#define	P2NPHASE(x, align)		(-(x) & ((align) - 1))

/*
 * return x rounded up to an align boundary
 * eg, P2ROUNDUP(0x1234, 0x100) == 0x1300 (0x13*align)
 * eg, P2ROUNDUP(0x5600, 0x100) == 0x5600 (0x56*align)
 */
#define	P2ROUNDUP(x, align)		(-(-(x) & -(align)))

/*
 * return the ending address of the block that x is in
 * eg, P2END(0x1234, 0x100) == 0x12ff (0x13*align - 1)
 * eg, P2END(0x5600, 0x100) == 0x56ff (0x57*align - 1)
 */
#define	P2END(x, align)			(-(~(x) & -(align)))

/*
 * return x rounded up to the next phase (offset) within align.
 * phase should be < align.
 * eg, P2PHASEUP(0x1234, 0x100, 0x10) == 0x1310 (0x13*align + phase)
 * eg, P2PHASEUP(0x5600, 0x100, 0x10) == 0x5610 (0x56*align + phase)
 */
#define	P2PHASEUP(x, align, phase)	((phase) - (((phase) - (x)) & -(align)))

/*
 * return TRUE if adding len to off would cause it to cross an align
 * boundary.
 * eg, P2BOUNDARY(0x1234, 0xe0, 0x100) == TRUE (0x1234 + 0xe0 == 0x1314)
 * eg, P2BOUNDARY(0x1234, 0x50, 0x100) == FALSE (0x1234 + 0x50 == 0x1284)
 */
#define	P2BOUNDARY(off, len, align) \
	(((off) ^ ((off) + (len) - 1)) > (align) - 1)

/*
 * Return TRUE if they have the same highest bit set.
 * eg, P2SAMEHIGHBIT(0x1234, 0x1001) == TRUE (the high bit is 0x1000)
 * eg, P2SAMEHIGHBIT(0x1234, 0x3010) == FALSE (high bit of 0x3010 is 0x2000)
 */
#define	P2SAMEHIGHBIT(x, y)		(((x) ^ (y)) < ((x) & (y)))

/*
 * Typed version of the P2* macros.  These macros should be used to ensure
 * that the result is correctly calculated based on the data type of (x),
 * which is passed in as the last argument, regardless of the data
 * type of the alignment.  For example, if (x) is of type uint64_t,
 * and we want to round it up to a page boundary using "PAGESIZE" as
 * the alignment, we can do either
 *	P2ROUNDUP(x, (uint64_t)PAGESIZE)
 * or
 *	P2ROUNDUP_TYPED(x, PAGESIZE, uint64_t)
 */
#define	P2ALIGN_TYPED(x, align, type)	\
	((type)(x) & -(type)(align))
#define	P2PHASE_TYPED(x, align, type)	\
	((type)(x) & ((type)(align) - 1))
#define	P2NPHASE_TYPED(x, align, type)	\
	(-(type)(x) & ((type)(align) - 1))
#define	P2ROUNDUP_TYPED(x, align, type)	\
	(-(-(type)(x) & -(type)(align)))
#define	P2END_TYPED(x, align, type)	\
	(-(~(type)(x) & -(type)(align)))
#define	P2PHASEUP_TYPED(x, align, phase, type)	\
	((type)(phase) - (((type)(phase) - (type)(x)) & -(type)(align)))
#define	P2CROSS_TYPED(x, y, align, type)	\
	(((type)(x) ^ (type)(y)) > (type)(align) - 1)
#define	P2SAMEHIGHBIT_TYPED(x, y, type) \
	(((type)(x) ^ (type)(y)) < ((type)(x) & (type)(y)))

#if 0
/*
 * Macros to declare bitfields - the order in the parameter list is
 * Low to High - that is, declare bit 0 first.  We only support 8-bit bitfields
 * because if a field crosses a byte boundary it's not likely to be meaningful
 * without reassembly in its nonnative endianness.
 */
#if defined(_BIT_FIELDS_LTOH)
#define	DECL_BITFIELD2(_a, _b)				\
	uint8_t _a, _b
#define	DECL_BITFIELD3(_a, _b, _c)			\
	uint8_t _a, _b, _c
#define	DECL_BITFIELD4(_a, _b, _c, _d)			\
	uint8_t _a, _b, _c, _d
#define	DECL_BITFIELD5(_a, _b, _c, _d, _e)		\
	uint8_t _a, _b, _c, _d, _e
#define	DECL_BITFIELD6(_a, _b, _c, _d, _e, _f)		\
	uint8_t _a, _b, _c, _d, _e, _f
#define	DECL_BITFIELD7(_a, _b, _c, _d, _e, _f, _g)	\
	uint8_t _a, _b, _c, _d, _e, _f, _g
#define	DECL_BITFIELD8(_a, _b, _c, _d, _e, _f, _g, _h)	\
	uint8_t _a, _b, _c, _d, _e, _f, _g, _h
#elif defined(_BIT_FIELDS_HTOL)
#define	DECL_BITFIELD2(_a, _b)				\
	uint8_t _b, _a
#define	DECL_BITFIELD3(_a, _b, _c)			\
	uint8_t _c, _b, _a
#define	DECL_BITFIELD4(_a, _b, _c, _d)			\
	uint8_t _d, _c, _b, _a
#define	DECL_BITFIELD5(_a, _b, _c, _d, _e)		\
	uint8_t _e, _d, _c, _b, _a
#define	DECL_BITFIELD6(_a, _b, _c, _d, _e, _f)		\
	uint8_t _f, _e, _d, _c, _b, _a
#define	DECL_BITFIELD7(_a, _b, _c, _d, _e, _f, _g)	\
	uint8_t _g, _f, _e, _d, _c, _b, _a
#define	DECL_BITFIELD8(_a, _b, _c, _d, _e, _f, _g, _h)	\
	uint8_t _h, _g, _f, _e, _d, _c, _b, _a
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif  /* _BIT_FIELDS_LTOH */
#endif

#if !defined(ARRAY_SIZE)
#define	ARRAY_SIZE(x)	(sizeof (x) / sizeof (x[0]))
#endif

/*
 * Add a value to a uint64_t that saturates at UINT64_MAX instead of wrapping
 * around.
 */
#define	UINT64_OVERFLOW_ADD(val, add) \
	((val) > ((val) + (add)) ? (UINT64_MAX) : ((val) + (add)))

/*
 * Convert to an int64, saturating at INT64_MAX.
 */
#define	UINT64_OVERFLOW_TO_INT64(uval) \
	(((uval) > INT64_MAX) ? INT64_MAX : (int64_t)(uval))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SYSMACROS_H */
