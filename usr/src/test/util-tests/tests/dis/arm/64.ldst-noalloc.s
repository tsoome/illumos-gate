/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017 Joyent, Inc.
 */

/*
 * C3.3.7 Load/store no-allocate pair (offset)
 *
 * C5.6.176 STNP
 * C5.6.80  LDNP
 * C6.3.283 STNP (SIMD&FP)
 * C6.3.164 LDNP (SIMD&FP)
 *
 * Test the minimum/maximum of registers and signed imm7.
 */
.macro ldstnoalloc1 op, reg, size, simd=0
	\op	\reg\()0,  \reg\()0,  [x0]
	\op	\reg\()30, \reg\()30, [x30, #(\size*63)]
	.if \simd
	\op	\reg\()31, \reg\()31, [sp,  #(\size*-64)]
	.else
	\op	\reg\()zr, \reg\()zr, [sp,  #(\size*-64)]
	.endif
.endm

.macro ldstnoalloc op
	ldstnoalloc1 \op, w,  4,
	ldstnoalloc1 \op, x,  8,
	ldstnoalloc1 \op, s,  4, 1
	ldstnoalloc1 \op, d,  8, 1
	ldstnoalloc1 \op, q, 16, 1
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	ldstnoalloc stnp
	ldstnoalloc ldnp
.size libdis_test, [.-libdis_test]
