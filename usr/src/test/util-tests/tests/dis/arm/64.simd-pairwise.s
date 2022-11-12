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
 * C3.6.8 AdvSIMD scalar pairwise
 */
.macro simd_pairwise op s=0
	.if \s
	\op	s0, v0.2s
	\op	s31, v31.2s
	.endif
	\op	d0, v0.2d
	\op	d31, v31.2d
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	simd_pairwise addp
	simd_pairwise fmaxnmp 1
	simd_pairwise faddp 1
	simd_pairwise fmaxp 1
	simd_pairwise fminnmp 1
	simd_pairwise fminp 1
.size libdis_test, [.-libdis_test]
