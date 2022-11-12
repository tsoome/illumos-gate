/*
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
 * C3.6.9 AdvSIMD scalar shift by immediate
 */
.macro simd_ss1 op low high
	\op	d0, d31, #\low
	\op	d31, d0, #\high
.endm
.macro simd_ss2 op
	\op	b0, b31, #0
	\op	b31, b0, #7
	\op	h0, h31, #0
	\op	h31, h0, #15
	\op	s0, s31, #0
	\op	s31, s0, #31
	\op	d0, d31, #0
	\op	d31, d0, #63
.endm
.macro simd_ss3 op
	\op	b0, h31, #1
	\op	b31, h0, #8
	\op	h0, s31, #1
	\op	h31, s0, #16
	\op	s0, d31, #1
	\op	s31, d0, #32
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	simd_ss1 sshr 1 64
	simd_ss1 ssra 1 64
	simd_ss1 srshr 1 64
	simd_ss1 srsra 1 64
	simd_ss1 shl 0 63

	simd_ss2 sqshl
	simd_ss3 sqshrn
	simd_ss3 sqrshrn
	/*
	simd_ss scvtf
	simd_ss fcvtzs
	*/
.size libdis_test, [.-libdis_test]
