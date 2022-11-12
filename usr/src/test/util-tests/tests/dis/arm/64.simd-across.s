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
 * C3.6.4 AdvSIMD across lanes
 */
.macro simd_across_hsd op
	\op	h0, v0.8b
	\op	h31, v31.16b
	\op	s0, v0.4h
	\op	s31, v31.8h
	\op	d31, v31.4s
.endm
.macro simd_across_bhs op
	\op	b0, v0.8b
	\op	b31, v31.16b
	\op	h0, v0.4h
	\op	h31, v31.8h
	\op	s31, v31.4s
.endm
.macro simd_across_s op
	\op	s31, v31.4s
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	simd_across_hsd saddlv
	simd_across_bhs smaxv
	simd_across_bhs sminv
	simd_across_bhs addv
	simd_across_hsd uaddlv
	simd_across_bhs umaxv
	simd_across_bhs uminv
	simd_across_s fmaxnmv
	simd_across_s fmaxv
	simd_across_s fminnmv
	simd_across_s fminv
.size libdis_test, [.-libdis_test]
