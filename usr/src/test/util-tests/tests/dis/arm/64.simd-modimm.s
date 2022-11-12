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

/* 8-bit */
.macro simd_modimm_8 op
	\op	v0.8b,   #0xa
	\op	v31.16b, #0x5, lsl 0
.endm
/* 16-bit shifted immediate */
.macro simd_modimm_16 op
	\op	v0.4h,  #0x5, lsl 0
	\op	v31.8h, #0xa, lsl 8
.endm
/* 32-bit shifted immediate */
.macro simd_modimm_32 op
	\op	v0.2s,  #0
	\op	v31.4s, #0x5,  lsl 8
	\op	v0.4s,  #0xa,  lsl 16
	\op	v31.2s, #0xff, lsl 24
.endm
/* 32-bit shifting ones */
.macro simd_modimm_32_1 op
	\op	v0.2s,  #0x5, msl 8
	\op	v31.4s, #0xa, msl 16
.endm
/*
 * C3.6.6 AdvSIMD modified immediate
 */
.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	simd_modimm_32 movi
	simd_modimm_32 orr
	simd_modimm_16 movi
	simd_modimm_16 orr
	simd_modimm_32_1 movi
	simd_modimm_8 movi
	/* XXX: enable when FP output fixed.
	fmov v0.2s, #2.0
	fmov v31.4s, #1.0
	*/
	simd_modimm_32 mvni
	simd_modimm_32 bic
	simd_modimm_16 mvni
	simd_modimm_16 bic
	simd_modimm_32_1 mvni
	/* scalar/vector */
	movi	d0, #0x0
	movi	d31, #0xff00ff00ff00ff00
	movi	v0.2d, #0x00ff00ff00ff00ff
	movi	v31.2d, #0xffffffffffffffff
	/* XXX: enable when FP output fixed.
	fmov v0.2d, #1.0
	fmov v31.2d, #2.0
	*/
.size libdis_test, [.-libdis_test]
