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
 * C3.3.14 Load/store register pair (offset)
 * C3.3.15 Load/store register pair (post-indexed)
 * C3.3.16 Load/store register pair (pre-indexed)
 *
 * Test the minimum/maximum values for both registers and immediates.
 */

.macro ldst_reg_pair_32 op
	\op	w0,  w30, [x0]
	\op	wzr, wzr, [x0, #-256]
	\op	wzr, w30, [sp, #252]
	\op	w0,  w30, [x0], #0
	\op	wzr, wzr, [x0], #-256
	\op	wzr, w30, [sp], #252
	\op	w0,  w30, [x0, #0]!
	\op	wzr, wzr, [x0, #-256]!
	\op	wzr, w30, [sp, #252]!
.endm

.macro ldst_reg_pair_64 op, multi=2
	\op	x0,  x30, [x0]
	\op	xzr, xzr, [x0, #(-256*\multi)]
	\op	xzr, x30, [sp, #(252*\multi)]
	\op	x0,  x30, [x0], #0
	\op	xzr, xzr, [x0], #(-256*\multi)
	\op	xzr, x30, [sp], #(252*\multi)
	\op	x0,  x30, [x0, #0]!
	\op	xzr, xzr, [x0, #(-256*\multi)]!
	\op	xzr, x30, [sp, #(252*\multi)]!
.endm

.macro ldst_reg_pair_simd_multi op, reg, multi
	\op	\reg\()0,  \reg\()0,  [x0]
	\op	\reg\()31, \reg\()30, [x0, #(-256*\multi)]
	\op	\reg\()30, \reg\()31, [sp, #(252*\multi)]
	\op	\reg\()0,  \reg\()0,  [x0], #0
	\op	\reg\()31, \reg\()30, [x0], #(-256*\multi)
	\op	\reg\()30, \reg\()31, [sp], #(252*\multi)
	\op	\reg\()0,  \reg\()0,  [x0, #0]!
	\op	\reg\()31, \reg\()30, [x0, #(-256*\multi)]!
	\op	\reg\()30, \reg\()31, [sp, #(252*\multi)]!
.endm

.macro ldst_reg_pair_simd op
	ldst_reg_pair_simd_multi \op s 1
	ldst_reg_pair_simd_multi \op d 2
	ldst_reg_pair_simd_multi \op q 4
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	ldst_reg_pair_32   stp
	ldst_reg_pair_32   ldp
	ldst_reg_pair_simd stp
	ldst_reg_pair_simd ldp
	ldst_reg_pair_64   ldpsw 1
	ldst_reg_pair_64   stp
	ldst_reg_pair_64   ldp
.size libdis_test, [.-libdis_test]
