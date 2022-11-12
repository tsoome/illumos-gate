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
 * C3.3.13 Load/store register (unsigned immediate)
 *
 * C5.6.143 PRFM is part of this group but is tested in XXX.
 *
 * Test the minimum/maximum values for both registers and unsigned immediates.
 */
.macro ldst_reg_unsigned_32 op, mult=1
	\op	w0,  [x0]
	\op	wzr, [sp, #(4095*\mult)]
.endm

.macro ldst_reg_unsigned_64 op, mult=1
	\op	x0,  [x0]
	\op	xzr, [sp, #(4095*\mult)]
.endm

.macro ldst_reg_unsigned_simd op
	\op	b0,  [x0]
	\op	b31, [sp, #4095]
	\op	h0,  [x0]
	\op	h31, [sp, #8190]
	\op	s0,  [x0]
	\op	s31, [sp, #16380]
	\op	d0,  [x0]
	\op	d31, [sp, #32760]
	\op	q0,  [x0]
	\op	q31, [sp, #65520]
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	ldst_reg_unsigned_32   strb
	ldst_reg_unsigned_32   ldrb
	ldst_reg_unsigned_64   ldrsb
	ldst_reg_unsigned_32   ldrsb
	ldst_reg_unsigned_simd str
	ldst_reg_unsigned_simd ldr
	ldst_reg_unsigned_32   strh  2
	ldst_reg_unsigned_32   ldrh  2
	ldst_reg_unsigned_64   ldrsh 2
	ldst_reg_unsigned_32   ldrsh 2
	ldst_reg_unsigned_32   str   4
	ldst_reg_unsigned_32   ldr   4
	ldst_reg_unsigned_64   ldrsw 4
	ldst_reg_unsigned_64   str   8
	ldst_reg_unsigned_64   ldr   8
.size libdis_test, [.-libdis_test]
