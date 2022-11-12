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
 * C3.3.10 Load/store register (register offset)
 *
 * C5.6.145 PRFM is part of this group but is tested in tst.ldst-prfm.s
 */
.macro ldst_reg_offset_simd op, reg, size
	\op	\reg\()0,  [x0,  x0]
	\op	\reg\()31, [sp,  wzr, uxtw]
	\op	\reg\()0,  [x30, w30, uxtw #\size]
	\op	\reg\()31, [sp,  xzr, lsl  #0]
	\op	\reg\()0,  [x30, x30, lsl  #\size]
	\op	\reg\()31, [sp,  wzr, sxtw]
	\op	\reg\()0,  [x30, w30, sxtw #\size]
	\op	\reg\()31, [sp,  xzr, sxtx]
	\op	\reg\()0,  [x30, x30, sxtx #\size]
.endm

.macro ldst_reg_offset op, wreg=0, xreg=0, simd=0, size32=0, size64=0
	.if \wreg
	\op	w0,  [x0,  x0]
	\op	w30, [x30, x30, sxtx]
	\op	wzr, [sp,  xzr, sxtx #\size32]
	\op	wzr, [sp,  xzr, lsl  #0]
	.endif
	.if \xreg
	\op	x0,  [x0,  x0]
	\op	x30, [x30, w30, uxtw]
	\op	xzr, [sp,  wzr, uxtw #\size64]
	\op	xzr, [sp,  xzr, lsl  #\size64]
	\op	xzr, [sp,  wzr, sxtw #\size64]
	\op	xzr, [sp,  xzr, sxtx #\size64]
	.endif
	.if \simd
	ldst_reg_offset_simd \op b 0
	ldst_reg_offset_simd \op h 1
	ldst_reg_offset_simd \op s 2
	ldst_reg_offset_simd \op d 3
	ldst_reg_offset_simd \op q 4
	.endif
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	ldst_reg_offset strb,  1, 0, 0, 0, 0
	ldst_reg_offset ldrb,  1, 0, 0, 0, 0
	ldst_reg_offset ldrsb, 1, 1, 0, 0, 0
	ldst_reg_offset str,   1, 1, 1, 2, 3
	ldst_reg_offset ldr,   1, 1, 1, 2, 3
	ldst_reg_offset strh,  1, 0, 0, 1, 1
	ldst_reg_offset ldrh,  1, 0, 0, 1, 1
	ldst_reg_offset ldrsh, 1, 1, 0, 1, 1
	ldst_reg_offset ldrsw, 0, 1, 0, 2, 2
.size libdis_test, [.-libdis_test]
