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
 * C3.3.9 Load/store register (immediate pre-indexed)
 *
 * C5.6.180 STRB  <Wt>, [<Xn|SP>, #<simm>]!
 * C5.6.86  LDRB  <Wt>, [<Xn|SP>, #<simm>]!
 * C5.6.90  LDRSB <Rt>, [<Xn|SP>, #<simm>]!
 * C6.3.285 STR   <Vt>, [<Xn|SP>, #<simm>]!
 * C6.3.166 LDR   <Vt>, [<Xn|SP>, #<simm>]!
 * C5.6.182 STRH  <Wt>, [<Xn|SP>, #<simm>]!
 * C5.6.88  LDRH  <Wt>, [<Xn|SP>, #<simm>]!
 * C5.6.92  LDRSH <Rt>, [<Xn|SP>, #<simm>]!
 * C5.6.178 STR   <Rt>, [<Xn|SP>, #<simm>]!
 * C5.6.83  LDR   <Rt>, [<Xn|SP>, #<simm>]!
 * C5.6.94  LDRSW <Xt>, [<Xn|SP>, #<simm>]!
 *
 * simm is signed 9bit, so test min/max.
 */
.macro ldst_reg_imm_pre op, wreg=0, xreg=0, simd=0
	.if \wreg
	\op	w0,  [x0,  #0]!
	\op	w30, [x30, #255]!
	\op	wzr, [sp,  #-256]!
	.endif
	.if \xreg
	\op	x0,  [x0,  #0]!
	\op	x30, [x30, #255]!
	\op	xzr, [sp,  #-256]!
	.endif
	.if \simd
	\op	b0,  [x0, #0]!
	\op	h31, [sp, #1]!
	\op	s0,  [x0, #-1]!
	\op	d31, [sp, #255]!
	\op	q0,  [x0, #-256]!
	.endif
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	ldst_reg_imm_pre strb  1
	ldst_reg_imm_pre ldrb  1
	ldst_reg_imm_pre ldrsb 1 1
	ldst_reg_imm_pre str   1 1 1
	ldst_reg_imm_pre ldr   1 1 1
	ldst_reg_imm_pre strh  1
	ldst_reg_imm_pre ldrh  1
	ldst_reg_imm_pre ldrsh 1 1
	ldst_reg_imm_pre ldrsw 0 1
.size libdis_test, [.-libdis_test]
