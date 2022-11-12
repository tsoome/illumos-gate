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
 * C3.3.12 Load/store register (unscaled immediate)
 *
 * STTRB  <Wt>, [<Xn|SP>{, #<simm>}]
 * LDTRB  <Wt>, [<Xn|SP>{, #<simm>}]
 * LDTRSB <Rt>, [<Xn|SP>{, #<simm>}]
 * STTRH  <Wt>, [<Xn|SP>{, #<simm>}]
 * LDTRH  <Wt>, [<Xn|SP>{, #<simm>}]
 * LDTRSH <Rt>, [<Xn|SP>{, #<simm>}]
 * STTR   <Rt>, [<Xn|SP>{, #<simm>}]
 * LDTR   <Rt>, [<Xn|SP>{, #<simm>}]
 * LDTRSW <Xt>, [<Xn|SP>{, #<simm>}]
 */
.macro ldst_reg_unpriv op, wreg=0, xreg=0 simd=0
	.if \wreg
	\op	w0,  [x0]
	\op	wzr, [sp,  #-1]
	\op	w30, [x30, #-256]
	\op	wzr, [sp,  #255]
	.endif
	.if \xreg
	\op	x0,  [x0]
	\op	xzr, [sp,  #-1]
	\op	x30, [x30, #-256]
	\op	xzr, [sp,  #255]
	.endif
	.if \simd
	\op	b0,  [x0]
	\op	h31, [sp,  #0]
	\op	s0,  [x0,  #-1]
	\op	d31, [sp,  #-256]
	\op	q0,  [x0,  #255]
	.endif
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	ldst_reg_unpriv sturb  1
	ldst_reg_unpriv ldurb  1
	ldst_reg_unpriv ldursb 1 1
	ldst_reg_unpriv stur   1 1 1
	ldst_reg_unpriv ldur   1 1 1
	ldst_reg_unpriv sturh  1
	ldst_reg_unpriv ldurh  1
	ldst_reg_unpriv ldursh 1 1
	ldst_reg_unpriv stur   1
	ldst_reg_unpriv ldur   1
	ldst_reg_unpriv ldursw 0 1
.size libdis_test, [.-libdis_test]
