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
 * C3.3.11 Load/store register (unprivileged)
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
.macro ldst_reg_unpriv op, wreg=0, xreg=0
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
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	ldst_reg_unpriv sttrb  1
	ldst_reg_unpriv ldtrb  1
	ldst_reg_unpriv ldtrsb 1 1
	ldst_reg_unpriv sttrh  1
	ldst_reg_unpriv ldtrh  1
	ldst_reg_unpriv ldtrsh 1 1
	ldst_reg_unpriv sttr   1
	ldst_reg_unpriv ldtr   1
	ldst_reg_unpriv ldtrsw 0 1
.size libdis_test, [.-libdis_test]
