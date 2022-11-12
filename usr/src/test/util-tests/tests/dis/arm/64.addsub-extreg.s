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
 * C3.5.1 Add/subtract (extended register)
 */

/*
 * Test all combinations of 32-bit/64-bit, source registers (SP/ZR/R*) and
 * extends.  The 64-bit form additionally supports <Wm>.
 */
.macro addsub_extreg_ext op extend zreg=0
	/* 32-bit */
	\op	w0, w15, w30
	\op	w0, w15, w30, \extend
	\op	w0, w15, w30, \extend #0
	\op	w0, w15, w30, \extend #1
	\op	w0, w15, w30, \extend #2
	\op	w0, w15, w30, \extend #3
	\op	w0, w15, w30, \extend #4
	\op	w0, wsp, wzr
	\op	w0, wsp, wzr, \extend
	\op	w0, wsp, wzr, \extend #0
	\op	w0, wsp, wzr, \extend #1
	\op	w0, wsp, wzr, \extend #2
	\op	w0, wsp, wzr, \extend #3
	\op	w0, wsp, wzr, \extend #4
	/* 64-bit */
	\op	x0, x15, w30, \extend
	\op	x0, x15, w30, \extend #0
	\op	x0, x15, w30, \extend #1
	\op	x0, x15, w30, \extend #2
	\op	x0, x15, w30, \extend #3
	\op	x0, x15, w30, \extend #4
	\op	x0, sp, wzr
	\op	x0, sp, wzr, \extend
	\op	x0, sp, wzr, \extend #0
	\op	x0, sp, wzr, \extend #1
	\op	x0, sp, wzr, \extend #2
	\op	x0, sp, wzr, \extend #3
	\op	x0, sp, wzr, \extend #4
	.if \zreg
	\op	xzr, x15, w30, \extend #0
	\op	xzr, x15, w30, \extend #1
	\op	xzr, x15, w30, \extend #2
	\op	xzr, x15, w30, \extend #3
	\op	xzr, x15, w30, \extend #4
	.else
	\op	sp, x15, x30
	\op	sp, x15, x30, \extend
	.endif
.endm

.macro addsub_extreg op zreg=0
	addsub_extreg_ext \op uxtb \zreg
	addsub_extreg_ext \op uxth \zreg
	addsub_extreg_ext \op uxtw \zreg
	addsub_extreg_ext \op uxtx \zreg
	addsub_extreg_ext \op sxtb \zreg
	addsub_extreg_ext \op sxth \zreg
	addsub_extreg_ext \op sxtw \zreg
	addsub_extreg_ext \op sxtx \zreg
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * C5.6.3 ADD (extended register)
	 */
	addsub_extreg add
	/*
	 * C5.6.6 ADDS (extended register)
	 * C5.6.41 CMN (extended register) (alias)
	 */
	addsub_extreg adds 1
	/*
	 * C5.6.194 SUB (extended register)
	 */
	addsub_extreg sub
	/*
	 * C5.6.197 SUBS (extended register)
	 * C5.6.44 CMP (extended register) (alias)
	 */
	addsub_extreg subs 1
.size libdis_test, [.-libdis_test]
