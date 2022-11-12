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
 * C3.5.2 Add/subtract (shifted register)
 */
.macro addsub_shiftreg op zreg=0
	/* 32-bit */
	\op	w0,  w15, w30
	\op	wzr, w15, w30, lsl #0
	\op	w0,  wzr, w30, lsl #31
	\op	w0,  w15, wzr, lsr #0
	\op	wzr, wzr, w30, lsr #31
	\op	w0,  wzr, wzr, asr #0
	\op	wzr, wzr, wzr, asr #31
	/* 64-bit */
	\op	x0,  x15, x30
	\op	xzr, x15, x30, lsl #0
	\op	x0,  xzr, x30, lsl #63
	\op	x0,  x15, xzr, lsr #0
	\op	xzr, xzr, x30, lsr #63
	\op	x0,  xzr, xzr, asr #0
	\op	xzr, xzr, xzr, asr #63
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * C5.6.5 ADD (shifted register)
	 */
	addsub_shiftreg add
	/*
	 * C5.6.8 ADDS (shifted register)
	 * C5.6.43 CMN (shifted register) (alias)
	 */
	addsub_shiftreg adds
	/*
	 * C5.6.196 SUB (shifted register)
	 * C5.6.135 NEG (alias)
	 */
	addsub_shiftreg sub
	/*
	 * C5.6.199 SUBS (shifted register)
	 * C5.6.46 CMP (shifted register) (alias)
	 * C5.6.136 NEGS (alias)
	 */
	addsub_shiftreg subs
.size libdis_test, [.-libdis_test]
