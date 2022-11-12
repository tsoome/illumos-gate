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
 * C3.5.10 Logical (shifted register)
 */
.macro logical_shift op zreg=0
	\op	w0,  w15, w30
	\op	wzr, w15, w30, lsl #0
	\op	w0,  wzr, w30, lsr #31
	\op	w0,  w15, wzr, asr #0
	\op	wzr, wzr, wzr, ror #31
	\op	x0,  x15, x30
	\op	xzr, x15, x30, lsl #0
	\op	x0,  xzr, x30, lsr #63
	\op	x0,  x15, xzr, asr #0
	\op	xzr, xzr, xzr, ror #63
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * C5.6.11 AND (shifted register)
	 */
	logical_shift and
	/*
	 * C5.6.24 BIC (shifted register)
	 */
	logical_shift bic
	/*
	 * C5.6.142 ORR (shifted register)
	 * C5.6.125 MOV (register)
	 */
	logical_shift orr
	/*
	 * C5.6.140 ORN (shifted register)
	 * C5.6.134 MVN
	 */
	logical_shift orn
	/*
	 * C5.6.65 EOR (shifted register)
	 */
	logical_shift eor
	/*
	 * C5.6.63 EON (shifted register)
	 */
	logical_shift eon
	/*
	 * C5.6.14 ANDS (shifted register)
	 * C5.6.210 TST (shifted register)
	 */
	logical_shift ands
	/*
	 * C5.6.25 BICS (shifted register)
	 */
	logical_shift bics
.size libdis_test, [.-libdis_test]
