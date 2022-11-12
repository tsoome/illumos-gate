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
 * C3.4.3 Extract
 */
.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * C5.6.67 EXTR
	 * C5.6.152 ROR (immediate) (alias)
	 */
	extr	w0, w15, wzr, #0
	extr	w0, w15, wzr, #31
	extr	x0, x15, xzr, #0
	extr	x0, x15, xzr, #63
	/* Test for ROR (Rn == Rm) */
	extr	w0, wzr, wzr, #0
	extr	w0, wzr, wzr, #31
	extr	x0, xzr, xzr, #0
	extr	x0, xzr, xzr, #31
.size libdis_test, [.-libdis_test]
