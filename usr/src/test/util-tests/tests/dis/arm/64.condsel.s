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
 * C3.5.6 Conditional select
 */
.macro condsel op
	/* 32-bit */
	\op	 w0, w15, w30, eq
	\op	wzr, w15, w30, ne
	\op	 w0, wzr, w30, cs
	\op	 w0, w15, wzr, cc
	\op	wzr, wzr, w30, mi
	\op	wzr, w15, wzr, pl
	\op	 w0, wzr, wzr, vs
	\op	wzr, wzr, wzr, vc
	\op	 w0, w15, w30, hi
	\op	 w0,  w0, w30, ls
	\op	 w0, w15,  w0, ge
	\op	 w0,  w0, w30, lt
	\op	 w0,  w0,  w0, gt
	\op	 w0, w15,  w0, le
	\op	 w0,  w0,  w0, al
	\op	wzr, wzr, wzr, nv
	/* 64-bit */
	\op	 x0, x15, x30, eq
	\op	xzr, x15, x30, ne
	\op	 x0, xzr, x30, cs
	\op	 x0, x15, xzr, cc
	\op	xzr, xzr, x30, mi
	\op	xzr, x15, xzr, pl
	\op	 x0, xzr, xzr, vs
	\op	xzr, xzr, xzr, vc
	\op	 x0, x15, x30, hi
	\op	 x0,  x0, x30, ls
	\op	 x0, x15,  x0, ge
	\op	 x0,  x0, x30, lt
	\op	 x0,  x0,  x0, gt
	\op	 x0, x15,  x0, le
	\op	 x0,  x0,  x0, al
	\op	xzr, xzr, xzr, nv
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * C5.6.50 CSEL
	 */
	condsel csel
	/*
	 * C5.6.53 CSINC
	 * C5.6.36 CINC (alias)
	 * C5.6.51 CSET (alias)
	 */
	condsel csinc
	/*
	 * C5.6.54 CSINV
	 * C5.6.37 CINV (alias)
	 * C5.6.52 CSETM (alias)
	 */
	condsel csinv
	/*
	 * C5.6.55 CSNEG
	 * C5.6.47 CNEG
	 */
	condsel csneg
.size libdis_test, [.-libdis_test]
