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
 * C3.5.5 Conditional compare (register)
 */
.macro condcomp_reg op
	/* 32-bit */
	\op	w0,  w0,  #0,  eq
	\op	w0,  wzr, #1,  ne
	\op	wzr, w0,  #2,  cs
	\op	wzr, wzr, #3,  cc
	\op	w0,  w0,  #4,  mi
	\op	w0,  wzr, #5,  pl
	\op	wzr, w0,  #6,  vs
	\op	wzr, wzr, #7,  vc
	\op	w0,  w0,  #8,  hi
	\op	w0,  wzr, #9,  ls
	\op	wzr, w0,  #10, ge
	\op	wzr, wzr, #11, lt
	\op	w0,  w0,  #12, gt
	\op	w0,  wzr, #13, le
	\op	wzr, w0,  #14, al
	\op	wzr, wzr, #15, nv
	/* 64-bit */
	\op	x0,  x0,  #0,  eq
	\op	x0,  xzr, #1,  ne
	\op	xzr, x0,  #2,  cs
	\op	xzr, xzr, #3,  cc
	\op	x0,  x0,  #4,  mi
	\op	x0,  xzr, #5,  pl
	\op	xzr, x0,  #6,  vs
	\op	xzr, xzr, #7,  vc
	\op	x0,  x0,  #8,  hi
	\op	x0,  xzr, #9,  ls
	\op	xzr, x0,  #10, ge
	\op	xzr, xzr, #11, lt
	\op	x0,  x0,  #12, gt
	\op	x0,  xzr, #13, le
	\op	xzr, x0,  #14, al
	\op	xzr, xzr, #15, nv
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * C5.6.33 CCMN (register)
	 * C5.6.35 CCMP (register)
	 */
	condcomp_reg ccmn
	condcomp_reg ccmp
.size libdis_test, [.-libdis_test]
