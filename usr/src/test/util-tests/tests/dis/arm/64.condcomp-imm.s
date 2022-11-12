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
 * C3.5.4 Conditional compare (immediate)
 */
.macro condcomp_imm op
	/* 32-bit */
	\op	w0,  #0,  #0,  eq
	\op	w0,  #31, #1,  ne
	\op	wzr, #0,  #2,  cs
	\op	wzr, #31, #3,  cc
	\op	w0,  #0,  #4,  mi
	\op	w0,  #31, #5,  pl
	\op	wzr, #0,  #6,  vs
	\op	wzr, #31, #7,  vc
	\op	w0,  #0,  #8,  hi
	\op	w0,  #31, #9,  ls
	\op	wzr, #0,  #10, ge
	\op	wzr, #31, #11, lt
	\op	w0,  #0,  #12, gt
	\op	w0,  #31, #13, le
	\op	wzr, #0,  #14, al
	\op	wzr, #31, #15, nv
	/* 64-bit */
	\op	x0,  #0,  #0,  eq
	\op	x0,  #31, #1,  ne
	\op	xzr, #0,  #2,  cs
	\op	xzr, #31, #3,  cc
	\op	x0,  #0,  #4,  mi
	\op	x0,  #31, #5,  pl
	\op	xzr, #0,  #6,  vs
	\op	xzr, #31, #7,  vc
	\op	x0,  #0,  #8,  hi
	\op	x0,  #31, #9,  ls
	\op	xzr, #0,  #10, ge
	\op	xzr, #31, #11, lt
	\op	x0,  #0,  #12, gt
	\op	x0,  #31, #13, le
	\op	xzr, #0,  #14, al
	\op	xzr, #31, #15, nv
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * C5.6.32 CCMN (immediate)
	 * C5.6.34 CCMP (immediate)
	 */
	condcomp_imm ccmn
	condcomp_imm ccmp
.size libdis_test, [.-libdis_test]
