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
 * C3.6.5 AdvSIMD copy
 * C3.6.7 AdvSIMD scalar copy
 */
.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/* DUP <Vd>.<T>, <Vn>.<Ts>[<index>]*/
	dup	v0.8b, v1.b[0]
	dup	v0.16b, v1.b[15]
	dup	v0.4h, v1.h[0]
	dup	v0.8h, v1.h[7]
	dup	v0.2s, v1.s[0]
	dup	v0.4s, v1.s[3]
	dup	v0.2d, v1.d[0]
	dup	v0.2d, v1.d[1]
	/* DUP <Vd>.<T>, <R><n> */
	dup	v0.8b, w0
	dup	v31.16b, wzr
	dup	v0.4h, w0
	dup	v31.8h, wzr
	dup	v0.2s, w0
	dup	v31.4s, wzr
	dup	v0.2d, x0
	dup	v31.2d, xzr
	/* SMOV <Rd>, <Vn>.<Ts>[<index>] */
	/* UMOV <Rd>, <Vn>.<Ts>[<index>] */
	smov	w0, v0.b[0]
	smov	wzr, v31.h[7]
	smov	x0, v0.b[15]
	smov	xzr, v31.h[7]
	smov	xzr, v31.s[3]
	umov	w0, v0.b[0]
	umov	wzr, v31.h[7]
	umov	x0, v0.d[0]
	umov	xzr, v31.d[1]
	/* INS <Vd>.<Ts>[<index>], <R><n> */
	ins	v0.b[15], w0
	ins	v31.h[7], wzr
	ins	v31.s[3], w30
	ins	v31.d[1], xzr
	/* INS <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>] */
	ins	v0.b[15], v31.b[0]
	ins	v0.h[7], v31.h[0]
	ins	v0.s[3], v31.s[0]
	ins	v0.d[1], v31.d[0]
	/* DUP <V><d>, <Vn>.<T>[<index>] */
	dup	b0, v0.8b[0]
	dup	b31, v31.16b[15]
	dup	h0, v0.4h[0]
	dup	h31, v31.8h[7]
	dup	s0, v0.2s[0]
	dup	s31, v31.4s[3]
	dup	d0, v0.1d[0]
	dup	d31, v31.2d[1]
.size libdis_test, [.-libdis_test]
