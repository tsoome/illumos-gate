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
 * C3.3.6 Load/store exclusive
 *
 * Test the various combinations of register arguments:
 *
 *   OP <32> <32>            [..
 *   OP      <32>            [..
 *   OP <32> <32|64>         [..
 *   OP <32> <32|64> <32|64> [..
 *   OP      <32|64>         [..
 *   OP      <32|64> <32|64> [..
 *
 * #0 is optional and default.
 */

.macro ldstexcl1 op test64=0
	\op	w0,  [x0]
	\op	w30, [x0, #0]
	\op	wzr, [sp]
	\op	wzr, [sp, #0]
	.if \test64
	\op	x0,  [x0]
	\op	x30, [x0, #0]
	\op	xzr, [sp]
	\op	xzr, [sp, #0]
	.endif
.endm

.macro ldstexcl2 op test64_1=0 test64_2=0
	\op	w0,  w0,  [x0]
	\op	w30, w30, [x0, #0]
	\op	wzr, wzr, [sp]
	\op	wzr, wzr, [sp, #0]
	.if \test64_1
	\op	w0,  x0,  [x0]
	\op	w30, x30, [x0, #0]
	\op	wzr, xzr, [sp]
	\op	wzr, xzr, [sp, #0]
	.endif
	.if \test64_2
	\op	x0,  x0,  [x0]
	\op	x30, x30, [x0, #0]
	\op	xzr, xzr, [sp]
	\op	xzr, xzr, [sp, #0]
	.endif
.endm

.macro ldstexcl3 op
	\op	w0,  w15, w30, [x0]
	\op	w30, w15, w0,  [x0, #0]
	\op	wzr, wzr, wzr, [sp]
	\op	wzr, wzr, wzr, [sp, #0]
	\op	w0,  x15, x30, [x0]
	\op	w30, x15, x0,  [x0, #0]
	\op	wzr, xzr, xzr, [sp]
	\op	wzr, xzr, xzr, [sp, #0]
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	ldstexcl2 stxrb
	ldstexcl2 stlxrb
	ldstexcl1 ldxrb
	ldstexcl1 ldaxrb
	ldstexcl1 stlrb
	ldstexcl1 ldarb
	ldstexcl2 stxrh
	ldstexcl2 stlxrh
	ldstexcl1 ldxrh
	ldstexcl1 ldaxrh
	ldstexcl1 stlrh
	ldstexcl1 ldarh
	ldstexcl2 stxr 1
	ldstexcl2 stlxr 1
	ldstexcl3 stxp
	ldstexcl3 stlxp
	ldstexcl1 ldxr 1
	ldstexcl1 ldaxr 1
	ldstexcl2 ldxp 0 1
	ldstexcl2 ldaxp 0 1
	ldstexcl1 stlr 1
	ldstexcl1 ldar 1
.size libdis_test, [.-libdis_test]
