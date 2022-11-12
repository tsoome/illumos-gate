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
 * C3.4.4 Logical (immediate)
 */
.macro logical_imm op zreg=0
	\op	w0,  w30, #0x00000001
	\op	w0,  w30, #0x7fffffff
	\op	x0,  x30, #0x00000001
	\op	x0,  x30, #0xffffffff
	.if \zreg
	\op	wzr, wzr, #0x00000001
	\op	wzr, wzr, #0x7fffffff
	\op	xzr, xzr, #0x00000001
	\op	xzr, xzr, #0xffffffff
	.else
	\op	wsp, wzr, #0x00000001
	\op	wsp, wzr, #0x7fffffff
	\op	sp,  xzr, #0x00000001
	\op	sp,  xzr, #0xffffffff
	.endif
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * C5.6.11 AND (immediate)
	 */
	logical_imm and
	/*
	 * C5.6.141 ORR (immediate)
	 * C5.6.124 MOV (bitmask immediate) (alias)
	 */
	logical_imm orr
	/*
	 * C5.6.64 EOR (immediate)
	 */
	logical_imm eor
	/*
	 * C5.6.13 ANDS (immediate)
	 * C5.6.209 TST (immediate) (alias)
	 */
	logical_imm ands 1
.size libdis_test, [.-libdis_test]
