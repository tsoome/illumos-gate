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
 * C3.4.1 Add/subtract (immediate)
 */
.macro addsub_imm op zreg=0
	/* 32-bit */
	\op	w0, w30, #0
	\op	w0, w30, #4095
	\op	w0, w30, #0, lsl #0
	\op	w0, w30, #4095, lsl #0
	\op	w0, w30, #0, lsl #12
	\op	w0, w30, #4095, lsl #12
	/* 64-bit */
	\op	x0, x30, #0
	\op	x0, x30, #4095
	\op	x0, x30, #0, lsl #0
	\op	x0, x30, #4095, lsl #0
	\op	x0, x30, #0, lsl #12
	\op	x0, x30, #4095, lsl #12
	/* SP/ZR (aliases) */
	\op	w0, wsp, #0
	\op	w30, wsp, #4095, lsl #12
	\op	x0, sp, #0
	\op	x30, sp, #4095, lsl #12
	.if \zreg
	\op	wzr, w0, #0
	\op	wzr, w30, #4095, lsl #12
	\op	wzr, wsp, #0
	\op	wzr, wsp, #4095, lsl #12
	\op	xzr, x0, #0
	\op	xzr, x30, #4095, lsl #12
	\op	xzr, sp, #0
	\op	xzr, sp, #4095, lsl #12
	.else
	\op	wsp, w0, #0
	\op	wsp, w30, #4095, lsl #12
	\op	wsp, wsp, #0
	\op	wsp, wsp, #4095, lsl #12
	\op	sp, x0, #0
	\op	sp, x30, #4095, lsl #12
	\op	sp, sp, #0
	\op	sp, sp, #4095, lsl #12
	.endif
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * C5.6.4 ADD (immediate)
	 * C5.6.121 MOV (to/from SP) (alias)
	 */
	addsub_imm add
	/*
	 * C5.6.7 ADDS (immediate)
	 * C5.6.42 CMN (immediate) (alias)
	 */
	addsub_imm adds 1
	/*
	 * C5.6.195 SUB (immediate)
	 */
	addsub_imm sub
	/*
	 * C5.6.198 SUBS (immediate)
	 * C5.6.45 CMP (immediate) (alias)
	 */
	addsub_imm subs 1
.size libdis_test, [.-libdis_test]
