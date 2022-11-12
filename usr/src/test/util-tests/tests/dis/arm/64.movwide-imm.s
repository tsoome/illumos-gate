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
 * C3.4.5 Move wide (immediate)
 */
.macro movw_imm op
	\op	w0, #0x0000
	\op	w0, #0x0000, lsl #0
	\op	w0, #0x0000, lsl #16
	\op	x0, #0x0000
	\op	x0, #0x0000, lsl #0
	\op	x0, #0x0000, lsl #16
	\op	x0, #0x0000, lsl #32
	\op	x0, #0x0000, lsl #48
	\op	w0, #0xffff
	\op	w0, #0xffff, lsl #0
	\op	w0, #0xffff, lsl #16
	\op	x0, #0xffff
	\op	x0, #0xffff, lsl #0
	\op	x0, #0xffff, lsl #16
	\op	x0, #0xffff, lsl #32
	\op	x0, #0xffff, lsl #48
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * C5.6.127 MOVN
	 * C5.6.122 MOV (inverted wide immediate) (alias)
	 */
	movw_imm movn
	movw_imm movz
	movw_imm movk
.size libdis_test, [.-libdis_test]
