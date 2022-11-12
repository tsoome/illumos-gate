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
 * C3.3.5 Load register (literal)
 *
 * C5.6.144 PRFM (literal) is handled by tst.ldst-prfm.s
 */
.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
1:
	ldr	w0,  2f
	ldr	xzr, 1b
2:
	ldr	s0,  2b
	ldr	d30, 3f
	ldr	q31, 1b
3:
	ldrsw	x30, 2b
.size libdis_test, [.-libdis_test]
