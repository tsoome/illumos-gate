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
 * C3.5.3 Add/subtract (with carry)
 */
.macro addsub_carry op
	/* 32-bit */
	\op	w0,  w15, w30
	\op	wzr, w15, w30
	\op	w0,  wzr, w30
	\op	w0,  w15, wzr
	/* 64-bit */
	\op	x0,  x15, x30
	\op	xzr, x15, x30
	\op	x0,  xzr, x30
	\op	x0,  x15, xzr
.endm

.text
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/*
	 * C5.6.1 ADC
	 */
	addsub_carry adc
	/*
	 * C5.6.2 ADCS
	 */
	addsub_carry adcs
	/*
	 * C5.6.155 SBC
	 * C5.6.137 NGC (alias)
	 */
	addsub_carry sbc
	/*
	 * C5.6.156 SBCS
	 * C5.6.138 NGCS (alias)
	 */
	addsub_carry sbcs
.size libdis_test, [.-libdis_test]
